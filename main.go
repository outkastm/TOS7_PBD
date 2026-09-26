package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const AppVersion = "1.0.0"

type SavePayload struct {
	Target  string `json:"target"`
	Content string `json:"content"`
}

type DiagnosticsResponse struct {
	Output  string            `json:"output"`
	PhpVars map[string]string `json:"phpVars"`
	EnvVars map[string]string `json:"envVars"`
	Ports   map[string]int    `json:"ports"`
	WebBase string            `json:"webBase"`
}

var (
	appID       string
	appLocalDir string
	wwwAppDir   string
	configDir   string
	socketPath  string
	envPath     string
)

func parsePhpConfig(appID string) map[string]string {
	phpVars := make(map[string]string)

	targetPath := fmt.Sprintf("/usr/local/%s/bin/config.inc.php", appID)

	content, err := os.ReadFile(targetPath)
	if err != nil {
		log.Printf("Warning: Failed to read PHP config at %s: %v", targetPath, err)
		return phpVars
	}

	re := regexp.MustCompile(`\$([A-Za-z0-9_]+)\s*=\s*['"]([^'"]+)['"]\s*;`)
	matches := re.FindAllStringSubmatch(string(content), -1)

	for _, match := range matches {
		if len(match) == 3 {
			key := strings.TrimSpace(match[1])
			val := strings.TrimSpace(match[2])
			phpVars[key] = val
		}
	}

	return phpVars
}

func parseEnvConfig(envFilePath string) (map[string]int, string, map[string]string) {
	ports := make(map[string]int)
	envVars := make(map[string]string)
	webBase := ""

	file, err := os.Open(envFilePath)
	if err != nil {
		log.Printf("[ERROR] Could not open env file at %s: %v", envFilePath, err)
		return ports, webBase, envVars
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		rawKey := strings.TrimSpace(parts[0])
		key := strings.ToUpper(rawKey)
		val := strings.Trim(strings.TrimSpace(parts[1]), `"' `)

		envVars[rawKey] = val

		if key == "WEB_BASE" {
			webBase = strings.TrimPrefix(val, "/")
			continue
		}

		port, err := strconv.Atoi(val)
		if err != nil || port <= 0 {
			continue
		}

		if strings.HasPrefix(key, "LISTEN_PORT_") {
			portName := strings.ToLower(strings.TrimPrefix(key, "LISTEN_PORT_"))
			ports[portName] = port
		} else if key == "PORT" || key == "HTTP_PORT" || key == "RPC_PORT" || key == "TRANSMISSION_RPC_PORT" {
			ports["http"] = port
		} else if key == "HTTPS_PORT" || key == "SSL_PORT" {
			ports["https"] = port
		}
	}

	return ports, webBase, envVars
}

func validateAuth(r *http.Request) bool {
	// Allow direct local Unix socket calls
	if r.RemoteAddr == "@" || strings.HasPrefix(r.RemoteAddr, "@") || r.RemoteAddr == "" {
		return true
	}

	cookieStr := r.Header.Get("Cookie")
	csrfToken := r.Header.Get("X-Csrf-Token")

	if csrfToken == "" {
		csrfToken = r.Header.Get("x-csrf-token")
	}

	if cookieStr == "" || csrfToken == "" {
		return false
	}

	tokenMatched := false
	var tmSessName string

	for _, part := range strings.Split(cookieStr, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(kv[0])
			v := strings.TrimSpace(kv[1])

			if k == "X-Csrf-Token" || k == "x-csrf-token" {
				if unencoded, err := url.QueryUnescape(v); err == nil && unencoded == csrfToken {
					tokenMatched = true
				} else if v == csrfToken {
					tokenMatched = true
				}
			}
			if k == "TMSESSNAME" {
				tmSessName = v
			}
		}
	}

	if !tokenMatched || tmSessName == "" {
		return false
	}

	if isSessionActiveInRedis(tmSessName) {
		return true
	}

	log.Printf("[AUTH DENIED] Session PHPREDIS_SESSION:%s deleted from Redis (User Logged Out)", tmSessName)
	return false
}

func isSessionActiveInRedis(sessionID string) bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:6379", 300*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()

	cmd := fmt.Sprintf("EXISTS PHPREDIS_SESSION:%s\r\n", sessionID)
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))

	_, err = conn.Write([]byte(cmd))
	if err != nil {
		return false
	}

	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		if strings.Contains(string(buf[:n]), ":1") {
			return true
		}
	}

	return false
}

func main() {
	showVersion := flag.Bool("version", false, "Display application version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	var listener net.Listener
	var err error

	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to resolve executable path: %v", err)
	}
	binDir := filepath.Dir(execPath)
	appLocalDir = filepath.Dir(binDir)
	appID = filepath.Base(appLocalDir)

	wwwAppDir = filepath.Join("/usr/www", appID)
	configDir = filepath.Join(appLocalDir, "config")
	socketPath = fmt.Sprintf("/var/api/%s.sock", appID)
	envPath = filepath.Join(appLocalDir, fmt.Sprintf("%s.env", appID))

	listenFdsStr := os.Getenv("LISTEN_FDS")
	if listenFdsStr != "" {
		listenFds, convErr := strconv.Atoi(listenFdsStr)
		if convErr != nil || listenFds < 1 {
			log.Fatalf("Invalid LISTEN_FDS value: %s", listenFdsStr)
		}

		file := os.NewFile(uintptr(3), "systemd-socket")
		if file == nil {
			log.Fatal("Failed to create file handle from descriptor 3")
		}

		listener, err = net.FileListener(file)
		file.Close()

		if err != nil {
			log.Fatalf("Failed to bind systemd socket listener: %v", err)
		}
		log.Printf("[%s v20] Running via systemd socket activation on %s", appID, socketPath)
	} else {
		_ = os.Remove(socketPath)

		if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
			log.Fatalf("Failed to create socket directory: %v", err)
		}

		listener, err = net.Listen("unix", socketPath)
		if err != nil {
			log.Fatalf("Failed to create Unix socket at %s: %v", socketPath, err)
		}

		if err := os.Chmod(socketPath, 0777); err != nil {
			log.Printf("Warning: Failed to set socket permissions: %v", err)
		}

		log.Printf("[%s v20] Running as standalone binary daemon listening on %s", appID, socketPath)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	basePath := fmt.Sprintf("/v2/proxy/%s/", appID)

	fileServer := http.FileServer(http.Dir(wwwAppDir))

	mux.HandleFunc(basePath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		if !validateAuth(r) {
			http.Error(w, "Unauthorized: TOS Session Expired or Logged Out", http.StatusUnauthorized)
			return
		}

		if r.URL.Query().Get("action") != "" {
			proxyHandler(w, r)
			return
		}

		relPath := strings.TrimPrefix(r.URL.Path, basePath)
		cleanPath := filepath.Clean(filepath.Join(wwwAppDir, relPath))

		info, err := os.Stat(cleanPath)
		if os.IsNotExist(err) || info.IsDir() {
			http.ServeFile(w, r, filepath.Join(wwwAppDir, "index.html"))
			return
		}

		http.StripPrefix(basePath, fileServer).ServeHTTP(w, r)
	})

	log.Fatal(http.Serve(listener, mux))
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	contentType := r.Header.Get("Content-Type")

	switch action {
	case "status":
		handleStatus(w)

	case "diagnostics":
		handleDiagnostics(w)

	case "log":
		handleLog(w, r.URL.Query().Get("path"))

	case "service":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		handleService(w, r.URL.Query().Get("cmd"))

	case "save":
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(contentType, "application/json") {
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}
		handleSave(w, r.Body)

	default:
		http.Error(w, "Invalid or missing 'action' parameter", http.StatusBadRequest)
	}
}

func handleStatus(w http.ResponseWriter) {
	cmd := exec.Command("systemctl", "is-active", appID+".service")
	output, _ := cmd.CombinedOutput()
	rawStatus := strings.TrimSpace(string(output))

	var statusStr string
	switch rawStatus {
	case "active":
		statusStr = "active"
	case "inactive", "failed", "deactivating":
		statusStr = "inactive"
	default:
		statusStr = "unknown"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": statusStr,
		"raw":    rawStatus,
	})
}

func handleDiagnostics(w http.ResponseWriter) {
	initScript := filepath.Join(appLocalDir, "init.d", appID)
	commands := []string{"status", "inst_version", "dep_check"}

	phpVars := parsePhpConfig(appID)
	ports, webBase, envVars := parseEnvConfig(envPath)

	var sb strings.Builder

	for _, cmd := range commands {
		execCmd := exec.Command(initScript, cmd)
		output, err := execCmd.CombinedOutput()
		outStr := strings.TrimSpace(string(output))

		if err != nil && outStr == "" {
			sb.WriteString(fmt.Sprintf("Error running %s: %v\n\n", cmd, err))
		} else {
			sb.WriteString(outStr + "\n\n")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(DiagnosticsResponse{
		Output:  sb.String(),
		PhpVars: phpVars,
		EnvVars: envVars,
		Ports:   ports,
		WebBase: webBase,
	})
}

func handleLog(w http.ResponseWriter, path string) {
	if path == "" {
		http.Error(w, "Missing 'path' parameter", http.StatusBadRequest)
		return
	}

	cleanPath := filepath.Clean(path)
	if !strings.HasPrefix(cleanPath, "/usr/local/") && !strings.HasPrefix(cleanPath, "/usr/www/") && !strings.HasPrefix(cleanPath, "/var/log/") {
		http.Error(w, "Forbidden: Restricted file path", http.StatusForbidden)
		return
	}

	content, err := os.ReadFile(cleanPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading file: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func handleService(w http.ResponseWriter, cmdType string) {
	if cmdType == "" {
		http.Error(w, `{"error": "Missing service parameters"}`, http.StatusBadRequest)
		return
	}

	// Runs /usr/local/<appid>/init.d/<appid> <cmdType>
	initScript := filepath.Join(appLocalDir, "init.d", appID)
	execCmd := exec.Command(initScript, cmdType)

	output, err := execCmd.CombinedOutput()
	outStr := strings.TrimSpace(string(output))
	if outStr == "" {
		outStr = fmt.Sprintf("Operation '%s' completed successfully.", cmdType)
	}

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "output": outStr})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"output": outStr})
}

func handleSave(w http.ResponseWriter, body io.Reader) {
	reqBody, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, `{"error": "Failed to read request body"}`, http.StatusBadRequest)
		return
	}

	var payload SavePayload
	if err := json.Unmarshal(reqBody, &payload); err != nil {
		http.Error(w, `{"error": "Invalid JSON payload"}`, http.StatusBadRequest)
		return
	}

	fileName := filepath.Base(payload.Target)
	ext := strings.ToLower(filepath.Ext(fileName))

	allowedExts := map[string]bool{
		".json": true,
		".ini":  true,
		".conf": true,
		".cfg":  true,
		".yaml": true,
		".yml":  true,
		".env":  true,
	}

	if !allowedExts[ext] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Forbidden: Restricted configuration file type"})
		return
	}

	var targetPath string
	if ext == ".env" {
		targetPath = envPath
	} else {
		targetPath = filepath.Join(configDir, fileName)
	}

	// Ensure target directory exists before writing
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to create configuration directory: %v", err)})
		return
	}

	err = os.WriteFile(targetPath, []byte(payload.Content), 0644)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to write config: %v", err)})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"output": fmt.Sprintf("Configuration saved successfully to %s.", fileName),
	})
}