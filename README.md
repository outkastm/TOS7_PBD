# TOS7_PBD
# TOS7 Proxy Backend Daemon

[![Maintainer](https://img.shields.io/badge/Maintainer-OutkastM-blue.svg)](https://tmnascommunity.eu)
[![Platform](https://img.shields.io/badge/Platform-TerraMaster_TOS7-orange.svg)](https://tmnascommunity.eu)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-green.svg)](LICENSE.md)

This project contains the Go source code for the backend proxy daemon (`main.go`) used by application packages (`<appID>`) built by **OutkastM** for TerraMaster OS (TOS7).

---

## 📌 Features & Purpose

The compiled binary acts as a secure local backend proxy and interface bridge between the TOS7 (`<appID>`) Web UI frontend and the underlying application daemon.

* **Authentication & CSRF Validation:** Validates active TOS7 user sessions via Redis (`PHPREDIS_SESSION`) and checks matching `X-Csrf-Token` headers.
* **Systemd Socket Activation:** Supports both standalone execution and systemd socket activation listening on local Unix sockets (`/var/api/<appID>.sock`).
* **Service Control API:** Enables standard control actions (`status`, `diagnostics`, `log`, `service`, `save`) exposed via proxy endpoints (`/v2/proxy/<appID>/`).
* **CLI Version Query:** Supports running with `-version` flag to quickly output the binary build version.

---

## 🛠 Compilation & Usage

### Build Binary
To compile the backend binary for TOS7 (Linux x86_64 / ARM64):

```bash
# For 64-bit x86 NAS units
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o backend main.go

# For ARM64 NAS units
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o backend main.go
```

### Display Version
```bash
./backend -version
```

### Systemd / Service Activation
When launched by systemd socket activation or as a standalone process, the daemon automatically infers its `appID` from its installation directory path (`/usr/local/<appID>/bin/backend`) and creates its socket at `/var/api/<appID>.sock`.

---

## 🔒 Security & Scope

* **Path Restrictions:** Log access and configuration file writing are strictly sanitized and restricted to `/usr/local/`, `/usr/www/`, `/var/log/`, and allowed configuration extensions (`.json`, `.ini`, `.conf`, `.cfg`, `.yaml`, `.yml`, `.env`).
* **Local Socket Security:** All direct socket calls from local Unix sockets bypassing remote HTTP headers are granted local administrative privileges.

---

## ⚠️ Disclaimer of Liability

This proxy backend binary is provided "AS IS" without warranty of any kind. The maintainer (**OutkastM**) assumes no responsibility or liability for any security misconfigurations, system instability, or data loss resulting from the execution or deployment of this software on TerraMaster TOS7 devices.
