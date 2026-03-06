# Deployment Guide

> Deployment documentation for the Panguard AI platform covering single-machine, Docker, distributed, and production setups.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
- [Quick Start (Single Machine)](#quick-start-single-machine)
- [Full Stack Deployment](#full-stack-deployment)
- [Docker Compose Setup](#docker-compose-setup)
- [Distributed Deployment](#distributed-deployment)
- [Environment Variables Reference](#environment-variables-reference)
- [Port Reference](#port-reference)
- [Systemd Service Installation](#systemd-service-installation)
- [Log Locations and Rotation](#log-locations-and-rotation)
- [Production Hardening Checklist](#production-hardening-checklist)

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Node.js | >= 20 (22 recommended) | Required for all deployments |
| pnpm | >= 9.0.0 | Package manager for monorepo |
| Docker | >= 24.0 | For containerized deployments |
| Docker Compose | >= 2.20 | For multi-container setups |
| Linux | Kernel 4.18+ | Required for eBPF, Falco, rootkit detection |
| Falco | >= 0.35 | Optional: kernel-level monitoring |
| Suricata | >= 7.0 | Optional: network IDS |
| Ollama | >= 0.1.0 | Optional: local AI analysis |

### OS Support

| Platform | Guard Agent | Manager | Response Actions |
|----------|-------------|---------|-----------------|
| Linux (x64/arm64) | Full support | Full support | iptables, process kill, account disable |
| macOS (x64/arm64) | Full support | Full support | pfctl, process kill, account disable |
| Windows (x64) | Full support | Full support | netsh, process kill, account disable |
| Docker | Full support | Full support | Host firewall via capabilities |

---

## Installation Methods

### Method 1: Clone and Build (Development)

```bash
git clone https://github.com/panguard-ai/panguard-ai.git
cd panguard-ai
pnpm install
pnpm build
```

### Method 2: npm Global Install

```bash
npm install -g @panguard-ai/panguard

# Verify installation
panguard --version
```

### Method 3: Docker

```bash
docker pull panguard/panguard-ai:latest

# Run with default settings
docker run -d \
  --name panguard \
  -p 3000:3000 \
  -v panguard-data:/data \
  panguard/panguard-ai:latest
```

### Method 4: One-Line Installer (curl)

```bash
curl -fsSL https://get.panguard.ai | bash
```

This downloads the latest release, installs it globally, and runs the initialization wizard.

---

## Quick Start (Single Machine)

### 1. Initialize Configuration

```bash
# Interactive setup wizard
panguard init

# Or with specific options
panguard init --language en --mode learning
```

The `init` command creates:
- `~/.panguard/config.json` -- global configuration
- `~/.panguard/llm.enc` -- encrypted AI provider credentials (if configured)
- `./data/` -- local data directory for baselines, logs, and rules

### 2. Run a Security Scan

```bash
# Quick scan
panguard scan

# Full scan with PDF report
panguard scan --full --report pdf

# Remote scan
panguard scan --remote --target 192.168.1.0/24
```

### 3. Start the Guard Agent

```bash
# Start in learning mode (recommended for first deployment)
panguard guard --mode learning

# Start in protection mode
panguard guard --mode protection

# Start with custom data directory
panguard guard --data-dir /opt/panguard/data
```

### 4. Start the API Server

```bash
# Start the full API server (auth + guard + web dashboard)
panguard serve --port 3000 --host 0.0.0.0 --db /data/auth.db
```

### 5. Start the Honeypot

```bash
panguard trap --ports 22,80,443,8080
```

### 6. Check Status

```bash
panguard status
```

---

## Full Stack Deployment

A full stack deployment runs the API server (`panguard serve`) and Guard agent (`panguard guard`) together. The API server integrates authentication, the web dashboard, and acts as a gateway to the Guard engine.

### Architecture

```
                              [Client Browser]
                                    |
                              [API Server :3000]
                              /       |       \
                    [Auth Server] [Web Dashboard] [Guard Engine]
                         |                            |
                    [SQLite DB]              [MonitorEngine]
                                            [DetectAgent]
                                            [AnalyzeAgent]
                                            [RespondAgent]
                                            [ReportAgent]
```

### Start Command

```bash
# Full stack with all options
panguard serve \
  --port 3000 \
  --host 0.0.0.0 \
  --db /data/auth.db \
  --guard-mode protection \
  --guard-data /var/panguard-guard
```

### Connecting to a Manager

For distributed deployments, the Guard agent connects to a centralized Manager:

```bash
# Start Manager (on management server)
panguard manager --port 8443 --auth-token "$(openssl rand -hex 32)"

# Start Guard with Manager connection (on each endpoint)
panguard guard \
  --mode learning \
  --manager-url "http://manager-host:8443" \
  --manager-token "your-secure-token" \
  --data-dir /var/panguard-guard
```

---

## Docker Compose Setup

### Basic Setup (API + Ollama)

```yaml
# docker-compose.yml
services:
  panguard:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: panguard
    restart: unless-stopped
    ports:
      - '3000:3000'
    volumes:
      - panguard-data:/data
      - ./config:/app/config:ro
    environment:
      - PANGUARD_DATA_DIR=/data
      - PANGUARD_PORT=3000
      - OLLAMA_ENDPOINT=http://ollama:11434
    depends_on:
      ollama:
        condition: service_healthy

  ollama:
    image: ollama/ollama:latest
    container_name: panguard-ollama
    restart: unless-stopped
    ports:
      - '11434:11434'
    volumes:
      - ollama-models:/root/.ollama
    healthcheck:
      test: ['CMD', 'curl', '-f', 'http://localhost:11434/api/tags']
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 30s

volumes:
  panguard-data:
  ollama-models:
```

```bash
# Build and start
docker compose up -d

# Pull an Ollama model (first time only)
docker exec panguard-ollama ollama pull llama3

# View logs
docker compose logs -f panguard
```

### Full Stack (Auth + Manager + Guard + Ollama)

```yaml
# docker-compose.full.yml
services:
  panguard-auth:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: panguard-auth
    restart: unless-stopped
    ports:
      - '3000:3000'
    volumes:
      - auth-data:/data
      - ./config:/app/config:ro
    environment:
      - PANGUARD_DATA_DIR=/data
      - PANGUARD_PORT=3000
      - JWT_SECRET=your-secret-key-here
      - GOOGLE_CLIENT_ID=your-google-client-id
      - GOOGLE_CLIENT_SECRET=your-google-client-secret
      - MANAGER_URL=http://panguard-manager:8443
      - MANAGER_AUTH_TOKEN=your-manager-token
      - OLLAMA_ENDPOINT=http://ollama:11434
    depends_on:
      panguard-manager:
        condition: service_started
      ollama:
        condition: service_healthy
    networks:
      - panguard-net
    healthcheck:
      test: ['CMD', 'node', '-e', "fetch('http://127.0.0.1:3000/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"]
      interval: 30s
      timeout: 5s
      retries: 3

  panguard-manager:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: panguard-manager
    command: ["node", "dist/cli/index.js", "manager", "--port", "8443"]
    restart: unless-stopped
    ports:
      - '8443:8443'
    environment:
      - MANAGER_PORT=8443
      - MANAGER_AUTH_TOKEN=your-manager-token
      - MANAGER_MAX_AGENTS=500
      - MANAGER_HEARTBEAT_TIMEOUT_MS=90000
      - MANAGER_CORRELATION_WINDOW_MS=300000
      - CORS_ALLOWED_ORIGINS=http://localhost:3000
    networks:
      - panguard-net

  ollama:
    image: ollama/ollama:latest
    container_name: panguard-ollama
    restart: unless-stopped
    ports:
      - '11434:11434'
    volumes:
      - ollama-models:/root/.ollama
    networks:
      - panguard-net
    healthcheck:
      test: ['CMD', 'curl', '-f', 'http://localhost:11434/api/tags']
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 30s

volumes:
  auth-data:
  ollama-models:

networks:
  panguard-net:
    driver: bridge
```

```bash
docker compose -f docker-compose.full.yml up -d
```

---

## Distributed Deployment

In a distributed deployment, multiple Guard agents on different machines report to a single Manager server.

```
[Machine A: Manager]                [Machine B: Guard Agent]
+-------------------+               +---------------------+
| Manager Server    |<-- heartbeat --| GuardEngine         |
| :8443             |<-- events   --| (learning/protection)|
|                   |-- policy   -->|                     |
+-------------------+               +---------------------+
        ^
        |                            [Machine C: Guard Agent]
        |                            +---------------------+
        +<-- heartbeat/events -------| GuardEngine         |
        +--- policy ---------------->|                     |
                                     +---------------------+
```

### Step 1: Deploy the Manager

```bash
pnpm panguard manager \
  --port 8443 \
  --auth-token "$(openssl rand -hex 32)" \
  --max-agents 500
```

### Step 2: Deploy Guard Agents

On each endpoint:

```bash
pnpm panguard guard \
  --mode learning \
  --manager-url "http://manager-host:8443" \
  --manager-token "your-secure-token" \
  --data-dir /var/panguard-guard
```

The Guard agent will:
1. Register with the Manager on startup
2. Send heartbeats every 30 seconds
3. Report detected threats in real-time
4. Poll for policy updates every 5 minutes

### Step 3: Monitor via Admin Dashboard

```bash
# Real-time event stream
curl -N -H "Authorization: Bearer your-secure-token" \
     http://manager-host:8443/api/events/stream

# Fleet overview
curl -H "Authorization: Bearer your-secure-token" \
     http://manager-host:8443/api/overview
```

---

## Environment Variables Reference

### Guard Agent

| Variable | Default | Description |
|----------|---------|-------------|
| `PANGUARD_DATA_DIR` | `./data` | Data directory for baselines, logs, rules |
| `PANGUARD_MODE` | `learning` | Guard mode: `learning` or `protection` |
| `PANGUARD_LLM_MODEL` | (auto-detect) | Override AI model name |
| `PANGUARD_SYSLOG_SERVER` | (none) | Syslog forwarding destination host |
| `PANGUARD_SYSLOG_PORT` | `514` | Syslog forwarding destination port |
| `OLLAMA_ENDPOINT` | `http://localhost:11434` | Ollama API endpoint |
| `ANTHROPIC_API_KEY` | (none) | Claude API key for cloud AI |
| `OPENAI_API_KEY` | (none) | OpenAI API key for cloud AI |
| `ABUSEIPDB_KEY` | (none) | AbuseIPDB API key for threat intel |

### Manager Server

| Variable | Default | Description |
|----------|---------|-------------|
| `MANAGER_PORT` | `8443` | Manager HTTP server port |
| `MANAGER_AUTH_TOKEN` | (none) | Bearer token for API authentication |
| `MANAGER_MAX_AGENTS` | `500` | Maximum registered agents |
| `MANAGER_HEARTBEAT_TIMEOUT_MS` | `90000` | Heartbeat timeout before marking agent stale |
| `MANAGER_HEARTBEAT_INTERVAL_MS` | `30000` | Interval for stale agent checks |
| `MANAGER_CORRELATION_WINDOW_MS` | `300000` | Cross-agent threat correlation window |
| `MANAGER_THREAT_RETENTION_MS` | `86400000` | Threat data retention period (default 24h) |
| `CORS_ALLOWED_ORIGINS` | (none) | Comma-separated allowed CORS origins |

### Auth Server

| Variable | Default | Description |
|----------|---------|-------------|
| `PANGUARD_PORT` | `3000` | API server port |
| `JWT_SECRET` | (none) | JWT signing secret (required in production) |
| `GOOGLE_CLIENT_ID` | (none) | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | (none) | Google OAuth client secret |
| `LEMONSQUEEZY_API_KEY` | (none) | LemonSqueezy billing API key |
| `LEMONSQUEEZY_WEBHOOK_SECRET` | (none) | LemonSqueezy webhook signing secret |

### Threat Cloud Server

| Variable | Default | Description |
|----------|---------|-------------|
| `TC_API_KEYS` | (none) | Comma-separated API keys |
| `TC_PORT` | (configurable) | Server port |
| `TC_DB_PATH` | (configurable) | SQLite database path |
| `ALLOW_ANONYMOUS_UPLOAD` | `false` | Allow anonymous threat data uploads |
| `CORS_ALLOWED_ORIGINS` | `https://panguard.ai,...` | CORS origins |
| `NODE_ENV` | `development` | Set to `production` for hardened mode |

### Docker / Production

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | `development` | Set to `production` for hardened mode |
| `PANGUARD_DATA_DIR` | `/data` | Data directory (Docker volume mount point) |

---

## Port Reference

| Port | Service | Protocol | Notes |
|------|---------|----------|-------|
| `3000` | API Server (Auth + Web) | HTTP | Main entry point, serves API and admin dashboard |
| `8443` | Manager Server | HTTP | Agent registration, heartbeats, threat reports, SSE |
| `11434` | Ollama | HTTP | Local AI inference |
| `2222` | Trap: SSH Honeypot | TCP | Default SSH trap port |
| `8080` | Trap: HTTP Honeypot | TCP | Default HTTP trap port |
| `2121` | Trap: FTP Honeypot | TCP | Default FTP trap port |
| `4450` | Trap: SMB Honeypot | TCP | Default SMB trap port |
| `3307` | Trap: MySQL Honeypot | TCP | Default MySQL trap port |
| `3390` | Trap: RDP Honeypot | TCP | Default RDP trap port |
| `2323` | Trap: Telnet Honeypot | TCP | Default Telnet trap port |

---

## Systemd Service Installation

### Guard Agent Service

Create `/etc/systemd/system/panguard-guard.service`:

```ini
[Unit]
Description=Panguard Guard Agent
Documentation=https://github.com/panguard-ai/panguard-ai
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=panguard
Group=panguard
WorkingDirectory=/opt/panguard
ExecStart=/usr/bin/node /opt/panguard/dist/cli/index.js guard --mode protection --data-dir /var/panguard-guard
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=panguard-guard

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/panguard-guard
PrivateTmp=true

# Required capabilities for response actions
AmbientCapabilities=CAP_NET_ADMIN CAP_KILL CAP_SYS_PTRACE

# Environment
Environment=NODE_ENV=production
Environment=PANGUARD_DATA_DIR=/var/panguard-guard
EnvironmentFile=-/etc/panguard/guard.env

[Install]
WantedBy=multi-user.target
```

### Manager Service

Create `/etc/systemd/system/panguard-manager.service`:

```ini
[Unit]
Description=Panguard Manager Server
Documentation=https://github.com/panguard-ai/panguard-ai
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=panguard
Group=panguard
WorkingDirectory=/opt/panguard
ExecStart=/usr/bin/node /opt/panguard/dist/cli/index.js manager --port 8443
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=panguard-manager

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/panguard-manager
PrivateTmp=true

# Environment
Environment=NODE_ENV=production
EnvironmentFile=-/etc/panguard/manager.env

[Install]
WantedBy=multi-user.target
```

### Installation Steps

```bash
# 1. Create system user
sudo useradd --system --home-dir /opt/panguard --shell /usr/sbin/nologin panguard

# 2. Create directories
sudo mkdir -p /opt/panguard /var/panguard-guard /var/panguard-manager /etc/panguard
sudo chown -R panguard:panguard /opt/panguard /var/panguard-guard /var/panguard-manager

# 3. Deploy application
sudo cp -r dist/ /opt/panguard/dist/
sudo cp -r node_modules/ /opt/panguard/node_modules/
sudo cp -r config/ /opt/panguard/config/

# 4. Create environment files
sudo tee /etc/panguard/guard.env << 'EOF'
PANGUARD_DATA_DIR=/var/panguard-guard
OLLAMA_ENDPOINT=http://localhost:11434
EOF

sudo tee /etc/panguard/manager.env << 'EOF'
MANAGER_PORT=8443
MANAGER_AUTH_TOKEN=your-secure-token-here
MANAGER_MAX_AGENTS=500
EOF

# 5. Set permissions on environment files (contain secrets)
sudo chmod 600 /etc/panguard/*.env
sudo chown panguard:panguard /etc/panguard/*.env

# 6. Enable and start services
sudo systemctl daemon-reload
sudo systemctl enable panguard-guard panguard-manager
sudo systemctl start panguard-guard panguard-manager

# 7. Check status
sudo systemctl status panguard-guard panguard-manager

# 8. View logs
sudo journalctl -u panguard-guard -f
sudo journalctl -u panguard-manager -f
```

---

## Log Locations and Rotation

### Log Locations

| Component | Path | Format |
|-----------|------|--------|
| Guard events | `{dataDir}/events.jsonl` | JSONL (one JSON record per line) |
| Guard actions | `{dataDir}/action-manifest.jsonl` | JSONL action history |
| Guard baseline | `{dataDir}/baseline.json` | JSON baseline state |
| Guard PID file | `{dataDir}/panguard-guard.pid` | Plain text PID |
| Application logs | stdout/stderr (or syslog) | Structured JSON (via `createLogger`) |
| Falco alerts | `/var/log/falco/alerts.json` | Falco JSON format |
| Suricata EVE | `/var/log/suricata/eve.json` | Suricata EVE JSON |
| YARA rules (custom) | `{dataDir}/yara-rules/custom/` | `.yar` files |
| Sigma rules (custom) | `{dataDir}/rules/` | `.yml` Sigma YAML files |

Default `dataDir` values:
- CLI: `./data` or `--data-dir` flag
- Docker: `/data` (mounted volume)
- Systemd: `/var/panguard-guard` or `/var/panguard-manager`

### Automatic Log Rotation

The `ReportAgent` handles log rotation automatically for `events.jsonl`:

| Setting | Default | Description |
|---------|---------|-------------|
| `maxFileSizeBytes` | 50 MB | Rotate when file exceeds this size |
| `maxRotatedFiles` | 10 | Maximum number of rotated files to keep |
| `retentionDays` | 90 | Delete files older than this |

Rotation naming scheme:
```
events.jsonl        (current)
events.jsonl.1      (most recent rotation)
events.jsonl.2      (next oldest)
...
events.jsonl.10     (oldest, deleted on next rotation)
```

### Syslog Forwarding

```bash
export PANGUARD_SYSLOG_SERVER=syslog.example.com
export PANGUARD_SYSLOG_PORT=514
```

The `SyslogAdapter` from `security-hardening` forwards structured events to the configured syslog server.

---

## Production Hardening Checklist

### Required

- [ ] Set `NODE_ENV=production` -- enables HSTS headers, disables wildcard CORS
- [ ] Configure `MANAGER_AUTH_TOKEN` -- generate with `openssl rand -hex 32`
- [ ] Configure `JWT_SECRET` for the auth server -- generate with `openssl rand -hex 32`
- [ ] Use TLS termination -- place nginx/caddy reverse proxy in front for HTTPS
- [ ] Restrict network access -- Manager port (8443) should only be accessible from Guard agent networks
- [ ] Run as non-root -- the Docker image creates a dedicated `panguard` user (UID 1001)
- [ ] Mount secrets as env files -- avoid passing secrets via Docker `environment` in compose files
- [ ] Set file permissions -- environment files containing secrets should be `chmod 600`

### Recommended

- [ ] Enable Falco -- for kernel-level visibility on Linux endpoints
- [ ] Install Suricata -- for network IDS coverage
- [ ] Configure Ollama -- for zero-cost local AI analysis
- [ ] Set up syslog forwarding -- for centralized log management
- [ ] Configure notification channels -- Telegram, Slack, Email, LINE, or Webhook
- [ ] Review firewall rules -- the RespondAgent modifies iptables/pfctl; ensure the Guard process has appropriate capabilities
- [ ] Enable TOTP 2FA for admin accounts
- [ ] Configure rate limiting appropriately for your traffic patterns

### Capabilities Required (Linux)

| Capability | Purpose |
|------------|---------|
| `CAP_NET_ADMIN` | Block IPs via iptables |
| `CAP_KILL` | Terminate malicious processes |
| `CAP_SYS_PTRACE` | Memory scanning for fileless malware |

### Docker Security

The production Docker image:
- Uses multi-stage build (build dependencies not in final image)
- Runs as non-root user (`panguard:1001`)
- Uses `tini` as PID 1 for proper signal handling and zombie reaping
- Includes minimal system packages (only `tini` and `curl`)

### Backup Strategy

- **Baseline data**: Back up `{dataDir}/baseline.json` regularly. Loss requires re-running learning mode.
- **Event logs**: `events.jsonl` files are rotated automatically. Archive rotated files to long-term storage.
- **Auth database**: `auth.db` (SQLite) should be backed up daily. Use `sqlite3 auth.db ".backup backup.db"`.
- **Threat Cloud database**: Back up the SQLite database using the built-in scheduler's backup functionality.
- **Configuration**: Store `~/.panguard/config.json` and environment files in version control or a secrets manager.

---

## Release Workflow

Tagged releases are built and published automatically via CI.

### Platforms

Each release produces pre-compiled binaries for 4 target platforms:

| Platform | Target |
|----------|--------|
| macOS Apple Silicon | `darwin-arm64` |
| Linux x86-64 | `linux-x64` |
| Linux ARM 64-bit | `linux-arm64` |
| Windows x86-64 | `win-x64` |

### npm Auto-Publish

On a successful tagged release, the following packages are published to npm automatically:

- `@panguard-ai/core` - Shared engine (rule engine, monitors, AI providers, i18n)
- `@panguard-ai/panguard` - Unified CLI entry point

### Triggering a Release

```bash
# Tag and push to trigger the release workflow
git tag v0.3.1
git push origin v0.3.1
```

The CI pipeline will:
1. Run the full test suite (`pnpm test`)
2. Build all packages (`pnpm build`)
3. Compile platform binaries for all 4 targets
4. Publish `@panguard-ai/core` and `@panguard-ai/panguard` to npm
5. Attach binaries to the GitHub release
