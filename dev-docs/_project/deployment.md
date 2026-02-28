# 部署配置

> 自動產生 | `./dev-docs/update.sh _project`

## Docker

```yaml
# docker-compose.yml
services:
  panguard:    # 主服務 (port 3000)
  ollama:      # 本地 AI (port 11434, 選配)
```

- Dockerfile: 多階段建置, Node.js 22, non-root user
- Health check: port 3000
- Volumes: panguard-data, ollama-models

## Railway

- 設定檔: `railway.toml`
- 建置: `pnpm install && pnpm build`
- 啟動: `node packages/panguard/dist/cli/index.js threat start --port 3000`

## Vercel

- 範圍: `packages/website` (官網)
- Framework: Next.js 14
- 環境變數: `LEAD_WEBHOOK_URL` (選配)

## CI/CD (GitHub Actions)

```
.github/workflows/ci.yml
├── Lint Job:   ESLint + Prettier check
├── Test Job:   TypeCheck + Tests + Coverage report
└── Build Job:  Full package build (depends on lint & test)
```

- 觸發: push main/dev, pull requests
- 快取: pnpm store
- Artifacts: coverage report (14 天保留)

## 系統服務

```bash
# Linux (systemd)
panguard guard install    # 安裝為系統服務
panguard guard uninstall  # 移除

# macOS (launchd)
panguard guard install
panguard guard uninstall
```

## 環境變數

### 主服務 (.env)
- `PANGUARD_PORT` - 服務埠號
- `PANGUARD_BASE_URL` - 基礎 URL
- `PANGUARD_AUTH_DB` - SQLite 路徑
- `SMTP_*` - 郵件設定
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` - OAuth
- `GOOGLE_SHEETS_*` - Waitlist 同步

### Threat Cloud (deploy/.env)
- `TC_DOMAIN` - HTTPS 域名
- `TC_API_KEYS` - API 金鑰
- `CORS_ALLOWED_ORIGINS` - CORS 白名單
- `SEED_FEEDS` - 威脅情報來源

### 網站 (.env.local)
- `LEAD_WEBHOOK_URL` - 表單提交 webhook
