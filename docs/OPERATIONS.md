# Panguard AI 營運管理手冊 (Operations Manual)

> 最後更新: 2026-03-06 | 版本: v0.3.1

---

## 目錄

1. [系統架構總覽](#1-系統架構總覽)
2. [本地開發環境啟動](#2-本地開發環境啟動)
3. [前端 (Website) 管理](#3-前端-website-管理)
4. [後端 (API Server) 管理](#4-後端-api-server-管理)
5. [CLI 管理](#5-cli-管理)
6. [後台管理面板 (Admin Dashboard)](#6-後台管理面板-admin-dashboard)
7. [使用者體驗全流程](#7-使用者體驗全流程)
8. [環境變數完整參考](#8-環境變數完整參考)
9. [資料庫管理](#9-資料庫管理)
10. [Google OAuth 設定](#10-google-oauth-設定)
11. [Lemon Squeezy 付款設定](#11-lemon-squeezy-付款設定)
12. [通知系統](#12-通知系統-emailtelegramslack)
13. [CI/CD 管線](#13-cicd-管線)
14. [Docker 部署](#14-docker-部署)
15. [版本發佈流程](#15-版本發佈流程)
16. [安全性檢查清單](#16-安全性檢查清單)
17. [故障排除](#17-故障排除-troubleshooting)
18. [常用指令速查表](#18-常用指令速查表)
19. [已知問題與改進建議](#19-已知問題與改進建議)

---

## 1. 系統架構總覽

### Monorepo 結構

Panguard AI 是一個 **16-package pnpm monorepo**，使用 TypeScript 5.7 + Node.js 20+。

```
panguard-ai/
├── packages/
│   ├── core/                  # 核心共用模組 (AI, i18n, rules, scoring)
│   ├── panguard/              # CLI 統一入口 (22 commands)
│   ├── panguard-scan/         # 安全掃描 (10 scanners)
│   ├── panguard-guard/        # 即時防護引擎 (4-agent pipeline)
│   ├── panguard-chat/         # 通知系統 (Telegram/Slack/Email/LINE/Webhook)
│   ├── panguard-trap/         # 蜜罐 (8 honeypot protocols)
│   ├── panguard-report/       # 合規報告 (ISO 27001/SOC 2/TCSA)
│   ├── panguard-auth/         # 認證系統 (OAuth/TOTP/billing)
│   ├── panguard-manager/      # 分散式代理管理 (最多 500 agents)
│   ├── panguard-mcp/          # MCP Server (11 tools)
│   ├── panguard-skill-auditor/# Skill 安全審計
│   ├── panguard-web/          # Web dashboard 引擎
│   ├── threat-cloud/          # 威脅情報後端
│   ├── website/               # Next.js 14 官網 (39+ pages)
│   └── admin/                 # 靜態 Admin HTML
├── security-hardening/        # 安全強化模組
├── config/
│   ├── sigma-rules/           # 3,760 Sigma 規則
│   └── yara-rules/            # 5,961 YARA 規則
├── scripts/installer/         # 安裝腳本
├── docs/                      # 文件
├── .github/workflows/         # CI/CD (6 workflows)
├── Dockerfile                 # Docker 多階段建置
├── docker-compose.yml         # Docker Compose
└── .env.example               # 環境變數範本
```

### 4-Agent 偵測管線

```
Monitor Engine → DetectAgent → AnalyzeAgent → RespondAgent → ReportAgent
     ↓              ↓              ↓              ↓              ↓
SecurityEvent  DetectionResult  ThreatVerdict  ResponseResult  JSONL Log
```

1. **DetectAgent** — Sigma 規則比對、威脅情報查詢、事件去重、關聯分析
2. **AnalyzeAgent** — 證據收集、信心分數計算 (0-100)、AI 推理
3. **RespondAgent** — 動作執行 (block_ip, kill_process, isolate_file 等)、安全規則
4. **ReportAgent** — JSONL 日誌、基線更新、匿名化

### 3-Layer AI Funnel

| Layer | 技術 | 成本 | 延遲 | 涵蓋率 |
|-------|------|------|------|--------|
| Layer 1 | 規則 (3,760 Sigma + 5,961 YARA) | $0 | <1ms | 90% |
| Layer 2 | 本地 AI (Ollama llama3) | $0 | ~100ms | 7% |
| Layer 3 | 雲端 AI (Claude/OpenAI) | ~$0.01/event | ~1s | 3% |

### 事件關聯模式 (7 patterns)

| 模式 | MITRE ID | 閾值 | 時間窗口 |
|------|----------|------|----------|
| 暴力破解 | T1110 | 5 次認證失敗 | 60s |
| 端口掃描 | T1046 | 10 個不同端口 | 60s |
| 橫向移動 | T1021 | 3+ 內部 IP | 5min |
| 資料外洩 | T1041 | >10MB 外送 | single |
| 後門安裝 | T1059 | file+process+network | 5min |
| 提權 | T1548 | setuid/sudo patterns | 5min |
| 嚴重度升級 | -- | 3+ low→medium | 5min |

### 核心依賴圖

```
website (Next.js) ─────────────┐
                                │
                          ┌─────┴────┐
                          │          │
admin (HTML)        panguard-cli   core  ← 所有 packages 依賴 core
                          ↑          ↑
        ┌─────────────────┼──────────┼──────────────────────────┐
        │                 │          │                          │
     guard ──► scan  trap  chat  report  web  auth  manager  threat-cloud  mcp  skill-auditor
        │                 │          │
        │                 └────┬─────┘
        │                      │
     security-hardening ◄──────┘
```

---

## 2. 本地開發環境啟動

### 系統需求

| 項目 | 最低要求 |
|------|---------|
| OS | macOS 12+, Ubuntu 20.04+, Windows 10+ |
| Node.js | >= 20.0.0 |
| pnpm | >= 9.0.0 |
| 磁碟 | 200 MB |
| 記憶體 | 512 MB (Guard 建議 1 GB) |

### 首次設定

```bash
# 1. Clone 專案
git clone https://github.com/panguard-ai/panguard-ai.git
cd panguard-ai

# 2. 安裝依賴
pnpm install

# 3. 建置所有 packages
pnpm build

# 4. 建立 .env (從範本複製)
cp .env.example .env
# 編輯 .env，填入必要的設定值

# 5. 執行測試
pnpm test
```

### 啟動三個服務

#### 後端 API Server (port 3002)
```bash
cd /Users/user/Downloads/panguard-ai
node --env-file=.env packages/panguard/dist/cli/index.js serve --port 3002
```

啟動後的路由：
- `/api/auth/*` — Auth API
- `/api/admin/*` — Admin API
- `/api/billing/*` — Billing API
- `/api/usage/*` — Usage & Quota API
- `/api/manager/*` — Manager API
- `/health` — Health check
- `/docs/api` — Swagger UI
- `/openapi.json` — OpenAPI 3.0 Spec

#### 前端 Website (port 3001)
```bash
cd packages/website
npx next dev -p 3001
```

> **注意**: 需要 `.env.local` 設定 `NEXT_PUBLIC_API_URL=http://localhost:3002`

#### CLI 互動模式
```bash
panguard
# 或開發模式
node packages/panguard/dist/cli/index.js
```

### 開發模式 (watch)
```bash
# Terminal 1: 編譯 core (watch)
cd packages/core && pnpm dev

# Terminal 2: 編譯 CLI (watch)
cd packages/panguard && pnpm dev

# Terminal 3: 前端 dev server
cd packages/website && npx next dev -p 3001
```

---

## 3. 前端 (Website) 管理

### 技術棧

- **Framework**: Next.js 14 (App Router)
- **UI**: React 18 + Tailwind CSS + Framer Motion
- **Icons**: Lucide React
- **i18n**: next-intl (EN + ZH-TW)
- **Styling**: Custom design tokens (Sage Green #8B9A8E, Deep Charcoal #1A1614)

### 頁面清單與狀態

#### 公開頁面 (全部完成)

| 頁面 | 路徑 | 說明 |
|------|------|------|
| 首頁 | `/` | 15 個動態區塊 |
| 產品總覽 | `/product` | 產品介紹 |
| Scan | `/product/scan` | 掃描產品頁 |
| Guard | `/product/guard` | 防護產品頁 |
| Chat | `/product/chat` | 通知產品頁 |
| Trap | `/product/trap` | 蜜罐產品頁 |
| Report | `/product/report` | 報告產品頁 |
| 定價 | `/pricing` | 4 方案 + FAQ + 功能比較 |
| 技術原理 | `/how-it-works` | 運作方式 |
| 技術 | `/technology` | 技術細節 |
| Threat Cloud | `/threat-cloud` | 威脅情報 |
| 安全 | `/security` | 安全措施 |
| 合規 | `/compliance` | 合規框架 |
| 開源 | `/open-source` | 開源說明 |
| 整合 | `/integrations` | 第三方整合 |
| 資源 | `/resources` | 資源中心 |
| 狀態 | `/status` | 服務狀態 |
| 信任中心 | `/trust` | 信任頁面 |

#### 解決方案 (全部完成)

| 頁面 | 路徑 |
|------|------|
| 開發者 | `/solutions/developers` |
| 中小企業 | `/solutions/smb` |
| 企業 | `/solutions/enterprise` |

#### 內容頁面 (全部完成)

| 頁面 | 路徑 |
|------|------|
| 部落格 | `/blog` + `/blog/[slug]` |
| 更新日誌 | `/changelog` |
| 關於 | `/about` |
| 職缺 | `/careers` |
| 聯絡 | `/contact` |
| 新聞 | `/press` |
| 客戶案例 | `/customers` + `/customers/[slug]` |
| 合作夥伴 | `/partners` |
| Demo 申請 | `/demo` |
| Early Access | `/early-access` |

#### 文件 (全部完成)

| 頁面 | 路徑 |
|------|------|
| 文件首頁 | `/docs` |
| 快速開始 | `/docs/getting-started` |
| CLI 參考 | `/docs/cli` |
| API 文件 | `/docs/api` |
| 部署 | `/docs/deployment` |
| 進階設定 | `/docs/advanced-setup` |
| 效能測試 | `/docs/benchmark` |

#### 法律頁面 (全部完成)

`/legal/terms`, `/legal/privacy`, `/legal/cookies`, `/legal/acceptable-use`, `/legal/security`, `/legal/responsible-disclosure`, `/legal/dpa`, `/legal/sla`

#### 認證相關 (完成)

| 頁面 | 路徑 | 狀態 |
|------|------|------|
| 登入 | `/login` | 完成 (Email + Google + 2FA) |
| 註冊 | `/register` | 完成 |
| 重設密碼 | `/reset-password` | 完成 |
| 用戶儀表板 | `/dashboard` | 部分 (mock usage data) |

#### 管理後台 (部分完成)

| 頁面 | 路徑 | 狀態 |
|------|------|------|
| Dashboard | `/admin/dashboard` | UI 完成, **mock data** |
| Endpoints | `/admin/endpoints` | UI 完成, **mock data** |
| Threats | `/admin/threats` | UI 完成, **mock data** |
| Policies | `/admin/policies` | **Coming Soon** |
| Settings | `/admin/settings` | **Coming Soon** |

#### 帳號管理 (未實作)

| 頁面 | 路徑 | 狀態 |
|------|------|------|
| 帳號設定 | `/account/settings` | **未實作** |
| 帳單管理 | `/account/billing` | **未實作** |

### 前端環境變數

```bash
# packages/website/.env.local
NEXT_PUBLIC_API_URL=http://localhost:3002     # 後端 API URL
NEXT_PUBLIC_CHECKOUT_ENABLED=true             # 啟用結帳流程
# NEXT_PUBLIC_PLAUSIBLE_DOMAIN=panguard.ai    # 分析 (選用)
```

### 部署

```bash
# Vercel (生產)
cd packages/website
vercel deploy --prod

# 本地預覽生產版
npx next build && npx next start -p 3001
```

### i18n 翻譯檔案

- `packages/website/messages/en.json` (~216KB)
- `packages/website/messages/zh.json` (~207KB)
- URL 結構: `/{locale}/{page}` (例: `/zh/pricing`)

### 設計系統

| Token | 值 | 用途 |
|-------|------|------|
| brand-sage | #8B9A8E | 品牌主色 |
| surface-0 | #1A1614 | 深色背景 |
| text-primary | #F5F1E8 | 主要文字 |
| 按鈕形狀 | `rounded-full` | 圓角膠囊 |
| 卡片效果 | `card-glow` | Sage 光暈 |

---

## 4. 後端 (API Server) 管理

### 啟動指令

```bash
node --env-file=.env packages/panguard/dist/cli/index.js serve \
  --port 3002 \
  --host 127.0.0.1 \
  --db ~/.panguard/auth.db \
  --manager-port 8443
```

### 完整 API 端點列表

#### Auth Routes (`/api/auth/`)

| Method | 路徑 | Auth | 說明 |
|--------|------|------|------|
| POST | `/api/auth/register` | No | 註冊 (自動 14 天 Solo 試用) |
| POST | `/api/auth/login` | No | 登入 (返回 session token) |
| POST | `/api/auth/logout` | Yes | 登出 |
| GET | `/api/auth/me` | Yes | 取得目前用戶資料 |
| POST | `/api/auth/delete-account` | Yes | 刪除帳號 (GDPR) |
| GET | `/api/auth/export-data` | Yes | 匯出用戶資料 (GDPR) |
| POST | `/api/auth/forgot-password` | No | 請求密碼重設 |
| POST | `/api/auth/reset-password` | No | 重設密碼 |

#### TOTP 2FA Routes (`/api/auth/totp/`)

| Method | 路徑 | Auth | 說明 |
|--------|------|------|------|
| POST | `/api/auth/totp/setup` | Yes | 產生 TOTP secret + 備援碼 |
| POST | `/api/auth/totp/verify` | Yes | 驗證 TOTP 碼以啟用 2FA |
| POST | `/api/auth/totp/disable` | Yes | 停用 2FA |
| GET | `/api/auth/totp/status` | Yes | 取得 2FA 狀態 |

#### OAuth Routes (`/api/auth/`)

| Method | 路徑 | Auth | 說明 |
|--------|------|------|------|
| GET | `/api/auth/google` | No | 發起 Google OAuth (PKCE) |
| GET | `/api/auth/google/callback` | No | Google OAuth callback |
| POST | `/api/auth/oauth/exchange` | No | 交換 OAuth code 為 session |
| GET | `/api/auth/cli` | No | CLI OAuth 發起 |
| POST | `/api/auth/cli/exchange` | No | CLI OAuth token 交換 |

#### Admin Routes (`/api/admin/`) — 需要 role=admin

| Method | 路徑 | 說明 |
|--------|------|------|
| GET | `/api/admin/dashboard` | Dashboard 總覽 |
| GET | `/api/admin/users` | 用戶列表 |
| GET | `/api/admin/users/search` | 搜尋用戶 |
| GET | `/api/admin/users/:id` | 用戶詳情 |
| PATCH | `/api/admin/users/:id/tier` | 更新方案等級 |
| PATCH | `/api/admin/users/:id/role` | 更新角色 |
| PATCH | `/api/admin/users/:id/suspend` | 停用帳號 |
| POST | `/api/admin/users/bulk-action` | 批次操作 |
| GET | `/api/admin/stats` | 平台統計 |
| GET | `/api/admin/sessions` | Session 列表 |
| DELETE | `/api/admin/sessions/:id` | 撤銷 Session |
| GET | `/api/admin/activity` | 用戶活動日誌 |
| GET | `/api/admin/audit` | 完整稽核日誌 |
| GET | `/api/admin/audit/actions` | 稽核動作類型 |
| GET | `/api/admin/usage` | 平台使用量 |
| GET | `/api/admin/usage/:userId` | 個別用戶使用量 |
| PATCH | `/api/admin/waitlist/:id/approve` | 核准候補名單 |
| PATCH | `/api/admin/waitlist/:id/reject` | 拒絕候補名單 |
| GET | `/api/admin/settings` | 設定狀態 |

#### Admin Proxy → Manager

| Method | 路徑 | 說明 |
|--------|------|------|
| GET | `/api/admin/agents` | Guard Agent 列表 |
| GET | `/api/admin/agents/:id` | Agent 詳情 |
| GET | `/api/admin/events` | 威脅事件列表 |
| GET | `/api/admin/threats` | 威脅摘要 |
| GET | `/api/admin/overview` | Manager 總覽 |

#### Billing Routes (`/api/billing/`)

| Method | 路徑 | Auth | 說明 |
|--------|------|------|------|
| POST | `/api/billing/webhook` | No (HMAC) | Lemon Squeezy webhook |
| POST | `/api/billing/checkout` | Yes | 建立結帳 URL |
| POST | `/api/billing/portal` | Yes | 建立客戶入口 URL |
| GET | `/api/billing/status` | Yes | 訂閱狀態 |

#### Usage Routes (`/api/usage/`)

| Method | 路徑 | Auth | 說明 |
|--------|------|------|------|
| GET | `/api/usage` | Yes | 目前使用量 + 方案 |
| GET | `/api/usage/limits` | Yes | 方案配額限制 |
| POST | `/api/usage/check` | Yes | 檢查配額 |
| POST | `/api/usage/record` | Yes | 記錄使用量 |

#### Waitlist Routes (`/api/waitlist/`)

| Method | 路徑 | Auth | 說明 |
|--------|------|------|------|
| POST | `/api/waitlist/join` | No | 加入候補名單 |
| GET | `/api/waitlist/verify/:token` | No | 驗證 email |
| GET | `/api/waitlist/stats` | No | 候補統計 |
| GET | `/api/waitlist/list` | Admin | 候補列表 |

#### Manager Server Routes (port 8443)

| Method | 路徑 | 說明 |
|--------|------|------|
| POST | `/api/agents/register` | 註冊 Guard Agent |
| POST | `/api/agents/:id/heartbeat` | Agent 心跳 |
| POST | `/api/agents/:id/events` | 提交威脅報告 |
| DELETE | `/api/agents/:id` | 取消註冊 Agent |
| GET | `/api/agents` | Agent 列表 |
| GET | `/api/agents/:id` | Agent 詳情 |
| GET | `/api/overview` | Dashboard 總覽 |
| GET | `/api/threats` | 近期威脅 |
| GET | `/api/threats/summary` | 威脅摘要 |
| POST | `/api/policy` | 建立政策 |
| GET | `/api/policy/active` | 取得生效政策 |
| GET | `/api/events/stream` | SSE 即時串流 |
| GET | `/health` | 健康檢查 |

#### Utility Routes

| Method | 路徑 | 說明 |
|--------|------|------|
| GET | `/health` | 健康檢查 + DB 探測 |
| GET | `/openapi.json` | OpenAPI 3.0 規格 |
| GET | `/docs/api` | Swagger UI |

### API 回應格式

```json
// 成功
{
  "ok": true,
  "data": { ... }
}

// 失敗
{
  "ok": false,
  "error": "錯誤訊息"
}
```

### 安全 Headers

伺服器自動加入：
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Strict-Transport-Security` (僅生產環境)

### 啟動驗證

生產環境 (NODE_ENV=production) 必填：
- `JWT_SECRET` — 不設定則拒絕啟動
- `PANGUARD_BASE_URL` — OAuth/email 連結必需
- `CORS_ALLOWED_ORIGINS` — 跨域請求必需

### 背景排程

- **每小時**: 檢查過期方案，自動降級為 community
- **每小時**: 發送 3 天內到期的警告 email

---

## 5. CLI 管理

### 全部 22 個指令

| 指令 | 說明 | 方案要求 |
|------|------|---------|
| `panguard` | 互動式 TUI 模式 | Community |
| `panguard scan` | 安全掃描 | Community |
| `panguard scan --quick` | 快速掃描 (~30s) | Community |
| `panguard scan --output report.pdf` | 產生 PDF 報告 | Community |
| `panguard scan --target 1.2.3.4` | 遠端掃描 | Solo+ |
| `panguard scan --json` | JSON 輸出 | Community |
| `panguard guard start` | 啟動即時防護 | Solo+ |
| `panguard guard stop` | 停止防護 | Solo+ |
| `panguard guard restart` | 重啟防護 | Solo+ |
| `panguard guard status` | 防護狀態 | Solo+ |
| `panguard guard config` | 防護設定 | Solo+ |
| `panguard report generate --framework iso27001` | 產生合規報告 | Pro+ |
| `panguard report summary` | 報告摘要 | Pro+ |
| `panguard report list-frameworks` | 列出合規框架 | Pro+ |
| `panguard chat setup` | 通知設定精靈 | Solo+ |
| `panguard chat test` | 測試通知 | Solo+ |
| `panguard trap start --services ssh,http,mysql` | 啟動蜜罐 | Pro+ |
| `panguard login` | OAuth 登入 | All |
| `panguard login --no-browser` | 無瀏覽器登入 (SSH) | All |
| `panguard logout` | 登出 | All |
| `panguard whoami` | 顯示目前用戶 | All |
| `panguard serve` | 啟動 HTTP 伺服器 | All |
| `panguard admin init` | 建立初始 admin 帳號 | All |
| `panguard admin create-user` | 建立用戶 | Admin |
| `panguard status` | 系統狀態 | All |
| `panguard config` | 設定管理 | All |
| `panguard doctor` | 診斷工具 | All |
| `panguard deploy` | 部署工具 | All |
| `panguard hardening` | 安全強化 | All |
| `panguard init` | 專案初始化 | All |
| `panguard threat` | 威脅分析 | All |
| `panguard upgrade` | 升級方案 | All |
| `panguard demo` | Demo 模式 | All |
| `panguard audit skill <path>` | Skill 安全審計 | All |

### CLI 認證流程

```
panguard login
    ↓
啟動本地 callback server (隨機 port)
    ↓
自動開啟瀏覽器 → panguard.ai OAuth
    ↓
用戶在瀏覽器登入
    ↓
Callback 收到 auth code
    ↓
交換 code 為 session token
    ↓
儲存至 ~/.panguard/credentials.json
```

### 認證檔案

```json
// ~/.panguard/credentials.json
{
  "email": "user@example.com",
  "name": "User Name",
  "tier": "solo",
  "token": "session-token-hash",
  "expiresAt": "2026-03-13T19:35:00Z"
}
```

### 互動模式 (TUI)

執行 `panguard` 不帶參數啟動互動式選單：
- 按數字鍵即時選擇 (1-8)
- 麵包屑導航 (隨時知道在哪)
- 自動語言偵測 (EN / ZH-TW)
- 掃描完成後自動建議啟動 Guard

---

## 6. 後台管理面板 (Admin Dashboard)

### 存取方式

1. 網頁前端: `http://localhost:3001/admin/dashboard` (需 admin 角色)
2. 後端靜態: `http://localhost:3002/admin` (內建 HTML)

### 建立 Admin 帳號

```bash
# 方法 1: CLI
panguard admin init --db ~/.panguard/auth.db

# 方法 2: API + SQLite
# 先註冊
curl -X POST http://localhost:3002/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@panguard.ai","password":"YourPassword123","name":"Admin"}'

# 升級為 admin
sqlite3 ~/.panguard/auth.db \
  "UPDATE users SET role='admin', tier='business' WHERE email='admin@panguard.ai';"
```

### 功能總覽

#### Dashboard (`/admin/dashboard`)
- 4 統計卡片: Endpoints Monitored, Active Threats, Guard Agents Online, Threats Blocked (30d)
- 14 天威脅趨勢圖 (長條圖)
- 最近警報列表 (嚴重度標籤: critical/high/medium/low)
- Guard Agent 狀態網格 (online/warning/offline + 威脅計數)
- Threat Cloud 連線狀態
- **目前狀態: Mock Data (未串接 API)**

#### Endpoints (`/admin/endpoints`)
- 搜尋: hostname, IP, OS, tag
- 篩選: All / Online / Warning / Offline
- 排序: hostname / status / threat count
- 表格: hostname, OS, Guard version, Status, Last heartbeat, CPU/Memory 使用率
- **目前狀態: Mock Data (14 個模擬 endpoints)**

#### Threats (`/admin/threats`)
- 摘要卡片: Critical / High / Medium / Low 計數
- 搜尋: description, type, IP, endpoint
- 排序: time / severity / confidence
- 可展開威脅卡片: 類型圖示、嚴重度、來源 IP、目標 endpoint、信心指數
- 10 種威脅類型: rootkit, c2_communication, privilege_escalation, port_scan, unauthorized_package, binary_modification, brute_force, data_exfiltration, malware_download, reverse_shell
- **目前狀態: Mock Data (10 個模擬事件)**

### 權限控制

```
user.role === 'admin'  → 可存取 /admin/*
user.role === 'user'   → 重導至 /dashboard
未登入                  → 重導至 /login
```

---

## 7. 使用者體驗全流程

### 完整用戶旅程

```
┌─────────────────────────────────────────────────────────────────────┐
│ 第一階段: 探索與註冊                                                 │
│                                                                     │
│  panguard.ai → 首頁 (15 區塊) → 產品頁 → 定價頁                     │
│       ↓                                                             │
│  /register (Email/Password) 或 /login (Google OAuth)                │
│       ↓                                                             │
│  /dashboard (Onboarding Checklist)                                  │
│    □ Install CLI                                                    │
│    □ First scan                                                     │
│    □ Guard active                                                   │
│    □ Notifications configured                                       │
└─────────────────────────────────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 第二階段: CLI 安裝與認證                                             │
│                                                                     │
│  curl -fsSL https://get.panguard.ai | bash                          │
│       ↓                                                             │
│  自動下載 binary → ~/.panguard/bin/panguard                          │
│  建立 wrapper script → ~/.local/bin/panguard                         │
│  自動加入 PATH (shell profile)                                       │
│       ↓                                                             │
│  panguard login → 開啟瀏覽器 → OAuth → token 存入本地                 │
└─────────────────────────────────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 第三階段: 掃描與防護                                                 │
│                                                                     │
│  panguard scan --quick (30s 快速掃描)                                │
│       ↓                                                             │
│  Risk Score: 62/100 [============--------] Grade: C                 │
│  Findings: CRITICAL / HIGH / MEDIUM / LOW                           │
│       ↓                                                             │
│  Agent 自動建議: "要啟動 Guard 防護嗎?" [Yes/No]                      │
│       ↓                                                             │
│  panguard guard start                                               │
│  Day 1-7: Learning Mode (觀察正常行為)                               │
│  Day 8+:  Protection Mode (自動偵測+回應)                            │
└─────────────────────────────────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 第四階段: 通知與監控                                                 │
│                                                                     │
│  panguard chat setup                                                │
│    → 選擇通道: Telegram / Slack / Email / Webhook                    │
│    → 選擇角色: boss / developer / it_admin                          │
│       ↓                                                             │
│  管理員: /admin/dashboard → 監控所有 endpoints                       │
└─────────────────────────────────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 第五階段: 進階功能 (Pro+)                                            │
│                                                                     │
│  panguard trap start --services ssh,http,mysql (蜜罐)               │
│  panguard report generate --framework iso27001 (合規報告)            │
│  panguard audit skill <path> (Skill 安全審計)                        │
└─────────────────────────────────────────────────────────────────────┘
```

### 定價方案

| 方案 | 月費 | Endpoints | 主要功能 |
|------|------|-----------|---------|
| **Community** | $0 | 1 | Scan + Layer 1 Guard |
| **Solo** | $9/mo | 3 | Full Guard (3 layers) + Chat |
| **Pro** | $29/mo | 10 | + Trap + Report + Advanced Chat |
| **Business** | $79/mo | 25 | + Custom models + SIEM + SSO |

年付享 20% 折扣。

### 合規報告加購 (Pro+)

| 框架 | 控制項 | 指令 |
|------|--------|------|
| Taiwan TCSA | 10 | `--framework tcsa` |
| ISO 27001 | 30 | `--framework iso27001` |
| SOC 2 | 10 | `--framework soc2` |

---

## 8. 環境變數完整參考

### 後端 Server (.env)

```bash
# ── 伺服器 ──────────────────────────────────────────
PANGUARD_PORT=3002                              # API 埠號
PANGUARD_HOST=127.0.0.1                         # 綁定位址
PANGUARD_BASE_URL=http://localhost:3002          # 公開 URL (OAuth callback 用)
PANGUARD_AUTH_DB=~/.panguard/auth.db             # SQLite 路徑
NODE_ENV=production                              # 生產環境 (啟用嚴格檢查)

# ── 認證 ────────────────────────────────────────────
JWT_SECRET=your-secret-key-min-32-chars          # JWT 密鑰 (生產必填)
CORS_ALLOWED_ORIGINS=https://panguard.ai         # 允許跨域的來源 (逗號分隔)

# ── Google OAuth ────────────────────────────────────
GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com  # Google OAuth Client ID
GOOGLE_CLIENT_SECRET=GOCSPX-xxx                  # Google OAuth Client Secret
GOOGLE_REDIRECT_URI=http://localhost:3002/api/auth/google/callback

# ── Email (二選一) ──────────────────────────────────
# 方案 A: Resend (推薦)
RESEND_API_KEY=re_xxxxxxxxxxxx
RESEND_FROM=Panguard AI <noreply@panguard.ai>

# 方案 B: SMTP
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your@email.com
SMTP_PASS=your-app-password
SMTP_FROM=noreply@panguard.ai

# ── Lemon Squeezy (付款) ───────────────────────────
LEMON_SQUEEZY_API_KEY=eyJ...                     # API Key
LEMON_SQUEEZY_STORE_ID=303383                    # Store ID
LEMON_SQUEEZY_WEBHOOK_SECRET=d4dfe98...          # Webhook Secret
LEMON_SQUEEZY_VARIANT_MAP={"1355444":"solo","1355423":"pro","1355437":"business"}

# ── AI Provider ─────────────────────────────────────
ANTHROPIC_API_KEY=sk-ant-...                     # Claude API Key
OPENAI_API_KEY=sk-...                            # OpenAI API Key
PANGUARD_LLM_MODEL=claude-sonnet-4-20250514      # 預設模型

# ── Manager ─────────────────────────────────────────
MANAGER_AUTH_TOKEN=openssl-rand-hex-32            # Manager API Token (生產必填)

# ── Threat Cloud ────────────────────────────────────
TC_API_KEYS=key1,key2                            # Threat Cloud API Keys
TC_BACKUP_DIR=/var/backups/threat-cloud           # 備份目錄

# ── Google Sheets (候補名單同步) ────────────────────
GOOGLE_SHEETS_ID=spreadsheet-id
GOOGLE_SHEETS_SA_EMAIL=panguard@project.iam.gserviceaccount.com
GOOGLE_SHEETS_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"

# ── Error Tracking ──────────────────────────────────
SENTRY_DSN=https://xxxx@sentry.io/1234

# ── 其他 ────────────────────────────────────────────
ABUSEIPDB_KEY=api-key                            # IP 信譽查詢
PANGUARD_CREDENTIAL_KEY=32-byte-hex              # 認證加密金鑰
```

### 前端 Website (packages/website/.env.local)

```bash
NEXT_PUBLIC_API_URL=http://localhost:3002         # 後端 API URL
NEXT_PUBLIC_CHECKOUT_ENABLED=true                 # 啟用結帳
NEXT_PUBLIC_PLAUSIBLE_DOMAIN=panguard.ai          # 分析 (選用)
```

---

## 9. 資料庫管理

### 位置與技術

- **引擎**: SQLite (better-sqlite3)
- **預設路徑**: `~/.panguard/auth.db`
- **可自訂**: `PANGUARD_AUTH_DB` 環境變數

### 資料表結構

#### users
```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  password_hash TEXT,
  role TEXT DEFAULT 'user',        -- user | admin
  tier TEXT DEFAULT 'community',   -- community | solo | pro | business | enterprise
  verified INTEGER DEFAULT 0,
  suspended INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  last_login TEXT,
  plan_expires_at TEXT
);
```

#### sessions
```sql
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id),
  token TEXT UNIQUE NOT NULL,      -- SHA-256 hash
  expires_at TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);
```

#### subscriptions (Lemon Squeezy)
```sql
CREATE TABLE subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id),
  ls_subscription_id TEXT UNIQUE,
  ls_customer_id TEXT,
  ls_variant_id TEXT,
  tier TEXT,
  status TEXT,
  renews_at TEXT,
  ends_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT
);
```

#### 其他表
- **totp_secrets** — 2FA TOTP 密鑰 (AES-256-GCM 加密)
- **password_reset_tokens** — 密碼重設 token (SHA-256 hash)
- **usage_meters** — 使用量計量 (user_id + resource + period)
- **audit_log** — 稽核日誌 (action, actor_id, target_id, details)
- **waitlist** — 候補名單 (email, status, verify_token hash)
- **report_purchases** — 報告加購紀錄

### 常用管理指令

```bash
# 查看所有用戶
sqlite3 ~/.panguard/auth.db "SELECT id, email, name, role, tier FROM users;"

# 升級用戶為 admin
sqlite3 ~/.panguard/auth.db "UPDATE users SET role='admin' WHERE email='xxx@example.com';"

# 變更用戶方案
sqlite3 ~/.panguard/auth.db "UPDATE users SET tier='pro' WHERE email='xxx@example.com';"

# 查看活躍 sessions
sqlite3 ~/.panguard/auth.db "SELECT s.id, u.email, s.expires_at FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.expires_at > datetime('now');"

# 清除過期 sessions
sqlite3 ~/.panguard/auth.db "DELETE FROM sessions WHERE expires_at < datetime('now');"

# 查看稽核日誌
sqlite3 ~/.panguard/auth.db "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 20;"

# 候補名單統計
sqlite3 ~/.panguard/auth.db "SELECT status, COUNT(*) FROM waitlist GROUP BY status;"

# 備份資料庫
sqlite3 ~/.panguard/auth.db ".backup /path/to/backup.db"

# 或使用 cp (SQLite 單一檔案)
cp ~/.panguard/auth.db ~/.panguard/auth.db.backup
```

---

## 10. Google OAuth 設定

### 建立 Google OAuth Credentials

1. 前往 https://console.cloud.google.com/apis/credentials
2. 建立專案 (或選擇現有專案)
3. 點「Create Credentials」→「OAuth client ID」
4. Application type: **Web application**
5. Name: `Panguard AI`
6. Authorized JavaScript origins:
   - 開發: `http://localhost:3001`
   - 生產: `https://panguard.ai`
7. Authorized redirect URIs:
   - 開發: `http://localhost:3002/api/auth/google/callback`
   - 生產: `https://api.panguard.ai/api/auth/google/callback`
8. 複製 Client ID 和 Client Secret 填入 `.env`

### 目前設定

```bash
# .env
GOOGLE_CLIENT_ID=<your-google-client-id>.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=<your-google-client-secret>
GOOGLE_REDIRECT_URI=http://localhost:3002/api/auth/google/callback
```

### OAuth 流程

```
用戶點「Continue with Google」
    ↓
GET /api/auth/google → 302 Redirect to Google
    ↓ (PKCE: code_challenge + state)
Google 登入頁面
    ↓
Google callback → GET /api/auth/google/callback?code=xxx&state=yyy
    ↓
後端驗證 state, 交換 code 為 tokens
    ↓
取得 Google 用戶資料 (email, name, picture)
    ↓
建立/查找用戶 (新用戶自動 14 天 Solo 試用)
    ↓
產生一次性 exchange code
    ↓
302 Redirect to frontend?code=xxx
    ↓
前端偵測 URL 中的 code, POST /api/auth/oauth/exchange
    ↓
取得 session token, 儲存至 localStorage
```

### 注意事項

- Google OAuth 新用戶自動 `role=user`，需要手動升級為 admin
- PKCE 流程 (S256) 無需 client secret 暴露在前端
- State 參數防止 CSRF 攻擊

---

## 11. Lemon Squeezy 付款設定

### 設定流程

1. 前往 https://app.lemonsqueezy.com/settings/api 取得 API Key
2. 建立 Products & Variants (Solo, Pro, Business)
3. 設定 Webhook URL: `https://api.panguard.ai/api/billing/webhook`
4. 設定 Webhook Secret
5. 記錄 Variant ID → Tier 對應

### 環境變數

```bash
LEMON_SQUEEZY_API_KEY=eyJ...
LEMON_SQUEEZY_STORE_ID=303383
LEMON_SQUEEZY_WEBHOOK_SECRET=d4dfe986663b88316eeacfa5b26507be16499bde
LEMON_SQUEEZY_VARIANT_MAP={"1355444":"solo","1355423":"pro","1355437":"business"}
```

### Webhook 事件

| 事件 | 處理邏輯 |
|------|---------|
| `order.created` | 升級用戶方案 |
| `order.refunded` | 降級為 community |
| `subscription.created` | 記錄訂閱 |
| `subscription.updated` | 更新方案/到期日 |
| `subscription.cancelled` | 排程降級 |

### 結帳流程

```
前端: POST /api/billing/checkout { tier: "pro" }
    ↓
後端: 呼叫 Lemon Squeezy API 建立 checkout session
    ↓
回傳: { ok: true, data: { url: "https://panguard.lemonsqueezy.com/checkout/..." } }
    ↓
前端: window.location.href = url (重導至付款頁)
    ↓
付款完成 → Webhook → 自動升級方案
```

---

## 12. 通知系統 (Email/Telegram/Slack)

### 支援通道

| 通道 | 設定方式 | 特色 |
|------|---------|------|
| Telegram | `panguard chat setup --channel telegram` | Bot 互動、即時推播 |
| Slack | `panguard chat setup --channel slack` | Block Kit 格式化 |
| Email | `panguard chat setup --channel email` | HTML 格式報告 |
| LINE | `panguard chat setup --channel line` | LINE Notify |
| Webhook | `panguard chat setup --channel webhook` | 自訂 HTTP + mTLS |

### 三種語氣模式

| 模式 | 適合對象 | 內容風格 |
|------|---------|---------|
| `boss` | 老闆/主管 | 影響摘要、白話語言 |
| `developer` | 開發者 | 技術細節、程式碼片段 |
| `it_admin` | IT 管理員 | 修復步驟、SOP |

### 設定範例

```bash
# Telegram + boss 模式
panguard chat setup --channel telegram --user-type boss

# Slack + IT admin 模式
panguard chat setup --channel slack --user-type it_admin

# 測試通知
panguard chat test
```

---

## 13. CI/CD 管線

### GitHub Actions Workflows

| 檔案 | 觸發條件 | 用途 |
|------|---------|------|
| `ci.yml` | push to main/dev, PR | Lint + TypeCheck + Test + Build |
| `release.yml` | tag `v*.*.*` | 4 平台 binary + GitHub Release + npm publish |
| `deploy.yml` | push to main | Docker build + 部署 + health check |
| `installer-e2e.yml` | push/PR | 安裝腳本端對端測試 |
| `cli-smoke.yml` | push/PR | CLI 基本功能測試 |
| `uptime.yml` | cron | 定期健康檢查 + 告警 |

### Release 自動化流程

```
git tag v0.3.1 && git push --tags
    ↓
release.yml 觸發:
    ↓
┌─ Build 4 平台 binary ──────────────┐
│  darwin-arm64  (macOS Apple Silicon) │
│  linux-x64     (Linux x86-64)       │
│  linux-arm64   (Linux ARM)          │
│  win-x64       (Windows x86-64)    │
└─────────────────────────────────────┘
    ↓
建立 GitHub Release + SHA256SUMS
    ↓
npm publish @panguard-ai/panguard + @panguard-ai/core
```

### CI 修復注意

- installer E2E 測試已從 ci.yml 和 deploy.yml 排除 (有獨立 workflow)
- ESLint 有 66 個預存 `no-unused-vars` 警告 (非阻塞)

---

## 14. Docker 部署

### 建置映像

```bash
cd /Users/user/Downloads/panguard-ai
docker build -t panguard-api .
```

### Docker Compose

```bash
docker compose up -d
```

服務：
- **panguard-api** — Port 3000, 含所有 API 路由
- **ollama** — Port 11434, 本地 AI (選用)

### Dockerfile 特點

- 多階段建置 (build → production)
- Node 22-slim base
- pnpm workspace 完整支援
- better-sqlite3 原生模組編譯
- standalone bundle (無 pnpm symlinks)
- tini 作為 PID 1

### 環境變數傳入

```bash
docker run -p 3000:3000 \
  -e JWT_SECRET=your-secret \
  -e PANGUARD_BASE_URL=https://api.panguard.ai \
  -e CORS_ALLOWED_ORIGINS=https://panguard.ai \
  -v panguard-data:/data \
  panguard-api
```

---

## 15. 版本發佈流程

### 完整 Checklist

```bash
# 1. 更新版本號 (所有位置)
#    - packages/panguard/package.json → version
#    - packages/core/package.json → version
#    - packages/website/src/lib/stats.ts → cliVersion
#    - docs/getting-started.md → 版本號
#    - docs/DEPLOYMENT.md → tag 範例

# 2. 更新 Changelog
#    packages/website/src/data/changelog-entries.ts

# 3. 確認無殘留舊版本號
grep -r "0\.3\.0" packages/ docs/ --include="*.ts" --include="*.json" --include="*.md"

# 4. 建置
pnpm build

# 5. 測試
pnpm test

# 6. Commit
git add -A
git commit -m "feat: prepare v0.3.2 release"

# 7. Tag + Push
git tag v0.3.2
git push && git push --tags

# 8. 驗證 CI
#    - GitHub Actions release.yml 執行
#    - GitHub Release 頁面有 4 platform binaries
#    - npm registry 有新版本

# 9. 部署網站
cd packages/website && vercel deploy --prod

# 10. 驗證安裝
curl -fsSL https://get.panguard.ai | bash
panguard --version  # 應該顯示新版本
```

### 版本號位置一覽

| 檔案 | 欄位 |
|------|------|
| `packages/panguard/package.json` | `"version"` |
| `packages/core/package.json` | `"version"` |
| `packages/website/src/lib/stats.ts` | `cliVersion` |
| `docs/getting-started.md` | 多處版本引用 |
| `docs/DEPLOYMENT.md` | tag 範例 |

---

## 16. 安全性檢查清單

### 密碼與認證

- [x] 密碼 hash: scrypt (N=65536, r=8, p=1, keylen=64)
- [x] Session tokens: 32-byte random, SHA-256 hash 儲存
- [x] TOTP 2FA: AES-256-GCM 加密, 備援碼
- [x] Password reset: SHA-256 hash, 限時 token
- [x] Rate limiting: 登入/註冊/重設 各有限制

### 傳輸安全

- [x] CORS: 明確允許來源清單 (生產環境必設)
- [x] CSP: Content Security Policy headers
- [x] HSTS: Strict-Transport-Security (生產環境)
- [x] X-Frame-Options: SAMEORIGIN
- [x] X-Content-Type-Options: nosniff

### 資料安全

- [x] SQL: 參數化查詢 (better-sqlite3)
- [x] XSS: 前端 React 自動轉義
- [x] SSRF: 遠端掃描私有 IP 阻擋
- [x] No eval/Function: 禁止動態程式碼執行
- [x] Input validation: Zod schema 驗證
- [x] Webhook: HMAC 簽名驗證 (Lemon Squeezy)

### 程式碼安全

- [x] SAST: 16 pattern 靜態分析
- [x] ReDoS: Sigma 規則正則表達式保護
- [x] 進程執行: execFile() only (無 shell injection)
- [x] 相依性: 定期 `pnpm audit`
- [x] Manager API: 生產環境需 MANAGER_AUTH_TOKEN
- [x] Waitlist token: SHA-256 hash 儲存

### 生產環境必填

| 環境變數 | 說明 |
|---------|------|
| `JWT_SECRET` | 不設定則拒絕啟動 |
| `PANGUARD_BASE_URL` | OAuth/email 連結必需 |
| `CORS_ALLOWED_ORIGINS` | 跨域請求控制 |
| `MANAGER_AUTH_TOKEN` | Manager API 認證 |

---

## 17. 故障排除 (Troubleshooting)

### 後端無法啟動

```
Error: JWT_SECRET not set in production
```
→ 設定 `JWT_SECRET` 或確認 `NODE_ENV` 不是 `production`

```
Error: listen EADDRINUSE :::3002
```
→ 其他程式占用 port: `lsof -i :3002` 找到並 kill

### Google OAuth 不工作

```
OAuth: Not configured
```
→ 確認 `.env` 有 `GOOGLE_CLIENT_ID` 和 `GOOGLE_CLIENT_SECRET`，重啟後端

```
Error: redirect_uri_mismatch
```
→ Google Cloud Console 的 redirect URI 必須完全匹配 `GOOGLE_REDIRECT_URI`

### 前端 CORS 錯誤

```
Access-Control-Allow-Origin header missing
```
→ 確認 `.env` 的 `CORS_ALLOWED_ORIGINS` 包含前端 URL (如 `http://localhost:3001`)

### CLI 安裝失敗

```
panguard: command not found
```
→ 確認 `~/.local/bin` 在 PATH 中: `echo $PATH | tr ':' '\n' | grep local`
→ 重新載入 shell: `source ~/.zshrc` 或 `source ~/.bashrc`

### 資料庫鎖定

```
Error: SQLITE_BUSY: database is locked
```
→ 確認沒有其他程式存取同一個 .db 檔案
→ 檢查: `lsof ~/.panguard/auth.db`

### 建置失敗

```
Cannot read file 'packages/xxx/tsconfig.json'
```
→ 確認所有 packages 在 Dockerfile COPY 中都有列出
→ 使用 build-error-resolver agent 或 `pnpm build 2>&1 | head -50`

### Vercel 部署

```
VERCEL_TOKEN expired
```
→ 生成新 token: https://vercel.com/account/tokens
→ 或使用本地 CLI: `cd packages/website && vercel deploy --prod`

### Guard 不啟動

```
Tier check failed: requires solo or above
```
→ 確認 CLI 已登入且方案為 Solo 以上: `panguard whoami`

---

## 18. 常用指令速查表

### 開發

```bash
# 安裝依賴
pnpm install

# 建置所有 packages
pnpm build

# 單獨建置某個 package
cd packages/core && pnpm build

# 執行測試
pnpm test

# 執行單一測試檔案
pnpm exec vitest run packages/panguard-auth/tests/auth.test.ts

# 型別檢查
pnpm exec tsc --noEmit

# Lint
pnpm exec eslint .
```

### 伺服器管理

```bash
# 啟動後端 (開發)
node --env-file=.env packages/panguard/dist/cli/index.js serve --port 3002

# 啟動前端 (開發)
cd packages/website && npx next dev -p 3001

# 查看 port 使用狀況
lsof -i :3001 -i :3002 | grep LISTEN

# 健康檢查
curl http://localhost:3002/health | python3 -m json.tool
```

### 資料庫

```bash
# 查看用戶
sqlite3 ~/.panguard/auth.db "SELECT id, email, role, tier FROM users;"

# 升級為 admin
sqlite3 ~/.panguard/auth.db "UPDATE users SET role='admin' WHERE email='xxx';"

# 備份
cp ~/.panguard/auth.db ~/.panguard/auth.db.$(date +%Y%m%d)
```

### 部署

```bash
# Docker
docker build -t panguard-api .
docker compose up -d

# Vercel (網站)
cd packages/website && vercel deploy --prod

# 發佈新版本
git tag v0.3.2 && git push --tags
```

### CLI

```bash
panguard                          # 互動模式
panguard scan --quick             # 快速掃描
panguard guard start              # 啟動防護
panguard chat setup               # 通知設定
panguard login                    # 登入
panguard whoami                   # 目前用戶
panguard doctor                   # 診斷
```

---

## 19. 已知問題與改進建議

| # | 區域 | 問題 | 嚴重度 | 建議 |
|---|------|------|--------|------|
| 1 | Admin Dashboard | 全部使用 mock data，未串接後端 API | Medium | 串接 `/api/admin/dashboard` + `/api/admin/agents` |
| 2 | Admin Endpoints | 同上 mock data | Medium | 串接 Manager API `/api/agents` |
| 3 | Admin Threats | 同上 mock data | Medium | 串接 Manager API `/api/threats` |
| 4 | Admin Policies | 頁面未實作 (Coming Soon) | Low | 實作政策管理 UI |
| 5 | Admin Settings | 頁面未實作 (Coming Soon) | Low | 實作系統設定 UI |
| 6 | Account Settings | `/account/settings` 路由存在但無內容 | Medium | 實作帳號設定頁 |
| 7 | Account Billing | `/account/billing` 路由存在但無內容 | Medium | 實作帳單管理頁 |
| 8 | User Dashboard | 使用 mock usage data | Low | 串接 `/api/usage` |
| 9 | ENV 更新 | 前端需重啟 dev server 才能套用 .env.local 變更 | Low | Next.js 限制，無法熱更新 |
| 10 | Google OAuth | 新用戶自動 role=user，需手動 DB 升級為 admin | Low | 加入 admin invite flow |
| 11 | ESLint | 66 個預存 no-unused-vars 警告 | Low | 批次修復 |
| 12 | Vercel Token | GitHub Secret VERCEL_TOKEN 過期 | Medium | 更新 token 或設定 auto-rotate |
| 13 | Skill Auditor | 無測試檔案 | Low | 補充單元測試 |
| 14 | panguard-mcp | 僅 1 個測試 | Low | 補充覆蓋率 |

---

## 附錄 A: 關鍵檔案路徑速查

| 用途 | 路徑 |
|------|------|
| 後端入口 | `packages/panguard/src/cli/commands/serve.ts` |
| Auth 路由 | `packages/panguard-auth/src/routes/auth.ts` |
| OAuth 路由 | `packages/panguard-auth/src/routes/oauth.ts` |
| TOTP 路由 | `packages/panguard-auth/src/routes/totp.ts` |
| Admin 路由 | `packages/panguard-auth/src/routes/admin.ts` |
| Billing 路由 | `packages/panguard-auth/src/routes/billing.ts` |
| Usage 路由 | `packages/panguard-auth/src/routes/usage.ts` |
| Waitlist 路由 | `packages/panguard-auth/src/routes/waitlist.ts` |
| DB Schema | `packages/panguard-auth/src/database.ts` |
| 前端 Auth | `packages/website/src/lib/auth.tsx` |
| Admin Layout | `packages/website/src/app/[locale]/admin/layout.tsx` |
| Admin Dashboard | `packages/website/src/app/[locale]/admin/dashboard/DashboardContent.tsx` |
| Admin Endpoints | `packages/website/src/app/[locale]/admin/endpoints/EndpointsContent.tsx` |
| Admin Threats | `packages/website/src/app/[locale]/admin/threats/ThreatsContent.tsx` |
| Login Form | `packages/website/src/app/[locale]/login/LoginForm.tsx` |
| Register Form | `packages/website/src/app/[locale]/register/RegisterForm.tsx` |
| User Dashboard | `packages/website/src/app/[locale]/dashboard/DashboardContent.tsx` |
| Pricing Cards | `packages/website/src/app/[locale]/pricing/PricingCards.tsx` |
| CLI 入口 | `packages/panguard/src/cli/index.ts` |
| CLI 互動模式 | `packages/panguard/src/cli/interactive.ts` |
| Guard 引擎 | `packages/panguard-guard/src/guard-engine.ts` |
| Detect Agent | `packages/panguard-guard/src/agent/detect-agent.ts` |
| Analyze Agent | `packages/panguard-guard/src/agent/analyze-agent.ts` |
| Respond Agent | `packages/panguard-guard/src/agent/respond-agent.ts` |
| Report Agent | `packages/panguard-guard/src/agent/report-agent.ts` |
| Event Correlator | `packages/panguard-guard/src/correlation/event-correlator.ts` |
| FunnelRouter | `packages/core/src/ai/funnel-router.ts` |
| Manager Server | `packages/panguard-manager/src/server.ts` |
| Threat Cloud | `packages/threat-cloud/src/database.ts` |
| 安裝腳本 | `scripts/installer/install.sh` |
| 網站統計 | `packages/website/src/lib/stats.ts` |
| 環境變數範本 | `.env.example` |
| CI/CD | `.github/workflows/` |
| Docker | `Dockerfile` + `docker-compose.yml` |
| 安全政策 | `SECURITY.md` |

---

## 附錄 B: 測試覆蓋率

| Package | 測試檔案數 | 說明 |
|---------|-----------|------|
| panguard-guard | 29 | 最完整覆蓋 |
| panguard-auth | 13 | 認證流程 |
| core | 12 | 核心模組 |
| panguard | 11 | CLI 指令 |
| threat-cloud | 11 | 威脅情報 |
| security-hardening | 10 | 安全強化 |
| panguard-chat | 10 | 通知系統 |
| panguard-report | 8 | 報告產生 |
| panguard-scan | 7 | 掃描器 |
| panguard-trap | 7 | 蜜罐 |
| panguard-manager | 7 | Manager |
| panguard-web | 5 | Web 引擎 |
| panguard-mcp | 1 | MCP Server |
| panguard-skill-auditor | 0 | **缺少測試** |

測試框架: Vitest 3.0 + coverage-v8
總測試案例: ~3,017+

---

*本文件由 Panguard AI 開發團隊維護。如有問題請聯絡 admin@panguard.ai*
