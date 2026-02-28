# 技術棧

> 自動產生 | `./dev-docs/update.sh _project`

## 核心技術

| 類別 | 技術 | 版本 |
|------|------|------|
| 語言 | TypeScript | 5.7 (strict) |
| 執行環境 | Node.js | 20+ |
| 套件管理 | pnpm | 10 (monorepo) |
| 測試 | Vitest | 3 |
| Lint | ESLint | 9 + security plugin |
| 格式化 | Prettier | semi, singleQuote, 100 width |
| CI/CD | GitHub Actions | lint → test → build |

## AI 整合

| 層級 | 技術 | 用途 |
|------|------|------|
| Layer 1 | Sigma + YARA | 規則引擎 (90% 事件) |
| Layer 2 | Ollama (llama3/phi3/mistral) | 本地 AI (7% 事件) |
| Layer 3 | Claude / GPT-4 | 雲端 AI (3% 事件) |

## 框架

| 用途 | 框架 |
|------|------|
| CLI | Commander.js |
| 官網 | Next.js 14 (App Router) |
| 樣式 | Tailwind CSS |
| 國際化 (CLI) | i18next |
| 國際化 (網站) | next-intl |
| 動畫 | Framer Motion |
| 圖示 | Lucide React |
| PDF | pdfkit |

## 資料庫

| 用途 | 技術 |
|------|------|
| Auth 認證 | SQLite (better-sqlite3) |
| Threat Cloud | SQLite (better-sqlite3) |
| 憑證加密 | AES-256-GCM (machine-locked) |
| 密碼雜湊 | scrypt |

## 安全監控

| 來源 | 技術 |
|------|------|
| Kernel 監控 | Falco eBPF |
| 網路 IDS | Suricata |
| 檔案完整性 | inotify / FSEvents |
| Windows 事件 | ETW / Sysmon |
| Linux 事件 | auditd / syslog |

## 部署目標

| 目標 | 工具 |
|------|------|
| 容器 | Docker (Node.js 22 多階段) |
| 雲端 | Railway |
| 網站 | Vercel |
| 系統服務 | systemd / launchd |
| CLI | npm / curl 安裝腳本 |
