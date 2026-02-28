# Panguard Chat

> 自動產生 | `./dev-docs/update.sh chat`

## 概述

AI 資安助理，透過 LINE / Telegram / Slack / Email / Webhook 五種通道推送警報。根據用戶類型（開發者 / 老闆 / IT 管理員）自動調整語氣。

## 數據

| 項目 | 數據 |
|------|------|
| 套件名 | `@panguard-ai/panguard-chat` |
| 程式碼 | 4532 行 / 20 檔 |
| 測試 | 6 個測試檔 |
| 匯出 | 30+ 個公開 API |
| 位置 | `packages/panguard-chat/src/` |
| 方案門檻 | Solo+ (通知功能) |

## 主要模組

| 模組 | 路徑 | 功能 |
|------|------|------|
| Agent | `src/agent/` | ChatAgent 核心 — 警報發送、追問、確認流程 |
| 通道 | `src/channels/` | LINE, Telegram, Slack, Email, Webhook |
| Server | `src/server/` | Webhook 接收器 + 簽名驗證 |
| 模板 | `src/templates/` | 7 種預建警報模板 |
| 引導 | `src/onboarding/` | 互動式設定精靈 |

## 用戶類型

| 類型 | 溝通風格 |
|------|----------|
| developer | 技術細節、MITRE ATT&CK、CVE、CLI 指令 |
| boss | 非技術類比、商業影響、財損估算 |
| it_admin | 技術 + 合規、系統檢查清單、事件報告 |

## 警報模板

SSH 暴力破解 / 勒索軟體偵測 / SQL 注入 / 可疑外連 / 編碼指令執行 / 權限提升 / 資料外洩

## CLI 指令

```bash
panguard-chat setup      # 互動式設定 (--channel, --user-type, --lang)
panguard-chat test       # 發送測試通知
panguard-chat status     # 顯示已設定通道
panguard-chat config     # 顯示設定 (JSON)
panguard-chat prefs      # 查看/更新通知偏好
```

## 通道認證

| 通道 | 認證方式 |
|------|----------|
| LINE | HMAC-SHA256 簽名驗證 |
| Telegram | Bot Token |
| Slack | Signing Secret + 重放保護 |
| Email | SMTP + STARTTLS |
| Webhook | Bearer Token / HMAC / mTLS |

## 依賴

- `@panguard-ai/core` - 基礎工具
- Node.js 內建模組 (crypto, http, net)

## 待辦

- [ ] Discord 通道
- [ ] Microsoft Teams 通道
- [ ] 訊息排程（靜音時段）
