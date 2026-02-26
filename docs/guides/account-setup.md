# Account Setup / 帳號設定指南

> 從建立帳號到 CLI 登入，完整的入門指南。

---

## 步驟 1：建立帳號

前往 [panguard.ai](https://panguard.ai) 建立帳號：

1. 點擊右上角「註冊」
2. 選擇 Google 帳號登入或輸入 Email + 密碼
3. 完成後取得帳號

### 選擇方案

在 [panguard.ai/pricing](https://panguard.ai/pricing) 瀏覽方案：

| 方案 | 月費 | 適合 |
|------|------|------|
| **Scan** | $0 | 快速掃描、了解安全狀況 |
| **Solo** | $9/月 | 個人開發者、1 端點 |
| **Starter** | $19/月 | 小團隊、最多 5 端點 |
| **Team** | $14/端點/月 | 中型團隊、5-50 端點 |
| **Business** | $10/端點/月 | 企業、50-500 端點 |
| **Enterprise** | 聯繫我們 | 500+ 端點、專屬支援 |

Scan 方案可直接使用，付費方案透過 CLI 或網站升級。合規報告為獨立加價購。

---

## 步驟 2：安裝 CLI

### 一行指令安裝（推薦）

```bash
curl -fsSL https://get.panguard.ai | sh
```

### 使用 npm 安裝

```bash
npm install -g @openclaw/panguard
```

### 從原始碼安裝（開發者，目前推薦）

```bash
git clone https://github.com/openclaw-security/openclaw-security.git
cd openclaw-security
pnpm install
pnpm build
# CLI: ./bin/panguard --help 或 pnpm cli -- --help
```

---

## 步驟 3：CLI 登入

```bash
panguard login
```

CLI 會自動開啟瀏覽器。在瀏覽器中完成登入後，回到終端機會看到：

```
  PANGUARD [#] AI

  -- 登入資訊 ----------------------------------------

  Email     user@example.com
  名稱      User Name
  方案      Team
  到期      2026-04-27

  登入成功！
```

### 驗證登入狀態

```bash
panguard whoami
```

```
  PANGUARD [#] AI

  -- 帳號資訊 ----------------------------------------

  Email     user@example.com
  名稱      User Name
  方案      Team
  到期      2026-04-27
  伺服器    https://panguard.ai
```

---

## 步驟 4：初始設定

執行設定精靈（可選，但推薦）：

```bash
panguard init
```

互動式精靈引導你完成：
- 語言選擇
- 防護模式和監控項目
- 通知管道（LINE / Telegram / Slack / Email / Webhook）
- AI 偏好（Cloud AI / Local AI / Rules Only）
- 安全等級

---

## 步驟 5：第一次掃描

```bash
panguard scan --quick
```

你會看到系統安全評估結果，包含風險分數和修復建議。

---

## 常見問題

### 瀏覽器沒有自動開啟

使用 `--no-browser` 選項手動開啟 URL：

```bash
panguard login --no-browser
```

### 在 SSH / 無頭伺服器上登入

同上，使用 `--no-browser`，將印出的 URL 複製到其他有瀏覽器的裝置開啟。

### 登入後看到「等級不足」

表示你的訂閱方案不支援該功能。到 [panguard.ai/pricing](https://panguard.ai/pricing) 升級方案。

### Token 過期

CLI session 有效期為 30 天。過期後重新執行：

```bash
panguard login
```

---

## 下一步

| 想做什麼 | 指令 |
|---------|------|
| 執行安全掃描 | `panguard scan` |
| 啟動即時防護 | `panguard guard start` |
| 設定通知管道 | `panguard chat setup` |
| 部署所有服務 | `panguard deploy` |
| 查看系統狀態 | `panguard status` |
| 查看所有指令 | `panguard --help` |

---

## 相關文件

- [認證架構](../concepts/authentication.md) — 認證流程技術說明
- [快速開始](../getting-started.md) — 5 分鐘上手指南
- [CLI 指令參考](../reference/cli.md) — 完整 CLI 文件
