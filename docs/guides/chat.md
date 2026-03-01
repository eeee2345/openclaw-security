# Panguard Chat / 通知設定指南 `[SOLO]`

> 讓 AI 用你習慣的方式通知你安全事件。老闆看人話，工程師看技術細節。
>
> 設定和測試通知管道需要 **Solo** 以上方案。

---

## 快速開始

```bash
# 互動式設定
panguard chat setup

# 直接指定管道和角色
panguard chat setup --channel telegram --user-type boss --lang zh-TW

# 測試通知
panguard chat test

# 查看狀態
panguard chat status
```

---

## 4 個通知管道

| 管道     | 適合對象          | 特色                             |
| -------- | ----------------- | -------------------------------- |
| Telegram | 個人用戶 / 開發者 | Bot API，Markdown 格式，全球通用 |
| Slack    | 團隊 / 企業       | Block Kit 豐富格式，頻道分流     |
| Email    | 合規場景          | SMTP HTML，留存紀錄              |
| Webhook  | 自動化整合        | mTLS 安全，自訂 payload          |

---

## Telegram 串接教程（Step by Step）

### 步驟 1：建立 Telegram Bot

1. 打開 Telegram，搜尋 **@BotFather** 並開始對話
2. 輸入 `/newbot`
3. 為你的 Bot 取一個顯示名稱（例如 `My Panguard Security`）
4. 為你的 Bot 取一個 username（必須以 `bot` 結尾，例如 `my_panguard_bot`）
5. BotFather 會回覆你一個 **Bot Token**，格式像：
   ```
   7123456789:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   ```
6. **複製並妥善保存這個 Token**，等下會用到

### 步驟 2：取得你的 Chat ID

方法 A（推薦）：

1. 在 Telegram 搜尋 **@userinfobot** 並開始對話
2. 輸入任意文字（例如 `/start`）
3. 它會回覆你的 **Chat ID**（純數字，例如 `123456789`）

方法 B（API）：

1. 先用 Telegram 傳一則訊息給你剛建立的 Bot
2. 在瀏覽器打開：
   ```
   https://api.telegram.org/bot<你的TOKEN>/getUpdates
   ```
3. 在 JSON 回應中找到 `"chat":{"id": 123456789}`

### 步驟 3：設定 Panguard Chat

```bash
panguard chat setup --channel telegram
```

設定精靈會依序詢問：

- **Bot Token**：貼上步驟 1 取得的 Token
- **Chat ID**：貼上步驟 2 取得的 Chat ID

或者非互動式設定：

```bash
panguard chat setup --channel telegram --user-type developer --lang zh-TW
```

### 步驟 4：測試

```bash
panguard chat test --channel telegram
```

你的 Telegram 應該會收到一則測試訊息。如果沒收到：

- 確認你已經先傳過訊息給你的 Bot（Bot 無法主動跟沒互動過的用戶聊天）
- 確認 Bot Token 和 Chat ID 正確
- 確認網路可以連到 `api.telegram.org`

### Telegram 群組通知（選用）

如果想讓 Bot 發通知到群組：

1. 建立一個 Telegram 群組
2. 把你的 Bot 加入群組
3. 在群組中傳一則訊息
4. 用 `getUpdates` API 取得群組的 Chat ID（群組 ID 是負數，例如 `-1001234567890`）
5. 設定 Panguard Chat 時使用這個群組 Chat ID

---

## Slack 串接教程（Step by Step）

### 步驟 1：建立 Slack App

1. 前往 [api.slack.com/apps](https://api.slack.com/apps)
2. 點擊 **Create New App**
3. 選擇 **From scratch**
4. App 名稱輸入 `Panguard Security`（或你喜歡的名稱）
5. 選擇你的 Workspace
6. 點擊 **Create App**

### 步驟 2：設定 Bot 權限

1. 在左側選單點 **OAuth & Permissions**
2. 往下滾到 **Scopes** 區塊
3. 在 **Bot Token Scopes** 底下，新增以下權限：

| Scope               | 用途                        |
| ------------------- | --------------------------- |
| `chat:write`        | 發送訊息到頻道              |
| `chat:write.public` | 發送到 Bot 未加入的公開頻道 |
| `files:write`       | 上傳 PDF 報告等附件         |

4. 點擊上方 **Install to Workspace**
5. 點 **Allow** 授權

### 步驟 3：取得 Bot Token

1. 安裝完成後，頁面會顯示 **Bot User OAuth Token**
2. 格式像：`xoxb-your-workspace-id-your-token-string`
3. **複製並妥善保存這個 Token**

### 步驟 4：取得 Signing Secret

1. 在左側選單點 **Basic Information**
2. 找到 **App Credentials** 區塊
3. 點 **Show** 顯示 **Signing Secret**
4. **複製並保存**

### 步驟 5：建立通知頻道

1. 在你的 Slack Workspace 建立一個頻道，例如 `#security-alerts`
2. 邀請你的 Bot 進入頻道：在頻道中輸入 `/invite @Panguard Security`

### 步驟 6：設定 Panguard Chat

```bash
panguard chat setup --channel slack
```

設定精靈會依序詢問：

- **Bot Token**：貼上步驟 3 的 `xoxb-...` Token
- **Signing Secret**：貼上步驟 4 的 Signing Secret
- **Default Channel**：輸入 `#security-alerts`（或你建的頻道名稱）

### 步驟 7：測試

```bash
panguard chat test --channel slack
```

你的 `#security-alerts` 頻道應該會收到一則測試訊息。如果沒收到：

- 確認 Bot 已被邀請到該頻道
- 確認 Bot Token 格式正確（以 `xoxb-` 開頭）
- 確認 Bot 有 `chat:write` 權限
- 在 Slack App 設定頁確認 App 已安裝到 Workspace

### Slack 進階設定（選用）

**互動式按鈕回應：**

如果想讓 Slack 通知帶有互動按鈕（例如「封鎖來源」、「查看詳情」），需要設定 Interactivity：

1. 在 Slack App 設定中，點 **Interactivity & Shortcuts**
2. 開啟 **Interactivity**
3. 填入 Request URL：`https://your-server.com/webhook/slack`
4. 點 **Save Changes**

> 互動功能需要你的伺服器有公開 URL。如果在本地開發，可用 ngrok 暫時暴露。

---

## Email 設定

```bash
panguard chat setup --channel email
```

設定精靈會要求：

1. SMTP Host（例如 `smtp.gmail.com`）
2. SMTP Port（587 for TLS, 465 for SSL）
3. SMTP 帳號
4. SMTP 密碼（Gmail 需使用 App Password）
5. 寄件人地址
6. 收件人地址

> Gmail 用戶注意：需要先到 Google 帳號設定中建立 App Password。
> 路徑：Google 帳號 > 安全性 > 兩步驟驗證 > 應用程式密碼

---

## Webhook

```bash
panguard chat setup --channel webhook
```

設定精靈會要求：

1. Webhook URL
2. 認證方式（Bearer Token / HMAC / mTLS）
3. 密鑰或 Token

Webhook 支援 mTLS 雙向認證，適合企業級安全整合。

---

## 3 種使用者角色

同一個安全事件，Chat 會根據你的角色調整通知格式：

### boss -- 影響摘要

適合：老闆、非技術主管。

```
[Panguard AI 安全通知]

偵測到你的伺服器正在與一個已知的惡意伺服器通訊。
該 IP 已被全球 1,247 次檢舉。
已自動封鎖，無需你採取行動。

風險等級：高
處理狀態：已自動處理
```

### developer -- 技術細節

適合：開發者、技術人員。

```
[Panguard AI Alert]

Threat Intel Match: 203.0.113.50
Source: AbuseIPDB (confidence: 98%)
Tag: C2-Server, ThreatFox IOC-12345
Process: curl (PID 5678) -> 203.0.113.50:443
Action: IP blocked via iptables
Rule: sigma/network/c2-communication.yml

Timeline:
  14:23:01 - Outbound connection detected
  14:23:02 - Threat intel match confirmed
  14:23:02 - Auto-response: IP blocked
```

### it_admin -- 修復步驟

適合：IT 管理員。

```
[Panguard AI - 修復指引]

事件：偵測到與已知 C2 伺服器的通訊
嚴重等級：高
已執行：自動封鎖 IP 203.0.113.50

建議後續步驟：
1. 檢查程序 curl (PID 5678) 是否為合法操作
2. 如果不是，終止程序：kill -9 5678
3. 檢查是否有其他程序連線到同一 IP
4. 掃描系統是否有後門：panguard scan
5. 如果確認入侵，執行完整調查
```

---

## 通知類型

Chat 會發送以下類型的通知：

| 類型         | 觸發條件                  | 頻率      |
| ------------ | ------------------------- | --------- |
| 威脅告警     | Guard 偵測到威脅          | 即時      |
| 自動回應通知 | Guard 自動執行了回應動作  | 即時      |
| 確認請求     | 信心度 70-90%，需要你確認 | 即時      |
| 每日摘要     | 每天固定時間              | 每日 1 次 |
| 學習進度     | 學習模式期間              | 每日 1 次 |
| 分數變化     | 安全分數顯著變動          | 即時      |

---

## 雙語支援

```bash
# 繁體中文通知
panguard chat setup --channel telegram --lang zh-TW

# 英文通知
panguard chat setup --channel slack --lang en
```

所有通知模板都有 English 和繁體中文兩個版本。

---

## 憑證安全

Chat 的管道認證資訊（Token、密碼等）使用 AES-256-GCM 加密儲存在本地，不會以明文存放。

---

## 常見問題

### Telegram Bot 收不到訊息？

1. 確認你已經先傳訊息給 Bot（Bot 不能主動聯繫新用戶）
2. 確認 Chat ID 正確（用 @userinfobot 確認）
3. 確認 Bot Token 沒有過期或被 revoke

### Slack Bot 發不出訊息？

1. 確認 Bot 已被邀請到目標頻道
2. 確認 Bot Token 以 `xoxb-` 開頭（不是 `xoxp-`）
3. 確認 Bot 有 `chat:write` scope
4. 檢查 Slack App 是否已安裝到 Workspace

### 如何切換通知管道？

重新執行 `panguard chat setup` 即可。

---

## CLI 選項

```
panguard chat <command> [options]

Commands:
  setup              互動式設定精靈
  test               發送測試通知
  status             顯示管道狀態
  config             顯示目前設定
  prefs              查看/更新通知偏好
  help               顯示說明

Options:
  --channel <type>       管道類型（telegram|slack|email|webhook）
  --user-type <type>     使用者角色（developer|boss|it_admin）
  --lang <en|zh-TW>      語言
  --data-dir <path>      資料目錄
```

完整 CLI 參考見 [CLI 指令參考](../reference/cli.md)。
