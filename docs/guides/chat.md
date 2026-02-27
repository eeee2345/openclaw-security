# Panguard Chat / 通知設定指南 `[STARTER]`

> 讓 AI 用你習慣的方式通知你安全事件。老闆看人話，工程師看技術細節。
>
> 設定和測試通知管道需要 **Starter** 以上方案。

---

## 快速開始

```bash
# 互動式設定
panguard chat setup

# 直接指定管道和角色
panguard chat setup --channel line --user-type boss --lang zh-TW

# 測試通知
panguard chat test

# 查看狀態
panguard chat status
```

---

## 5 個通知管道

| 管道     | 適合對象          | 特色                         |
| -------- | ----------------- | ---------------------------- |
| LINE     | 個人用戶（台灣）  | 最普及的通訊軟體             |
| Telegram | 個人用戶 / 開發者 | Bot API，Markdown 格式       |
| Slack    | 團隊 / 企業       | Block Kit 豐富格式，頻道分流 |
| Email    | 合規場景          | SMTP HTML，留存紀錄          |
| Webhook  | 自動化整合        | mTLS 安全，自訂 payload      |

---

## 設定各管道

### LINE

```bash
panguard chat setup --channel line
```

設定精靈會要求：

1. LINE Notify Token（從 [notify-bot.line.me](https://notify-bot.line.me) 取得）

### Telegram

```bash
panguard chat setup --channel telegram
```

設定精靈會要求：

1. Bot Token（從 [@BotFather](https://t.me/botfather) 取得）
2. Chat ID

### Slack

```bash
panguard chat setup --channel slack
```

設定精靈會要求：

1. Webhook URL（從 Slack App 設定取得）

Slack 通知使用 Block Kit 格式，包含結構化的嚴重等級標示和操作按鈕。

### Email

```bash
panguard chat setup --channel email
```

設定精靈會要求：

1. SMTP Host
2. SMTP Port
3. 使用者帳號
4. 密碼
5. 寄件人地址
6. 收件人地址

Email 使用 HTML 格式，包含品牌配色的告警模板。

### Webhook

```bash
panguard chat setup --channel webhook
```

設定精靈會要求：

1. Webhook URL
2. 認證方式（可選：mTLS 憑證路徑）

Webhook 支援 mTLS 雙向認證，適合企業級安全整合。

---

## 3 種使用者角色

同一個安全事件，Chat 會根據你的角色調整通知格式：

### boss — 影響摘要

適合：老闆、非技術主管。

```
[Panguard AI 安全通知]

偵測到你的伺服器正在與一個已知的惡意伺服器通訊。
該 IP 已被全球 1,247 次檢舉。
已自動封鎖，無需你採取行動。

風險等級：高
處理狀態：已自動處理
```

### developer — 技術細節

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

### it_admin — 修復步驟

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
| 成就解鎖     | 解鎖新成就                | 即時      |

---

## 雙語支援

```bash
# 繁體中文通知
panguard chat setup --channel line --lang zh-TW

# 英文通知
panguard chat setup --channel line --lang en
```

所有通知模板都有 English 和繁體中文兩個版本。

---

## 憑證安全

Chat 的管道認證資訊（Token、密碼等）使用 AES-256-GCM 加密儲存在本地，不會以明文存放。

---

## CLI 選項

```
panguard chat <command> [options]

Commands:
  setup              互動式設定精靈
  test               發送測試通知
  status             顯示管道狀態
  config             顯示目前設定
  help               顯示說明

Options:
  --channel <type>       管道類型（line|telegram|slack|email|webhook）
  --user-type <type>     使用者角色（developer|boss|it_admin）
  --lang <en|zh-TW>      語言
  --data-dir <path>      資料目錄
```

完整 CLI 參考見 [CLI 指令參考](../reference/cli.md)。
