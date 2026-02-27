# Configuration / 設定檔格式

> Panguard AI 各工具的設定檔格式和選項。

---

## Guard 設定

Guard 的設定檔位於資料目錄中：

```
~/.panguard-guard/config.json
```

### 完整設定範例

```json
{
  "mode": "protection",
  "learningDays": 7,
  "monitoring": {
    "processes": true,
    "network": true,
    "files": true,
    "registry": false
  },
  "rules": {
    "sigmaDir": "./rules/sigma",
    "yaraDir": "./rules/yara",
    "autoReload": true
  },
  "response": {
    "autoBlock": true,
    "autoQuarantine": true,
    "autoKill": true,
    "confirmThreshold": 0.7,
    "autoThreshold": 0.9
  },
  "threatIntel": {
    "enabled": true,
    "feeds": ["threatfox", "urlhaus", "feodo", "greynoise", "abuseipdb"],
    "updateInterval": 21600
  },
  "dashboard": {
    "enabled": false,
    "port": 3100
  },
  "notification": {
    "channel": "line",
    "userType": "boss",
    "language": "zh-TW"
  },
  "auth": {
    "tier": "free"
  }
}
```

### 設定項說明

#### mode

| 值           | 說明                     |
| ------------ | ------------------------ |
| `learning`   | 學習模式，不產生告警     |
| `protection` | 保護模式，偵測並回應威脅 |

`learning` 在 7 天後自動切換為 `protection`。

#### monitoring

| 設定        | 類型    | 預設    | 說明                            |
| ----------- | ------- | ------- | ------------------------------- |
| `processes` | boolean | `true`  | 監控程序活動                    |
| `network`   | boolean | `true`  | 監控網路連線                    |
| `files`     | boolean | `true`  | 監控檔案變更                    |
| `registry`  | boolean | `false` | 監控 Windows 登錄（僅 Windows） |

#### response

| 設定               | 類型    | 預設   | 說明                   |
| ------------------ | ------- | ------ | ---------------------- |
| `autoBlock`        | boolean | `true` | 自動封鎖惡意 IP        |
| `autoQuarantine`   | boolean | `true` | 自動隔離可疑檔案       |
| `autoKill`         | boolean | `true` | 自動終止惡意程序       |
| `confirmThreshold` | number  | `0.7`  | 70% 以上信心度詢問確認 |
| `autoThreshold`    | number  | `0.9`  | 90% 以上信心度自動執行 |

#### threatIntel

| 設定             | 類型     | 預設      | 說明                             |
| ---------------- | -------- | --------- | -------------------------------- |
| `enabled`        | boolean  | `true`    | 啟用威脅情報查詢                 |
| `feeds`          | string[] | 全部 5 個 | 啟用的情報來源                   |
| `updateInterval` | number   | `21600`   | Feed 更新間隔（秒，預設 6 小時） |

#### dashboard

| 設定      | 類型    | 預設    | 說明                     |
| --------- | ------- | ------- | ------------------------ |
| `enabled` | boolean | `false` | 啟用 WebSocket Dashboard |
| `port`    | number  | `3100`  | Dashboard 監聽 port      |

---

## Chat 設定

Chat 的設定（含加密認證資訊）位於：

```
~/.panguard chat/config.json
```

### LINE 設定

```json
{
  "channel": "line",
  "userType": "boss",
  "language": "zh-TW",
  "line": {
    "token": "encrypted:..."
  }
}
```

### Telegram 設定

```json
{
  "channel": "telegram",
  "userType": "developer",
  "language": "en",
  "telegram": {
    "botToken": "encrypted:...",
    "chatId": "123456789"
  }
}
```

### Slack 設定

```json
{
  "channel": "slack",
  "userType": "it_admin",
  "language": "en",
  "slack": {
    "webhookUrl": "encrypted:..."
  }
}
```

### Email 設定

```json
{
  "channel": "email",
  "userType": "boss",
  "language": "zh-TW",
  "email": {
    "host": "smtp.gmail.com",
    "port": 587,
    "user": "encrypted:...",
    "pass": "encrypted:...",
    "from": "panguard@example.com",
    "to": "admin@example.com"
  }
}
```

### Webhook 設定

```json
{
  "channel": "webhook",
  "userType": "developer",
  "language": "en",
  "webhook": {
    "url": "https://your-endpoint.com/webhook",
    "mtlsCert": "/path/to/client.crt",
    "mtlsKey": "/path/to/client.key"
  }
}
```

---

## 認證加密

Chat 設定中的敏感欄位（token、密碼、webhook URL）使用 AES-256-GCM 加密：

- 加密金鑰衍生自機器特徵
- 設定檔中以 `encrypted:...` 前綴表示
- 用 `panguard chat setup` 設定時自動加密
- 不要手動編輯加密欄位

---

## 認證憑證

CLI 登入後的憑證檔案：

```
~/.panguard/credentials.json
```

檔案權限為 `0o600`（僅擁有者可讀寫）。由 `panguard login` 自動建立，不要手動編輯。

### 格式

```json
{
  "token": "session-token-string",
  "expiresAt": "2026-04-27T00:00:00.000Z",
  "email": "user@example.com",
  "tier": "pro",
  "name": "User Name",
  "savedAt": "2026-02-26T12:00:00.000Z",
  "apiUrl": "https://panguard.ai"
}
```

### 欄位說明

| 欄位        | 類型   | 說明                                                |
| ----------- | ------ | --------------------------------------------------- |
| `token`     | string | Bearer session token                                |
| `expiresAt` | string | ISO 到期時間（登入後 30 天）                        |
| `email`     | string | 帳號 email                                          |
| `tier`      | string | 訂閱等級：`free` / `starter` / `pro` / `enterprise` |
| `name`      | string | 使用者名稱                                          |
| `savedAt`   | string | 儲存時間                                            |
| `apiUrl`    | string | 認證伺服器 URL                                      |

### 管理指令

```bash
# 建立（透過登入）
panguard login

# 查看
panguard whoami

# 刪除（透過登出）
panguard logout
```

---

## Panguard 設定檔

`panguard init` 產生的統一設定檔：

```
~/.panguard/config.json
```

包含所有模組（Guard、Scan、Trap、Chat 等）的設定。由設定精靈自動產生。

---

## 環境變數

部分設定可透過環境變數覆寫：

| 環境變數             | 說明                              |
| -------------------- | --------------------------------- |
| `PANGUARD_DATA_DIR`  | Guard 資料目錄                    |
| `PANGUARD_LOG_LEVEL` | 日誌等級（debug/info/warn/error） |
| `PANGUARD_LANG`      | 預設語言                          |
