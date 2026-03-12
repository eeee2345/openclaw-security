# Authentication / 認證架構

> 了解 Panguard AI 的認證流程：網站註冊、CLI 登入。

---

## 認證流程概覽

Panguard AI 採用與 Claude Code 相似的認證模式：

1. **在網站註冊帳號** -- 建立帳號
2. **在 CLI 登入** -- `panguard login` 開瀏覽器完成 OAuth，本地儲存 token
3. **使用功能** -- 所有功能對所有使用者免費開放

```
  使用者
    |
    v
  [panguard.ai]  <- 註冊 / 建立帳號
    |
    | OAuth
    v
  [panguard login]  <- 開瀏覽器 -> 完成登入 -> 回到終端機
    |
    | token 儲存在 ~/.panguard/credentials.json
    v
  [panguard scan / guard / trap ...]  <- 所有功能皆可使用
```

---

## CLI 登入流程

### 標準流程（有瀏覽器）

```bash
panguard login
```

1. CLI 在本機啟動臨時 HTTP server（隨機 port）
2. 生成 CSRF state token 防止攻擊
3. 自動開啟瀏覽器到 `panguard.ai/login?cli_state={state}`
4. 使用者在瀏覽器完成 Google OAuth 或密碼登入
5. 伺服器 redirect 回本地 callback URL
6. CLI 接收 token 並儲存到 `~/.panguard/credentials.json`
7. 終端機顯示登入成功

### 無瀏覽器環境（SSH / Headless）

```bash
panguard login --no-browser
```

CLI 會印出認證 URL，你可以複製到有瀏覽器的裝置開啟：

```
  請在瀏覽器開啟以下網址完成登入：
  https://panguard.ai/login?cli_state=abc123&callback=...

  等待認證中...
```

---

## 憑證儲存

### 檔案位置

```
~/.panguard/credentials.json
```

檔案權限設為 `0o600`（僅擁有者可讀寫）。

### 格式

```json
{
  "token": "session-token-string",
  "expiresAt": "2026-04-27T00:00:00.000Z",
  "email": "user@example.com",
  "name": "User Name",
  "savedAt": "2026-02-26T12:00:00.000Z",
  "apiUrl": "https://panguard.ai"
}
```

### Session 有效期

- CLI session：30 天
- 過期後需要重新 `panguard login`
- 可用 `panguard whoami` 查看到期時間

---

## CLI 功能一覽

所有功能對所有使用者免費開放（MIT 授權）：

| 指令                               | 說明                 |
| ---------------------------------- | -------------------- |
| `panguard init`                    | 設定精靈             |
| `panguard login / logout / whoami` | 認證指令             |
| `panguard status`                  | 狀態查詢             |
| `panguard demo`                    | 功能展示             |
| `panguard scan --quick`            | 快速掃描             |
| `panguard scan`                    | 完整掃描             |
| `panguard guard start`             | 即時防護             |
| `panguard chat setup`              | 通知設定             |
| `panguard deploy`                  | 部署服務             |
| `panguard trap`                    | 蜜罐系統（Coming Soon） |
| `panguard report`                  | 合規報告（Coming Soon） |
| `panguard threat`                  | 威脅情報 API         |

---

## 安全措施

| 項目          | 說明                             |
| ------------- | -------------------------------- |
| CSRF 防護     | 隨機 state token 驗證 callback   |
| Callback 限制 | 只接受 localhost callback URL    |
| 檔案權限      | credentials.json 設為 0o600      |
| Token 到期    | 30 天自動過期                    |
| 流程逾時      | 待處理認證流程 10 分鐘後自動清理 |

---

## 常見操作

```bash
# 登入
panguard login

# 查看帳號資訊
panguard whoami

# JSON 格式（for scripting）
panguard whoami --json

# 登出
panguard logout

# 指定認證伺服器（開發/自建）
panguard login --api-url http://localhost:3100
```

---

## 相關文件

- [帳號設定指南](../guides/account-setup.md) -- 從零開始建立帳號
- [快速開始](../getting-started.md) -- 5 分鐘上手指南
- [CLI 指令參考](../reference/cli.md) -- 完整 CLI 文件
- [設定檔格式](../reference/configuration.md) -- credentials.json 說明
