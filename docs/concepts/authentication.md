# Authentication / 認證架構

> 了解 Panguard AI 的認證流程：網站註冊、CLI 登入、功能分級。

---

## 認證流程概覽

Panguard AI 採用與 Claude Code 相似的認證模式：

1. **在網站註冊帳號** — 瀏覽方案、建立帳號、管理訂閱
2. **在 CLI 登入** — `panguard login` 開瀏覽器完成 OAuth → 本地儲存 token
3. **使用功能** — CLI 根據訂閱等級自動解鎖對應功能

```
  使用者
    |
    v
  [panguard.ai]  ← 註冊 / 瀏覽方案 / 管理訂閱
    |
    | OAuth
    v
  [panguard login]  ← 開瀏覽器 → 完成登入 → 回到終端機
    |
    | token 儲存在 ~/.panguard/credentials.json
    v
  [panguard scan / guard / trap ...]  ← 依等級使用功能
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
  "tier": "team",
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

## 功能分級

### 6 個訂閱等級

| 等級 | 月費 | 定位 |
|------|------|------|
| **Scan** | $0 | 快速掃描、了解安全狀況（轉換入口） |
| **Solo** | $9 | 防護 + 1 通知管道（個人開發者） |
| **Starter** | $19 | 防護 + 3 通知管道（小團隊、最多 5 端點） |
| **Team** | $14/端點 | 全功能含蜜罐（中型團隊、5-50 端點） |
| **Business** | $10/端點 | 全功能 + 基礎合規報告（企業、50-500 端點） |
| **Enterprise** | 聯繫我們 | 500+ 端點 + 專屬支援 |

### CLI 功能對照

| 指令 | 最低等級 | 說明 |
|------|---------|------|
| `panguard init` | 無需登入 | 設定精靈 |
| `panguard login / logout / whoami` | 無需等級 | 認證指令 |
| `panguard status` | Scan | 狀態查詢 |
| `panguard demo` | Scan | 功能展示 |
| `panguard scan --quick` | Scan | 快速掃描 |
| `panguard scan` | Solo | 完整掃描 |
| `panguard guard start` | Solo | 即時防護 |
| `panguard chat setup` | Solo | 通知設定 |
| `panguard deploy` | Solo | 部署服務 |
| `panguard trap` | Team | 蜜罐系統 |
| `panguard report` | Team | 合規報告（需加價購或 Business 方案） |
| `panguard threat` | Business | 威脅情報 API |

### 等級檢查機制

CLI 使用 `withAuth()` 裝飾器檢查登入狀態和訂閱等級：

- **未登入** → 提示「請執行 panguard login」
- **等級不足** → 提示「此功能需要 {tier}，升級請見 panguard.ai/pricing」
- **已登入且等級足夠** → 正常執行

---

## 安全措施

| 項目 | 說明 |
|------|------|
| CSRF 防護 | 隨機 state token 驗證 callback |
| Callback 限制 | 只接受 localhost callback URL |
| 檔案權限 | credentials.json 設為 0o600 |
| Token 到期 | 30 天自動過期 |
| 流程逾時 | 待處理認證流程 10 分鐘後自動清理 |

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

- [帳號設定指南](../guides/account-setup.md) — 從零開始建立帳號
- [快速開始](../getting-started.md) — 5 分鐘上手指南
- [CLI 指令參考](../reference/cli.md) — 完整 CLI 文件
- [設定檔格式](../reference/configuration.md) — credentials.json 說明
