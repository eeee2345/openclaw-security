# Troubleshooting / 常見問題

> 遇到問題？這裡整理了最常見的狀況和解決方法。

---

## 認證問題

### panguard login 瀏覽器沒開啟

**可能原因：** 你在 SSH / headless 環境中。

```bash
# 使用 --no-browser 模式
panguard login --no-browser
# 複製印出的 URL 到其他裝置的瀏覽器開啟
```

### panguard login 逾時

**可能原因：** 認證流程超過 10 分鐘。

```bash
# 重新執行
panguard login
```

### 「未登入」但已經登入過

**可能原因：** Token 已過期（30 天到期）。

```bash
# 檢查狀態
panguard whoami

# 重新登入
panguard login
```

### 「等級不足」錯誤

**可能原因：** 你的訂閱方案不支援該功能。

```bash
# 查看目前方案
panguard whoami

# 到網站升級
# https://panguard.ai/pricing
```

### credentials.json 權限錯誤

```bash
# 修正權限
chmod 600 ~/.panguard/credentials.json
```

---

## 安裝問題

### pnpm install 失敗

**錯誤：** `ERR_PNPM_UNSUPPORTED_ENGINE`

```
Your Node.js version (v18.x) is not compatible
```

**解決方法：** Panguard 需要 Node.js >= 20。

```bash
# 使用 nvm 安裝 Node.js 20
nvm install 20
nvm use 20
node --version  # 應顯示 v20.x.x
```

### pnpm build 失敗

**錯誤：** TypeScript 編譯錯誤

```bash
# 確保依賴都已安裝
pnpm install

# 清除舊編譯結果重新編譯
pnpm build
```

---

## Panguard Scan

### 掃描卡住不動

**可能原因：** 網路掃描在等待 port 回應。

**解決方法：**

```bash
# 使用 --quick 跳過耗時的檢查
panguard scan --quick

# 或加 --verbose 看是卡在哪一步
panguard scan --verbose
```

### PDF 報告產生失敗

**可能原因：** 輸出路徑權限不足或磁碟空間不足。

```bash
# 確認路徑可寫入
panguard scan --output ~/Desktop/report.pdf
```

### 掃描結果全部是 INFO

**可能原因：** 你的系統安全設定很好，或是 --quick 模式跳過了深度檢查。

```bash
# 試試完整掃描
panguard scan --verbose
```

---

## Panguard Guard

### Guard 啟動失敗

**錯誤：** `Guard is already running`

```bash
# 先停止現有實例
panguard guard stop

# 如果 stop 也失敗，手動清除 PID 檔案
rm ~/.panguard-guard/guard.pid

# 重新啟動
panguard guard start
```

**錯誤：** `Permission denied`

```bash
# Guard 需要權限監控系統事件
# macOS / Linux：用 sudo
sudo panguard guard start

# 或安裝為系統服務（自動取得權限）
sudo panguard guard install
```

### Guard 記憶體使用過高

**可能原因：** 規則太多或基線資料過大。

```bash
# 查看狀態中的資源使用
panguard guard status

# 限制 Sigma 規則數量
# 移除不需要的規則檔案
ls ~/.panguard-guard/rules/sigma/
```

### Guard 產生大量誤報

**可能原因：** 學習期不夠長，或有新部署的服務。

**解決方法：**

1. 確認你的環境在學習期間是正常運作的
2. 如果最近有大量變更，考慮重置學習
3. 調高信心度閾值

### 自動回應沒有執行

**可能原因：**

1. 你可能使用 Free 版（不支援自動回應，需要 Starter 以上）
2. 信心度低於 90%，需要你確認

```bash
# 檢查登入狀態和訂閱等級
panguard whoami

# 如果需要升級，到 panguard.ai/pricing
```

---

## Panguard Chat

### 通知沒有收到

**排查步驟：**

```bash
# 1. 檢查管道設定
panguard chat status

# 2. 發送測試通知
panguard chat test

# 3. 重新設定
panguard chat setup --channel line
```

**LINE 特定問題：**

- 確認 LINE Notify Token 是否過期
- 確認你的 LINE 帳號有連動 Notify

**Telegram 特定問題：**

- 確認 Bot Token 正確
- 確認 Chat ID 正確（可用 @userinfobot 查詢）
- 確認你已經先對 Bot 發送過訊息

**Slack 特定問題：**

- 確認 Webhook URL 有效
- 確認 Slack App 有權限發送到目標頻道

### 通知語言不對

```bash
# 重新設定語言
panguard chat setup --channel line --lang zh-TW
```

---

## Panguard Trap

### 蜜罐 port 被佔用

**錯誤：** `EADDRINUSE: port 2222 already in use`

```bash
# 找出佔用 port 的程序
lsof -i :2222

# 使用不同 port
panguard trap start --services ssh --port 22222
```

### 沒有攻擊者連入

**可能原因：** 蜜罐 port 沒有對外開放。

確認防火牆允許蜜罐 port 的連入流量（注意：只開放蜜罐 port，不要開放真實服務 port）。

---

## Threat Cloud

### 伺服器啟動失敗

**錯誤：** `EADDRINUSE`

```bash
# 改用其他 port
panguard threat start --port 8081
```

**錯誤：** `SQLITE_CANTOPEN`

```bash
# 確認資料庫目錄存在且可寫入
mkdir -p /var/lib/threat-cloud
panguard threat start --db /var/lib/threat-cloud/data.db
```

### API 回傳 401

確認請求帶有正確的 API Key：

```bash
curl -H "Authorization: Bearer your-api-key" \
  http://localhost:8080/api/v1/health
```

---

## 通用問題

### 支援哪些作業系統？

| 作業系統 | 版本            | 狀態     |
| -------- | --------------- | -------- |
| macOS    | 12+ (Monterey+) | 完整支援 |
| Ubuntu   | 20.04+          | 完整支援 |
| Debian   | 11+             | 完整支援 |
| CentOS   | 8+              | 完整支援 |
| Windows  | 10+             | 完整支援 |

### 需要 root / admin 權限嗎？

- **Scan**：不需要（但部分檢查需要 sudo 才能取得完整結果）
- **Guard**：建議使用 sudo 或安裝為系統服務
- **Chat**：不需要
- **Trap**：port < 1024 需要 sudo
- **Threat Cloud**：port < 1024 需要 sudo

### 如何更新？

```bash
# 如果用一行指令安裝
curl -fsSL https://get.panguard.ai | sh

# 如果從原始碼安裝
git pull
pnpm install
pnpm build
```

### 如何完全移除？

```bash
# 1. 登出
panguard logout

# 2. 停止並移除系統服務
panguard guard uninstall

# 3. 刪除資料目錄
rm -rf ~/.panguard
rm -rf ~/.panguard-guard
rm -rf ~/.panguard-chat

# 4. 移除安裝
# 依你的安裝方式而定
```

---

## 取得幫助

- GitHub Issues: [github.com/panguard-ai/panguard-ai/issues](https://github.com/panguard-ai/panguard-ai/issues)
- 文件: [panguard.ai/docs](https://panguard.ai/docs)
