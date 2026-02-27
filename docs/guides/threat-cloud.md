# Threat Cloud / 集體威脅情報部署指南 `[ENTERPRISE]`

> 你的 Panguard 偵測到的威脅，自動保護所有 Panguard 用戶。
>
> 啟動 Threat Cloud API 伺服器需要 **Enterprise** 方案。

---

## 什麼是 Threat Cloud？

Threat Cloud 是一個集體威脅情報平台。每個 Panguard Guard 偵測到的威脅會匿名化上傳，經過驗證後推送給所有用戶。

**等於你一個人安裝了 Panguard，背後有整個社群的情報在保護你。**

---

## 快速開始

### 使用公共 Threat Cloud（預設）

不需要任何設定。Guard 啟動後自動連接公共 Threat Cloud。

### 部署私有 Threat Cloud

企業可以部署私有的 Threat Cloud 伺服器：

```bash
# 啟動伺服器
panguard threat start --port 8080 --api-key your-secret-key

# 指定資料庫路徑
panguard threat start --port 8080 --db /var/lib/threat-cloud/data.db --api-key key1,key2
```

---

## 伺服器設定

### 基本啟動

```bash
panguard threat start --port 8080
```

預設綁定 `127.0.0.1`（僅本機存取）。要對外服務：

```bash
panguard threat start --host 0.0.0.0 --port 8080 --api-key your-api-key
```

### API Key 認證

開啟 API Key 認證（對外服務時強烈建議）：

```bash
# 單一 API Key
panguard threat start --api-key my-secret-key

# 多個 API Key（給不同用戶端）
panguard threat start --api-key key-team-a,key-team-b,key-team-c
```

用戶端請求需在 Header 帶上：

```
Authorization: Bearer your-api-key
```

### 資料庫

Threat Cloud 使用 SQLite，輕量且零維護：

```bash
# 自訂資料庫路徑
panguard threat start --db /var/lib/threat-cloud/data.db
```

---

## API 端點

Threat Cloud 提供 RESTful API：

### 提交 IoC

```bash
POST /api/v1/ioc

{
  "type": "ip",
  "value": "203.0.113.50",
  "confidence": 95,
  "source": "panguard-guard",
  "tags": ["c2", "botnet"],
  "description": "Known C2 server"
}
```

### 查詢 IoC

```bash
GET /api/v1/ioc?type=ip&value=203.0.113.50
```

### 批量查詢

```bash
POST /api/v1/ioc/batch

{
  "indicators": [
    { "type": "ip", "value": "203.0.113.50" },
    { "type": "domain", "value": "malware.example.com" }
  ]
}
```

### 最新威脅

```bash
GET /api/v1/ioc/recent?limit=100
```

### 健康檢查

```bash
GET /api/v1/health
```

完整 API 參考見 [API 參考文件](../reference/api.md)。

---

## 部署建議

### 小型部署（< 50 個端點）

```bash
# 直接在現有伺服器上跑
panguard threat start --port 8080 --api-key your-key
```

### 中型部署（50-500 個端點）

```bash
# 專用伺服器 + systemd 管理
panguard threat start --host 0.0.0.0 --port 8080 \
  --db /var/lib/threat-cloud/data.db \
  --api-key team-key-1,team-key-2
```

### 資源需求

| 規模        | CPU     | 記憶體 | 磁碟  |
| ----------- | ------- | ------ | ----- |
| < 50 端點   | 1 core  | 256 MB | 1 GB  |
| 50-500 端點 | 2 cores | 512 MB | 5 GB  |
| 500+ 端點   | 4 cores | 1 GB   | 20 GB |

---

## 隱私與安全

### 匿名化

上傳到 Threat Cloud 的資料只包含：

- 威脅指標（IP、domain、URL、hash）
- 信心度分數
- 標籤和分類
- 時間戳記

**不包含**：系統名稱、使用者名稱、內部 IP、檔案內容、任何可識別個人的資訊。

### 傳輸安全

- HTTPS（TLS 1.2+）
- API Key 認證
- 速率限制

### 資料保留

- IoC 預設保留 90 天
- 過期自動清理
- 可自訂保留期限

---

## CLI 選項

```
panguard threat start [options]

Options:
  --port <number>     監聽 port（預設：8080）
  --host <string>     監聽位址（預設：127.0.0.1）
  --db <path>         SQLite 資料庫路徑（預設：./threat-cloud.db）
```

完整 CLI 參考見 [CLI 指令參考](../reference/cli.md)。
