# Threat Cloud API / API 參考文件

> Threat Cloud 的 RESTful API 完整參考。

---

## Base URL

```
http://localhost:8080/api/v1
```

---

## 認證

如果 Threat Cloud 啟用了 API Key 認證，所有請求需在 Header 帶上：

```
Authorization: Bearer your-api-key
```

未啟用認證時不需要此 Header。

---

## 端點

### Health Check

確認伺服器是否正常運行。

```
GET /api/v1/health
```

**回應：**

```json
{
  "status": "ok",
  "version": "0.1.0",
  "uptime": 3600
}
```

---

### 提交 IoC

提交一個入侵指標到 Threat Cloud。

```
POST /api/v1/ioc
```

**Request Body：**

```json
{
  "type": "ip",
  "value": "203.0.113.50",
  "confidence": 95,
  "source": "panguard guard",
  "tags": ["c2", "botnet"],
  "description": "Known C2 server detected by behavioral analysis"
}
```

**欄位說明：**

| 欄位          | 類型     | 必填 | 說明                                             |
| ------------- | -------- | ---- | ------------------------------------------------ |
| `type`        | string   | v    | IoC 類型：`ip`, `domain`, `url`, `hash`, `email` |
| `value`       | string   | v    | IoC 值                                           |
| `confidence`  | number   | v    | 信心度 0-100                                     |
| `source`      | string   | -    | 來源識別                                         |
| `tags`        | string[] | -    | 標籤（如 `c2`, `botnet`, `phishing`）            |
| `description` | string   | -    | 描述                                             |

**回應：**

```json
{
  "id": "ioc-12345",
  "created": true
}
```

---

### 查詢 IoC

查詢特定 IoC 的威脅情報。

```
GET /api/v1/ioc?type=ip&value=203.0.113.50
```

**Query Parameters：**

| 參數    | 類型   | 必填 | 說明     |
| ------- | ------ | ---- | -------- |
| `type`  | string | v    | IoC 類型 |
| `value` | string | v    | IoC 值   |

**回應：**

```json
{
  "found": true,
  "ioc": {
    "type": "ip",
    "value": "203.0.113.50",
    "confidence": 95,
    "tags": ["c2", "botnet"],
    "description": "Known C2 server",
    "firstSeen": "2024-01-10T08:00:00Z",
    "lastSeen": "2024-01-15T14:23:00Z",
    "reportCount": 47
  }
}
```

**未找到時：**

```json
{
  "found": false,
  "ioc": null
}
```

---

### 批量查詢

一次查詢多個 IoC。

```
POST /api/v1/ioc/batch
```

**Request Body：**

```json
{
  "indicators": [
    { "type": "ip", "value": "203.0.113.50" },
    { "type": "domain", "value": "malware.example.com" },
    { "type": "hash", "value": "a1b2c3d4..." }
  ]
}
```

**回應：**

```json
{
  "results": [
    { "type": "ip", "value": "203.0.113.50", "found": true, "confidence": 95 },
    { "type": "domain", "value": "malware.example.com", "found": false },
    { "type": "hash", "value": "a1b2c3d4...", "found": true, "confidence": 72 }
  ]
}
```

---

### 最新威脅

取得最近提交的 IoC。

```
GET /api/v1/ioc/recent?limit=100
```

**Query Parameters：**

| 參數    | 類型   | 預設 | 說明                              |
| ------- | ------ | ---- | --------------------------------- |
| `limit` | number | `50` | 回傳數量上限                      |
| `type`  | string | -    | 過濾 IoC 類型                     |
| `since` | string | -    | ISO 8601 時間，只回傳此時間之後的 |

**回應：**

```json
{
  "total": 100,
  "indicators": [
    {
      "type": "ip",
      "value": "203.0.113.50",
      "confidence": 95,
      "tags": ["c2"],
      "lastSeen": "2024-01-15T14:23:00Z"
    }
  ]
}
```

---

### 統計

取得 Threat Cloud 統計資訊。

```
GET /api/v1/stats
```

**回應：**

```json
{
  "totalIoCs": 12345,
  "last24h": 234,
  "byType": {
    "ip": 5678,
    "domain": 3456,
    "url": 1234,
    "hash": 1987
  },
  "topTags": [
    { "tag": "c2", "count": 3456 },
    { "tag": "botnet", "count": 2345 },
    { "tag": "phishing", "count": 1234 }
  ]
}
```

---

## 錯誤回應

所有 API 錯誤使用統一格式：

```json
{
  "error": "error_code",
  "message": "Human-readable error description"
}
```

### 常見錯誤碼

| HTTP 狀態碼 | 錯誤碼            | 說明               |
| ----------- | ----------------- | ------------------ |
| 400         | `invalid_request` | 請求格式錯誤       |
| 401         | `unauthorized`    | API Key 缺失或無效 |
| 404         | `not_found`       | 端點不存在         |
| 429         | `rate_limited`    | 請求頻率過高       |
| 500         | `internal_error`  | 伺服器內部錯誤     |

---

## 速率限制

| 端點              | 限制        |
| ----------------- | ----------- |
| `POST /ioc`       | 100 次/分鐘 |
| `GET /ioc`        | 300 次/分鐘 |
| `POST /ioc/batch` | 30 次/分鐘  |
| `GET /ioc/recent` | 60 次/分鐘  |

超過限制時回傳 `429 Too Many Requests`。

---

## SDK 範例

### Node.js

```typescript
const response = await fetch('http://localhost:8080/api/v1/ioc', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    Authorization: 'Bearer your-api-key',
  },
  body: JSON.stringify({
    type: 'ip',
    value: '203.0.113.50',
    confidence: 95,
    tags: ['c2'],
  }),
});

const result = await response.json();
```

### curl

```bash
# 提交 IoC
curl -X POST http://localhost:8080/api/v1/ioc \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-api-key" \
  -d '{"type":"ip","value":"203.0.113.50","confidence":95}'

# 查詢 IoC
curl "http://localhost:8080/api/v1/ioc?type=ip&value=203.0.113.50" \
  -H "Authorization: Bearer your-api-key"
```

---

## 相關文件

- [Threat Cloud 部署指南](../guides/threat-cloud.md)
- [威脅情報概念](../concepts/threat-intelligence.md)
