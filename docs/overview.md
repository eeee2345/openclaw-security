# Product Overview / 產品概覽

> AI-Driven Adaptive Endpoint Protection
> AI 驅動的自適應端點防護平台

---

## What is Panguard AI?

Panguard AI 是一個開源的網路安全平台，專為沒有資安團隊的中小企業和個人開發者設計。

核心理念很簡單：**在網站註冊帳號，在 CLI 登入，AI 全自動保護你的機器。有事它會告訴你，沒事你什麼都不用做。**

### 使用體驗

像 Claude / Claude Code 一樣：

1. **網站** — 瀏覽方案、註冊帳號、管理訂閱
2. **CLI** — `panguard login` 開瀏覽器完成認證 → token 存在本地
3. **使用** — 依訂閱等級使用 CLI 功能，零日常操作

### 為什麼需要 Panguard AI？

傳統資安工具的問題：

- 需要專業知識才能安裝和設定
- 介面充滿 Sigma、YARA、IOC、MITRE ATT&CK 等術語
- 產生大量告警，不知道哪些重要
- 企業級工具太貴，免費工具太難用

Panguard AI 的做法：

- **一行指令安裝**，零設定
- **用人話通知你**，透過你已經在用的 LINE / Telegram / Slack
- **AI 自動判斷**嚴重程度並執行回應
- **越用越準**，從你的環境持續學習

---

## 產品線

Panguard AI 包含 6 個產品，各自獨立但可以協同運作：

### Panguard Scan — 60 秒安全健檢

一次性安全掃描，產生風險評分和 PDF 報告。

```bash
panguard scan --quick
```

- 系統環境偵察（OS、網路、port、服務）
- 密碼政策檢查
- 防火牆狀態
- 風險評分 0-100（A-F 等級）
- PDF 報告（含修復建議 + 合規對應）

適合：初次評估、定期健檢、合規稽核前準備。

[詳細指南 ->](guides/scan.md)

---

### Panguard Guard — AI 即時監控 `[STARTER]`

持續運行的 AI 守護引擎，自動偵測和回應威脅。

```bash
panguard guard start
```

- 5 個 AI Agent 管線：Detect -> Analyze -> Respond -> Report -> Investigation
- 7 天學習期建立行為基線
- 42 條 Sigma 規則 + YARA 掃描
- 即時威脅情報（ThreatFox / URLhaus / GreyNoise）
- 自動回應：IP 封鎖、檔案隔離、程序終止
- 安全分數引擎 + 成就系統

適合：伺服器長期防護、VPS 保護、辦公室端點監控。

[詳細指南 ->](guides/guard.md)

---

### Panguard Chat — AI 資安通知 `[STARTER]`

將技術性安全告警翻譯成人話，透過你偏好的管道通知。

```bash
panguard chat setup --channel line --user-type boss
```

- 5 個通知管道：LINE、Telegram、Slack（Block Kit）、Email（SMTP HTML）、Webhook（mTLS）
- 3 種角色格式：
  - **boss** — 影響摘要，人話描述
  - **developer** — 技術細節，指令碼和日誌
  - **it_admin** — 修復步驟，逐步操作指引
- 雙語模板（English / 繁體中文）

適合：所有人。Guard 偵測到威脅後透過 Chat 通知你。

[詳細指南 ->](guides/chat.md)

---

### Panguard Trap — 智慧蜜罐 `[PRO]`

部署假服務引誘攻擊者，收集情報並分析其行為。

- 8 種蜜罐服務：SSH、HTTP、FTP、SMB、MySQL、RDP、Telnet、Redis
- 攻擊者側寫：技術等級分類（腳本小子 / 進階攻擊者 / APT）
- 憑證收集與指令記錄
- 攻擊意圖分析
- 威脅情報報告

適合：想了解誰在攻擊你、攻擊者的意圖和技術水準。

[詳細指南 ->](guides/trap.md)

---

### Panguard Report — 合規報告 `[PRO]`

自動產生符合法規框架的安全合規報告。

- 台灣資通安全管理法（10 個控制項）
- ISO 27001（12 個控制項）
- SOC 2（10 個控制項）
- JSON 和 PDF 格式
- 雙語輸出

適合：需要合規報告的中型企業、稽核準備。

[詳細指南 ->](guides/report.md)

---

### Threat Cloud — 集體威脅情報 `[ENTERPRISE]`

匿名化的威脅情報共享平台，所有 Panguard 用戶共同建構防護網。

```bash
panguard threat start --port 8080
```

- RESTful API 伺服器
- SQLite 後端，輕量部署
- IoC（入侵指標）提交和查詢
- 速率限制
- 自動過期清理

適合：企業私有部署、社群共享威脅情報。

[詳細指南 ->](guides/threat-cloud.md)

---

## 架構概覽

```
                         使用者
                          |
                    [panguard.ai]
                   註冊 / 登入 / 管理訂閱
                          |
                    [panguard login]
                   CLI 本地認證
                          |
    +---------------------+---------------------+
    |                     |                     |
[Panguard Scan]    [Panguard Guard]      [Panguard Report]
 60s 健檢          AI 即時監控           合規報告
    |              |         |                |
    |         [5 AI Agents] [Context Memory]  |
    |              |                          |
    +------[Panguard Trap]------+              |
           蜜罐系統                           |
                |                            |
           [Threat Cloud] ------ 集體威脅情報
```

### 三層 AI 漏斗

Panguard Guard 使用三層架構處理安全事件，在效率和準確度之間取得平衡：

| 層級 | 技術 | 處理比例 | 延遲 | 成本 |
|------|------|---------|------|------|
| Layer 1 | Sigma/YARA 規則引擎 | 90% | < 1ms | 零 |
| Layer 2 | 本地 AI（Ollama） | 7% | < 5s | 零（本機運算） |
| Layer 3 | 雲端 AI | 3% | < 30s | 極低 |

[了解更多 ->](concepts/three-layer-ai.md)

---

## 技術堆疊

| 類別 | 技術 |
|------|------|
| 語言 | TypeScript 5.7（strict mode） |
| 執行環境 | Node.js 20+ |
| 套件管理 | pnpm 10（workspace monorepo） |
| 測試 | Vitest 3（1068 tests） |
| 規則引擎 | Sigma + YARA |
| 威脅情報 | abuse.ch / GreyNoise / AbuseIPDB |
| 認證 | Google OAuth (PKCE) + scrypt 密碼雜湊 |
| i18n | i18next（English + 繁體中文） |
| 加密 | AES-256-GCM |

---

## 訂閱等級

| 功能 | Free | Starter | Pro | Enterprise |
|------|------|---------|-----|-----------|
| 快速掃描 | v | v | v | v |
| 狀態查詢 | v | v | v | v |
| 完整掃描 | - | v | v | v |
| 即時防護（Guard） | - | v | v | v |
| 通知管道（Chat） | - | v | v | v |
| 部署服務 | - | v | v | v |
| AI 深度分析 | - | v | v | v |
| 自動回應 | - | v | v | v |
| 合規報告 | - | - | v | v |
| 蜜罐系統（Trap） | - | - | v | v |
| 威脅情報 API | - | - | - | v |
| 進階調查引擎 | - | - | - | v |
| 優先支援 | - | - | - | v |

管理訂閱：[panguard.ai/pricing](https://panguard.ai/pricing)

---

## 開源授權

Panguard AI 以 [MIT License](https://github.com/openclaw-security/openclaw-security/blob/main/LICENSE) 釋出。
