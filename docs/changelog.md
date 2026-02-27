# Changelog / 版本記錄

> 所有顯著變更都記錄在這裡。

---

## v0.7.0 (2025-02-25)

### Phase 15-16: Sigma 增強 + osquery 整合

**Sigma 規則引擎增強**

- 聚合表達式支援：`1 of them`、`all of them`、`1 of sel*`、`all of filter*`
- 新增比對修飾符：`|cidr`（IP 範圍匹配）、`|gt`/`|gte`/`|lt`/`|lte`（數值比較）
- 新增編碼修飾符：`|base64`、`|base64offset`、`|utf8`、`|wide`
- 括號群組條件支援：`(sel_a OR sel_b) AND NOT filter`

**osquery 整合**

- 新增 `OsqueryProvider`，透過 SQL 查詢系統狀態
- 支援程序、port、使用者、網路介面、核心模組查詢
- osquery 未安裝時自動降級到 shell 指令方式

---

## v0.6.0 (2025-02-25)

### Phase 13-14: 品牌 CLI + 安全分數 + 成就系統

**品牌 CLI 升級**

- 全新 CLI 渲染模組，24-bit ANSI 顏色匹配品牌標準色
- Sage Green #8B9A8E 主色調
- 品牌 Logo 格式：`PANGUARD [▣] AI`
- 進度條、表格、狀態面板、Shield ASCII Art
- 零外部依賴（無 chalk/ora/ink）

**安全分數引擎**

- 8 因子加權評分（0-100）
- A-F 等級對照
- 趨勢追蹤（improving/declining/stable）

**成就系統**

- 12 個成就徽章
- 自動解鎖 + 通知

---

## v0.5.0 (2025-02-25)

### Phase 10-12: 自動回應 + YARA + 威脅情報 Feed

**自動回應引擎**

- IP 封鎖（macOS pfctl / Linux iptables / Windows netsh）
- 檔案隔離（SHA-256 追蹤）
- 程序終止
- 信心度機制（>90% 自動 / 70-90% 確認 / <70% 通知）

**YARA 掃描器**

- 原生 YARA 引擎支援
- Regex fallback（未安裝 YARA 時）
- 檔案和記憶體掃描

**威脅情報 Feed 管理**

- ThreatFox Feed（abuse.ch）
- URLhaus Feed（abuse.ch）
- Feodo Tracker Feed（abuse.ch）
- GreyNoise 即時查詢
- AbuseIPDB 即時查詢
- 自動更新 + 本地快取

---

## v0.4.0 (2025-02-24)

### Phase 7-9: Chat 通知 + Trap 蜜罐 + Report 合規

**Panguard Chat**

- 5 個通知管道：LINE、Telegram、Slack、Email、Webhook
- 3 種使用者角色格式：developer、boss、it_admin
- 互動式設定精靈
- 雙語告警模板

**Panguard Trap**

- 8 種蜜罐服務：SSH、HTTP、FTP、SMB、MySQL、RDP、Telnet、Redis
- 攻擊者側寫：技術等級分類 + 攻擊意圖分析
- 憑證收集與指令記錄
- 威脅情報報告

**Panguard Report**

- 台灣資通安全管理法（10 控制項）
- ISO 27001（12 控制項）
- SOC 2（10 控制項）
- JSON 和 PDF 格式

---

## v0.3.0 (2025-02-24)

### Phase 5-6: Guard AI + Investigation

**Panguard Guard**

- 5 個 AI Agent 管線：Detect、Analyze、Respond、Report、Investigation
- 7 天學習期 + 自動切換保護模式
- 42 條 Sigma 規則
- Dashboard WebSocket 伺服器
- 系統服務安裝（macOS/Linux/Windows）
- PID 管理 + Watchdog

**Threat Cloud**

- RESTful API 伺服器
- SQLite 後端
- IoC 提交/查詢/批量查詢
- API Key 認證

---

## v0.2.0 (2025-02-23)

### Phase 3-4: Scan + PDF 報告

**Panguard Scan**

- 系統環境偵察
- 密碼政策檢查
- Port 掃描 + 危險 port 偵測
- SSL 憑證驗證
- 排程任務稽核
- 共享資料夾安全
- 風險評分 0-100（A-F 等級）
- PDF 報告產生

---

## v0.1.0 (2025-02-23)

### Phase 1-2: 核心基礎

**@panguard-ai/core**

- TypeScript monorepo 架構
- i18n 雙語支援（en + zh-TW）
- Sigma 規則引擎
- 系統偵察引擎（OS、網路、服務、安全工具）
- 4 個監控器：Log、Network、Process、File
- 3 個適配器：Windows Defender、Wazuh、Syslog
- 威脅情報查詢
- AES-256-GCM 加密

**基礎建設**

- pnpm workspace monorepo
- Vitest 測試框架
- ESLint + eslint-plugin-security
- Prettier 程式碼格式化
- GitHub Actions CI/CD
