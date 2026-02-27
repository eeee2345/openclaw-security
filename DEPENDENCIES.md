# Panguard AI — 開源資安工具參考清單

> 按照 README.md 的 Phase 排列。只列「你真的會用到的」，不列好看但用不上的。

---

## Phase 1: Panguard 安全加固

| 工具                            | GitHub                                         | 用途                                                                            | 怎麼用在我們的專案                                                                                |
| ------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| **centminmod/explain-panguard** | https://github.com/centminmod/explain-panguard | 已有人做過 Panguard 安全稽核文件，含 5 個 AI 模型的交叉分析                     | **直接參考**。裡面有完整的安全漏洞清單、加固步驟、Cloudflare WAF 規則。省掉你自己做安全稽核的時間 |
| **keytar** (npm)                | https://github.com/nicedoc/keytar              | 跨平台系統憑證管理（Win Credential Manager / macOS Keychain / Linux libsecret） | 取代 Panguard 的明文憑證儲存。`npm install keytar` 直接用                                         |

---

## Phase 2A: 環境偵察引擎

| 工具                        | GitHub                                              | 用途                                                                         | 怎麼用                                                                                                                                           |
| --------------------------- | --------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **osquery**                 | https://github.com/osquery/osquery                  | Facebook 出品，用 SQL 查詢端點系統資訊（程序、Port、使用者、服務、登錄檔等） | 核心依賴。你的 Discovery 引擎不用自己寫 OS 查詢，直接 `SELECT * FROM listening_ports` 就拿到所有開放 Port。跨平台（Win/Lin/Mac），已經是業界標準 |
| **systeminformation** (npm) | https://github.com/sebhildebrandt/systeminformation | Node.js 系統資訊收集庫，零依賴                                               | 如果不想安裝 osquery 的二進位檔，用這個做輕量偵察。`npm install systeminformation` → `si.osInfo()`, `si.networkConnections()`, `si.services()`   |
| **Lynis**                   | https://github.com/CISOfy/lynis                     | Linux/macOS 安全稽核工具（HIPAA/ISO27001/PCI DSS 合規）                      | 參考它的檢查項目和評分邏輯來設計你的風險評分演算法。已經有 800+ 檢查項目，不用自己發明                                                           |

---

## Phase 2B: AI/LLM 整合

| 工具                        | GitHub                                                                                                   | 用途                           | 怎麼用                                                                                                   |
| --------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------- |
| **@anthropic-ai/sdk** (npm) | https://github.com/anthropics/anthropic-sdk-typescript                                                   | Claude API 官方 TypeScript SDK | 你的 Claude provider 用這個                                                                              |
| **ollama-js** (npm)         | https://github.com/ollama/ollama-js                                                                      | Ollama 官方 JS/TS 客戶端       | 你的本地 LLM provider 用這個                                                                             |
| **Wazuh + LLM POC**         | https://documentation.wazuh.com/current/proof-of-concept-guide/leveraging-llms-for-alert-enrichment.html | Wazuh 官方 LLM 告警增強指南    | **參考架構**。他們已經做了「YARA 偵測 → LLM 分析 → 結構化輸出」的完整 POC，跟你的 PanguardGuard 幾乎一樣 |

---

## Phase 2C: 規則引擎（最重要的部分）

| 工具                   | GitHub                                  | 用途                                                 | 怎麼用                                                                                                                                                    |
| ---------------------- | --------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **⭐ Tigma**           | https://github.com/binalyze/tigma       | **TypeScript 原生的 Sigma Rule 引擎**（解析 + 匹配） | **核心依賴**。這就是你要的 Sigma Rule 解析器。Binalyze 出品（DFIR 公司），支援完整 Sigma 語法，轉成 AST 可以用 JSON Scanner 匹配。不用自己寫 Sigma parser |
| **⭐ SigmaHQ/sigma**   | https://github.com/SigmaHQ/sigma        | 全球最大 Sigma 規則倉庫（3000+ 條）                  | **規則來源**。直接拿他們的規則，按分類載入。涵蓋 Windows Event Log、Syslog、Process Creation 等幾乎所有場景                                               |
| **YARA**               | https://github.com/VirusTotal/yara      | 惡意程式特徵比對工具                                 | 用於 PanguardScan 的檔案掃描和 PanguardGuard 的 FIM（檔案完整性監控）                                                                                     |
| **Nextron/YARA-Forge** | https://github.com/YARAHQ/yara-forge    | 自動編譯優化的 YARA 規則集                           | 不用自己收集 YARA 規則，他們已經做好去重、驗證、優化的規則包                                                                                              |
| **awesome-yara**       | https://github.com/InQuest/awesome-yara | YARA 規則和工具的完整清單                            | 參考用。找特定威脅的 YARA 規則                                                                                                                            |

---

## Phase 2D: 系統監控引擎

| 工具                                 | GitHub                                           | 用途                                                       | 怎麼用                                                                                                                                         |
| ------------------------------------ | ------------------------------------------------ | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| **⭐ Wazuh**                         | https://github.com/wazuh/wazuh                   | 開源 XDR/SIEM 平台（端點監控 + 日誌分析 + FIM + 漏洞偵測） | **兩種用法**：(1) 如果客戶已裝 Wazuh → 你的 Adapter 對接它的 API 讀取告警；(2) 參考它的偵測規則設計你自己的規則。它的 C 解碼器架構是業界最快的 |
| **Velociraptor**                     | https://github.com/Velocidex/velociraptor        | 端點監控和數位鑑識（VQL 查詢語言）                         | 參考它的端點查詢方式。特別是 Windows artifacts 收集的部分                                                                                      |
| **⭐ SwiftOnSecurity/sysmon-config** | https://github.com/SwiftOnSecurity/sysmon-config | 高品質 Windows Sysmon 設定範本                             | **直接參考**。它定義了 Windows 上該監控什麼事件，是整個資安社群的標準配置。你的 Windows 監控模組按這個設定來決定要看哪些 Event ID              |
| **sysmon-modular**                   | https://github.com/olafhartong/sysmon-modular    | 模組化 Sysmon 設定 + MITRE ATT&CK 對照                     | 比上面那個更細，每個模組對應一個 ATT&CK 技術。你的偵測規則可以參考這個來做 ATT&CK 標記                                                         |
| **DeepBlueCLI**                      | https://github.com/sans-blue-team/DeepBlueCLI    | PowerShell 威脅偵測（Windows Event Log 分析）              | **參考它的偵測邏輯**。它用 PowerShell 分析 Windows 事件日誌找威脅，你可以把它的偵測規則翻譯成 TypeScript                                       |
| **SilkETW**                          | https://github.com/mandiant/SilkETW              | Mandiant 的 Windows ETW 遙測工具                           | 參考它的 ETW（Event Tracing for Windows）使用方式。你的 Windows 監控最終會需要 ETW                                                             |

---

## Phase 3: PanguardScan（資安健檢）

| 工具                            | GitHub                                | 用途                     | 怎麼用                                                                      |
| ------------------------------- | ------------------------------------- | ------------------------ | --------------------------------------------------------------------------- |
| **windows-hardening-checklist** | 搜尋 "CIS benchmark windows" 相關資源 | Windows 安全基線檢查清單 | 你的掃描檢查項目按 CIS Benchmark 設計。這樣報告出來的結果客戶和稽核員都認得 |
| **pdfkit** (npm)                | https://github.com/foliojs/pdfkit     | Node.js PDF 生成庫       | 用來產生 PanguardScan 的 PDF 掃描報告                                       |
| **Lynis**（同上）               | https://github.com/CISOfy/lynis       | Linux 安全稽核           | 參考它的掃描邏輯。在 Linux 上你可以直接包裝 Lynis 的結果                    |

---

## Phase 4: PanguardGuard（即時監控）

| 工具          | GitHub                                    | 用途                      | 怎麼用                                                                                      |
| ------------- | ----------------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------- |
| **OSSEC**     | https://github.com/ossec/ossec-hids       | 老牌 HIDS（主機入侵偵測） | 參考它的 Active Response 架構（事件 → 規則匹配 → 自動回應）。Wazuh 就是從 OSSEC fork 出來的 |
| **Bluespawn** | https://github.com/ION28/BLUESPAWN        | Windows 主動防禦 EDR      | 參考它的 Windows 偵測模組（Sysmon 監控、Event Log 分析、程序監控、Registry 監控）           |
| **OpenEDR**   | https://github.com/ComodoSecurity/openedr | Comodo 開源 EDR           | 參考完整的 EDR 架構。但它是 C++ 寫的，看架構不看程式碼                                      |

---

## Phase 6: PanguardTrap（蜜罐）

| 工具                     | GitHub                                       | 用途                                        | 怎麼用                                                                        |
| ------------------------ | -------------------------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------- |
| **⭐ awesome-honeypots** | https://github.com/paralax/awesome-honeypots | 蜜罐工具大全                                | 所有蜜罐工具的清單。重點看以下幾個                                            |
| **Cowrie**               | https://github.com/cowrie/cowrie             | 中/高互動 SSH/Telnet 蜜罐                   | 你的假 SSH 服務參考它。它能記錄攻擊者的完整 session（輸入的指令、上傳的檔案） |
| **HFish**                | https://github.com/hacklcx/HFish             | 跨平台蜜罐（SSH/FTP/HTTP/RDP/SMB/MySQL 等） | **最接近你要做的東西**。Go 寫的，支援多協議。參考它的假服務設計               |
| **Dionaea**              | https://github.com/DinoTools/dionaea         | 低互動蜜罐（SMB/HTTP/FTP/MSSQL/SIP）        | 參考它的協議模擬方式                                                          |

---

## 通用：威脅情報 & MITRE ATT&CK

| 工具                     | GitHub                           | 用途                        | 怎麼用                                                                  |
| ------------------------ | -------------------------------- | --------------------------- | ----------------------------------------------------------------------- |
| **MITRE ATT&CK**         | https://github.com/mitre/cti     | ATT&CK 框架的 STIX 格式資料 | 你的所有偵測規則和事件報告都要對應 ATT&CK 技術編號。用這個資料做對照    |
| **MITRE CALDERA**        | https://github.com/mitre/caldera | 自動化紅隊模擬              | 測試用。模擬真實攻擊來驗證你的偵測規則有效                              |
| **AbuseIPDB**            | https://www.abuseipdb.com/api    | 惡意 IP 資料庫 API          | PanguardGuard 的網路監控用這個查惡意 IP。免費帳號每天 1000 次查詢       |
| **abuse.ch / Threatfox** | https://threatfox.abuse.ch/api/  | IOC（入侵指標）資料庫       | 免費的 IP、domain、hash IOC 來源                                        |
| **OSSEM**                | https://github.com/OTRF/OSSEM    | 安全事件元資料標準          | 參考它的事件欄位命名規範。你的 SecurityEvent 型別按這個設計，跟業界相容 |

---

## 最重要的 5 個（一定要用）

如果只能選 5 個：

1. **⭐ Tigma** — TypeScript Sigma Rule 引擎。不用自己寫規則解析器。
2. **⭐ SigmaHQ/sigma** — 3000+ 條現成偵測規則。不用自己寫偵測邏輯。
3. **⭐ systeminformation** — Node.js 系統資訊收集。Discovery 引擎的基礎。
4. **⭐ SwiftOnSecurity/sysmon-config** — Windows 該監控什麼事件的標準答案。
5. **⭐ centminmod/explain-panguard** — Panguard 安全稽核文件。Phase 1 直接用。

---

## README.md 要不要加這些？

**不要直接加進 README**。README 已經夠長了（779 行）。
建議做法：把這份清單存為 `DEPENDENCIES.md`，在 README 的技術選型表格下加一行：

```markdown
> 完整的開源工具參考清單見 [DEPENDENCIES.md](./DEPENDENCIES.md)
```

這樣 Claude Code 在開發到對應 Phase 時，會去讀 DEPENDENCIES.md 找到該用什麼。
