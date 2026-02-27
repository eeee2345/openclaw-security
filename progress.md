# 開發進度

## 目前階段：Phase 11 (已完成)

---

### Phase 11：CI/CD 強化 + 公開 README + 全品牌重命名 (完成於 2026-02-25)

#### 已完成

##### README 重整

- [x] `README.md` → `SPEC.md` — 保留 1300 行中文開發規格書供內部參考
- [x] 新建公開 `README.md` — 專業雙語格式（英文+中文）
  - CI/License/Node 版本 Badges
  - What is Panguard AI? 雙語簡介
  - Product Suite 表格（5 產品）
  - Quick Start 安裝指令
  - Architecture 架構說明（三層漏斗：90% rules / 7% local AI / 3% cloud AI）
  - 9 個 Packages 列表與簡述
  - Development 開發指令與目錄結構
  - Tech Stack / Test Coverage / License / Contributing

##### CI/CD 強化 (`.github/workflows/ci.yml`)

- [x] pnpm store cache — 3 個 job (lint/test/build) 全部加入 `actions/cache@v4`
- [x] test job 改用 `pnpm run test:coverage` + `actions/upload-artifact@v4` 上傳 coverage 報告
- [x] build job 加入 `actions/upload-artifact@v4` 上傳 web build artifact (`packages/web/dist/`)
- [x] 修正 step 順序 — pnpm/action-setup 在 actions/setup-node 之前

##### 全品牌重命名：Phalanx AI → Panguard AI

- [x] 產品名稱 — PhalanxScan/ClawScan → Panguard Scan, PhalanxGuard/ClawGuard → Panguard Guard, PhalanxChat/ClawChat → Panguard Chat, PhalanxTrap/ClawTrap → Panguard Trap, PhalanxReport/ClawReport → Panguard Report
- [x] 品牌名稱 — Phalanx AI → Panguard AI, phalanx.ai → panguard.ai, Phalanx Threat Cloud → Panguard Threat Cloud
- [x] npm 套件名 — @panguard-ai/clawscan → @panguard-ai/panguard-scan, @panguard-ai/clawguard → @panguard-ai/panguard-guard, @panguard-ai/clawchat → @panguard-ai/panguard-chat, @panguard-ai/clawtrap → @panguard-ai/panguard-trap, @panguard-ai/clawreport → @panguard-ai/panguard-report, @panguard-ai/phalanx-web → @panguard-ai/panguard-web
- [x] 版本常數 — CLAWSCAN_VERSION → PANGUARD_SCAN_VERSION, CLAWGUARD_VERSION → PANGUARD_GUARD_VERSION, CLAWCHAT_VERSION → PANGUARD_CHAT_VERSION, CLAWTRAP_VERSION → PANGUARD_TRAP_VERSION, CLAWREPORT_VERSION → PANGUARD_REPORT_VERSION, PHALANX_WEB_VERSION → PANGUARD_WEB_VERSION
- [x] 程式碼識別碼 — ClawScan → PanguardScan, ClawGuard → PanguardGuard, ClawChat → PanguardChat, ClawTrap → PanguardTrap, ClawReport → PanguardReport
- [x] 目錄重命名 — packages/clawscan → panguard-scan, clawguard → panguard-guard, clawchat → panguard-chat, clawtrap → panguard-trap, clawreport → panguard-report, phalanx-web → panguard-web
- [x] i18n JSON 檔案重命名 — clawscan.json → panguard-scan.json, clawguard.json → panguard-guard.json, clawchat.json → panguard-chat.json, clawtrap.json → panguard-trap.json, clawreport.json → panguard-report.json, phalanxweb.json → panguardweb.json (en + zh-TW 共 12 檔)
- [x] 配置檔案 — tsconfig.json, vitest.config.ts, pnpm-workspace.yaml, ci.yml 路徑全部更新
- [x] 測試修復 — platform-integrity.test.ts import alias 修正 (hyphen → camelCase)

##### 修復項目

- [x] i18n config.ts — 含 hyphen 的 namespace key 加引號 (`'panguard-scan'`)
- [x] platform-integrity.test.ts — `import * as panguard-scan` 改為 `import * as panguardScan` (JS identifier 不能含 hyphen)

#### 驗證結果

- `pnpm build`: 9 個套件全部編譯通過
- `pnpm test`: 848 個測試全部通過（47 個測試檔案）
- `pnpm typecheck`: 全部通過，無型別錯誤
- `pnpm lint`: 0 errors, 264 warnings（安全插件預期警告）
- Vite build: 285.94 kB JS + 16.61 kB CSS (gzip: 91.39 kB + 3.64 kB)

#### 涉及檔案

| 檔案                                           | 操作                                |
| ---------------------------------------------- | ----------------------------------- |
| `README.md`                                    | git mv → `SPEC.md`                  |
| `README.md`                                    | 新建（公開雙語 README）             |
| `.github/workflows/ci.yml`                     | 修改（cache + coverage + artifact） |
| 全部 285+ 檔案                                 | sed 品牌重命名                      |
| 6 個 package 目錄                              | 目錄重命名                          |
| 12 個 i18n JSON                                | 檔案重命名                          |
| `packages/core/src/i18n/config.ts`             | 修復 quoted keys                    |
| `tests/integration/platform-integrity.test.ts` | 修復 import aliases                 |

#### Checkpoint 標準

- [x] SPEC.md 內容與原 README.md 完全一致
- [x] 新 README.md 專業格式、雙語、含 badges
- [x] CI YAML 含 pnpm cache + coverage upload + web build artifact
- [x] 全品牌 Phalanx AI → Panguard AI 零殘留
- [x] 目錄、檔案名、套件名、常數、字串、註解全部一致
- [x] 848 個測試全部通過，0 errors
- [x] `pnpm build` / `pnpm test` / `pnpm typecheck` / `pnpm lint` 全過

---

### Phase 10：Panguard AI React 前端 (完成於 2026-02-25)

#### 已完成

##### 專案建置 (`packages/web/`)

- [x] Vite 6 + React 19 + TypeScript 5.7 + TailwindCSS 3.4
- [x] PostCSS + Autoprefixer 配置
- [x] Vite 路徑別名 — @panguard-ai/panguard-web → ../panguard-web/src
- [x] TailwindCSS 自訂品牌色彩 — dark (#0a0f1e), card (#1a1f2e), cyan (#00d4ff), purple (#7c3aed)
- [x] 自訂 CSS 元件類別 — btn-primary, btn-secondary, card, card-highlighted, gradient-text, code-block, section-title, grid-bg

##### App Shell + 路由 + i18n

- [x] React Router 7 — 6 個頁面路由 (/, /features, /pricing, /docs, /guide, /about)
- [x] LanguageContext — en/zh-TW 語言切換，t() 輔助函式
- [x] Layout 元件 — Navbar + Outlet + Footer 統一佈局
- [x] Navbar — 品牌 Logo + 頁面連結 + 語言切換 (EN/ZH) + Get Started CTA
- [x] Footer — 品牌名稱 + 標語 + Panguard AI 署名

##### 首頁 (`/`)

- [x] Hero 區塊 — 漸變標題 + 安裝指令 (curl) + 雙 CTA 按鈕
- [x] 「我們保護誰」區塊 — 3 個 PersonaCard (developer/small_business/mid_enterprise)
- [x] 產品套件區塊 — 5 個 FeatureCard (Panguard Scan/Guard/Chat/Trap/Report)
- [x] 統計數據區塊 — 5 模組 / 3 框架 / 8 蜜罐 / 24/7 監控
- [x] 底部 CTA — 引導至設定指南

##### 功能頁 (`/features`)

- [x] 產品功能卡片 — 5 個 FeatureCard 含標籤/標題/說明/highlights
- [x] 實際應用場景 — 3 角色 x 2 場景 = 6 個 Before/After 情境對照
- [x] 痛點展示 — 每角色 4 個雙語痛點卡片

##### 定價頁 (`/pricing`)

- [x] 4 個方案卡片 — Free($0)/Starter($9)/Pro($29)/Business($59)
- [x] Pro 方案突出顯示 (Most Popular)
- [x] 功能比較清單 — included/not-included 雙色標示
- [x] 4 個 FAQ 問答 — 方案切換/免費試用/合規框架/AI 學習期

##### 設定指南 (`/guide`)

- [x] 7 步互動精靈 — welcome → persona_select → threat_assessment → product_recommendation → notification_setup → installation → complete
- [x] StepProgress — 視覺化步驟進度指示器
- [x] 角色選擇 — 3 個選項，點選自動進入下一步
- [x] 環境評估 — 多選切換 (伺服器/Web App/資料庫)
- [x] 產品推薦 — 根據回答動態計算，顯示推薦方案 + 產品卡片
- [x] 通知管道選擇 — LINE/Telegram/Slack/Email
- [x] 安裝指令 — CopyCommand 元件 (含複製按鈕 + 回饋)
- [x] 配置步驟 — 雙語設定步驟 + 預估時間
- [x] 返回/繼續 導覽

##### 文件頁 (`/docs`)

- [x] 快速開始 — 3 步驟 (安裝/初始化/啟動) 含 CopyCommand
- [x] 設定檔範例 — YAML 格式 (monitoring/notifications/scan/report)
- [x] 模組概覽 — 5 個模組說明卡片 (Scan/Guard/Chat/Trap/Report)

##### 關於頁 (`/about`)

- [x] 使命 — 為中小企業提供企業級 AI 資安防護
- [x] 技術 — 4 項技術說明 (基準線學習/多層偵測/適應性通訊/威脅情報網路)
- [x] Panguard AI — 公司介紹 + 平台版本顯示
- [x] 聯繫方式 — Email/GitHub/Location

##### 共用元件

- [x] PersonaCard — 角色名稱 + 描述 + 痛點列表
- [x] FeatureCard — 產品標籤 + 名稱 + 標題 + 說明 + highlights
- [x] PricingCard — 方案名稱/價格/功能列表 + CTA 連結
- [x] CopyCommand — 指令展示 + 複製到剪貼簿 + 「已複製」回饋
- [x] StepProgress — 數字步驟圈 + 連接線 + 當前/完成/待完成 狀態
- [x] Hero — 漸變標題 + 安裝指令 + 雙 CTA
- [x] GuidanceWizard — 7 步互動流程完整實作

#### 驗證結果

- `pnpm build`: 9 個套件全部編譯通過 (含 web Vite build)
- `pnpm test`: 848 個測試全部通過（47 個測試檔案）
- `pnpm typecheck`: 全部通過，無型別錯誤 (含 web tsc --noEmit)
- `pnpm lint`: 0 errors, 264 warnings（安全插件預期警告）
- Vite build: 285.94 kB JS + 16.61 kB CSS (gzip: 91.39 kB + 3.64 kB)

#### 檔案結構

```
packages/web/
  package.json          # React 19, Vite 6, TailwindCSS 3.4
  vite.config.ts        # @vitejs/plugin-react + panguard-web 別名
  tsconfig.json         # noEmit, react-jsx, bundler moduleResolution
  tailwind.config.ts    # 品牌色彩 + 字型
  postcss.config.js     # TailwindCSS + Autoprefixer
  index.html            # Vite 入口
  src/
    main.tsx            # React entry + BrowserRouter + LanguageProvider
    App.tsx             # Routes (6 頁面)
    index.css           # Tailwind directives + 元件類別
    context/
      LanguageContext.tsx  # en/zh-TW 狀態 + t() 輔助函式
    components/
      Layout.tsx        # Navbar + Outlet + Footer
      Navbar.tsx        # 導覽列 + 語言切換
      Footer.tsx        # 品牌 + 署名
      Hero.tsx          # 首頁 Hero
      PersonaCard.tsx   # 角色卡片
      FeatureCard.tsx   # 產品特色卡片
      PricingCard.tsx   # 定價方案卡片
      GuidanceWizard.tsx # 7 步互動精靈
      StepProgress.tsx  # 步驟進度指示器
      CopyCommand.tsx   # 複製指令元件
    pages/
      HomePage.tsx      # 首頁
      FeaturesPage.tsx  # 功能頁
      PricingPage.tsx   # 定價頁
      DocsPage.tsx      # 文件頁
      GuidePage.tsx     # 設定指南頁
      AboutPage.tsx     # 關於頁
```

#### Checkpoint 標準

- [x] 6 個頁面路由全部正確渲染
- [x] 語言切換切換所有內容 (en/zh-TW)
- [x] 引導精靈完整 7 步流程 (角色選擇→環境評估→產品推薦→通知管道→安裝指令→完成)
- [x] 所有內容來自 @panguard-ai/panguard-web（零硬編碼產品資料）
- [x] 暗色主題 cybersecurity 風格
- [x] Vite build 成功 (< 300 kB JS gzip)
- [x] `pnpm build` / `pnpm test` / `pnpm typecheck` / `pnpm lint` 全過

---

### Phase 9：跨套件整合測試 (完成於 2026-02-25)

#### 已完成

##### PanguardScan -> PanguardReport 管線 (`tests/integration/scan-to-report.test.ts`)

- [x] Finding 轉換 — PanguardScan Finding → ComplianceFinding 格式轉換，嚴重度保留，唯一 ID 追蹤
- [x] 完整管線 — 3 大合規框架各自測試：控制項評估、摘要產生、統計、建議、報告產生、JSON 序列化、雙語摘要
- [x] 跨框架一致性 — 發現數量一致、框架特定控制項數量 (TW:10, ISO:12, SOC2:10)、雙語框架名稱、雙語報告標籤
- [x] 嚴重度排序 — sortBySeverity 排序後餵入報告

##### PanguardGuard -> PanguardChat 通知管線 (`tests/integration/guard-to-chat.test.ts`)

- [x] Verdict→Alert 轉換 — malicious→critical, suspicious→medium, benign→info
- [x] 語氣適配 — developer/boss/it_admin x en/zh-TW = 6 組合
- [x] 信心度決策 — autoRespond (>=85%), notifyAndWait (50-84%), logOnly (<50%)
- [x] 告警模板 — 7 種攻擊類型覆蓋、參數插值、雙語摘要
- [x] 授權門控 — Free (無通知), Pro (有通知+自動回應), Enterprise (全功能)
- [x] 基線整合 — 摘要、學習進度、偏離偵測觸發通知
- [x] 無事報平安 — 英文/中文和平報告
- [x] 確認流程 — ConfirmationRequest 格式化、快速回覆按鈕

##### PanguardTrap -> Threat Cloud 情報管線 (`tests/integration/trap-to-intel.test.ts`)

- [x] Session→Intel 轉換 — 蜜罐連線→匿名化情報、認證嘗試計數、MITRE 標記、攻擊類型判定
- [x] 批次情報 — 多 session 批次建構
- [x] Profiling — 技術水準 4 級 (script_kiddie/intermediate/advanced/apt)、意圖分類 8 種、工具偵測
- [x] Trap→合規 — 蜜罐發現餵入合規報告
- [x] 服務配置 — 8 種服務類型完整覆蓋

##### Panguard Web 引導管線 (`tests/integration/web-guidance.test.ts`)

- [x] 角色→方案映射 — developer→starter, small_business→pro, mid_enterprise→business, 無→free
- [x] 產品推薦 — 永遠包含 Panguard Scan, 有角色→Guard+Chat, 有伺服器→Trap, 企業→Report
- [x] 安裝指令 — curl 基礎指令、--plan 方案標記、--notify 通知管道
- [x] 配置步驟 — 雙語、合規步驟 (企業)、蜜罐步驟 (伺服器使用者)、預估時間
- [x] 步驟導覽 — 7 步完整遍歷、前後導覽、選項與角色一致
- [x] 定價方案 — 價格遞增、highlighted 方案一致、雙語內容
- [x] HTML 範本 — Nav/Feature Cards/Pricing Cards/Hero/Head/Footer 一致性

##### 端對端管線 (`tests/integration/e2e-pipeline.test.ts`)

- [x] 版本一致性 — 7 個套件全部 0.1.0
- [x] 完整管線 — Scan→Sort→Convert→Guard(baseline)→Analyze(verdict)→Chat(format per userType)→Report(3 框架)→JSON
- [x] 蜜罐回饋 — Trap Session→Intel→ComplianceFinding→Compliance Report
- [x] 線上引導 — developer 完整設定流程、enterprise 合規設定流程
- [x] 型別相容 — Scan/Report 嚴重度相容、Persona/UserType 相容、5 產品覆蓋、3 框架可用
- [x] 授權門控 — Free/Pro/Enterprise 功能分級
- [x] 雙語一致性 — 告警模板/框架名稱/角色/定價方案/產品特色/合規報告
- [x] 產品數量驗證 — 7 套件、5 產品、4 方案、3 框架、3 角色、7 告警模板、8 蜜罐服務

##### 平台完整性 (`tests/integration/platform-integrity.test.ts`)

- [x] 套件載入 — 7 個套件全部可匯入且有版本常數
- [x] 匯出完整性 — core (discovery/rules/monitor/adapters), panguard-guard (agents/investigation/threat-cloud/dashboard/daemon), panguard-chat (channels/ChatAgent), panguard-trap (services/profiler/engine), panguard-report (frameworks), panguard-web (content data)
- [x] 預設配置 — ActionPolicy/Preferences/WebConfig/ReportConfig/TrapConfig 一致
- [x] 品牌一致 — "Panguard AI" 跨所有範本、"Panguard AI" 署名、產品名稱 Panguard 前綴
- [x] i18n — 初始化無錯誤、語言切換
- [x] 安全覆蓋 — 8 種蜜罐、3 框架、7 告警模板、Sigma 規則

#### 驗證結果

- `pnpm build`: 8 個套件全部編譯通過
- `pnpm test`: 848 個測試全部通過（47 個測試檔案）
- `pnpm typecheck`: 全部通過，無型別錯誤
- `pnpm lint`: 0 errors, 264 warnings（安全插件預期警告 + CLI console.log）

#### 測試覆蓋 (新增 162 個整合測試)

| 測試檔案                   | 測試數 | 涵蓋範圍                                                                                                            |
| -------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------- |
| scan-to-report.test.ts     | 29     | Finding 轉換(3)/完整管線 x3 框架(21)/跨框架一致性(4)/嚴重度排序(1)                                                  |
| guard-to-chat.test.ts      | 27     | Verdict→Alert(3)/語氣適配(6)/信心度決策(3)/告警模板(3)/System Prompt(3)/授權門控(3)/基線(3)/和平報告(2)/確認流程(1) |
| trap-to-intel.test.ts      | 13     | Session→Intel(4)/批次Intel(2)/Profiling(3)/Trap→合規(2)/服務配置(2)                                                 |
| web-guidance.test.ts       | 32     | 角色→方案(4)/產品推薦(5)/安裝指令(3)/配置步驟(4)/導覽(4)/定價(3)/HTML範本(6)/頁面(3)                                |
| e2e-pipeline.test.ts       | 24     | 版本(1)/完整管線(1)/蜜罐回饋(1)/線上引導(2)/型別相容(4)/授權門控(1)/雙語(6)/產品數量(8)                             |
| platform-integrity.test.ts | 37     | 套件載入(7)/匯出完整性(14)/預設配置(5)/品牌一致(3)/i18n(2)/安全覆蓋(6)                                              |

#### Checkpoint 標準

- [x] PanguardScan→PanguardReport 管線完整測試（3 框架 x 7 項 = 21 測試）
- [x] PanguardGuard→PanguardChat 通知管線完整測試（語氣適配 + 授權門控）
- [x] PanguardTrap→ThreatCloud 情報管線完整測試（Profiling + 合規回饋）
- [x] Panguard Web 引導→推薦管線完整測試
- [x] 端對端管線測試（掃描→偵測→分析→回應→報告→通知）
- [x] 平台完整性驗證（套件載入 + 匯出完整性 + 品牌一致性）
- [x] 848 個測試全部通過，0 errors
- [x] `pnpm build` / `pnpm test` / `pnpm typecheck` / `pnpm lint` 全過

---

### Phase 8：Panguard Web 官網引擎 (完成於 2026-02-25)

#### 已完成

##### 型別定義 (`packages/panguard-web/src/types.ts`)

- [x] 完整型別定義 — WebLanguage, PersonaType (3 種: developer/small_business/mid_enterprise), PersonaProfile (含 scenarios), ScenarioStory (場景化文案), PricingPlan (4 種), PlanFeature, PricingPlanDetails, PageId (6 頁), PageMeta, GuidanceStepType (7 步), GuidanceStep, GuidanceOption, GuidanceAnswers, GuidanceResult, WebConfig
- [x] 預設配置 — DEFAULT_WEB_CONFIG (zh-TW/https://panguard.ai/Panguard AI)

##### 場景化文案 (`packages/panguard-web/src/content/`)

- [x] 3 組目標用戶角色 (Personas)
  - developer: 個人開發者/AI 開發者 (推薦 starter, 2 場景: SSH 暴力破解 + AI Code 漏洞)
  - small_business: 小型企業 5-50 人 (推薦 pro, 2 場景: 勒索軟體 + 弱密碼)
  - mid_enterprise: 中型企業 50-500 人 (推薦 business, 2 場景: 合規稽核 + 橫向移動)
- [x] 每個角色含雙語痛點 (4 個) + 場景故事 (before/after/notification)
- [x] 所有通知文案用人話（無 Sigma/YARA/IOC/MITRE 術語 — 符合 README 語言指南）
- [x] 4 個定價方案 — Free($0)/Starter($9)/Pro($29/endpoint)/Business($59/endpoint)
- [x] 每個方案含雙語名稱/標語/功能列表 (9 項)，Pro 方案 highlighted

##### 頁面定義 (`packages/panguard-web/src/pages/`)

- [x] 6 個頁面 — home(/), features(/features), pricing(/pricing), docs(/docs), guide(/guide), about(/about)
- [x] 5 個產品特色卡片 — Panguard Scan/Panguard Guard/Panguard Chat/Panguard Trap/Panguard Report
- [x] 每個產品含雙語 headline/description/highlights (5-6 項)
- [x] getPage, getPageTitle (雙語), getNavItems (排除 guide), getProductFeature

##### 線上引導精靈 (`packages/panguard-web/src/guidance/`)

- [x] 7 步驟引導流程 — welcome → persona_select → threat_assessment → product_recommendation → notification_setup → installation → complete
- [x] persona_select: 3 個選項 (developer/small_business/mid_enterprise)
- [x] threat_assessment: 3 個選項 (servers/web apps/databases)
- [x] notification_setup: 4 個選項 (LINE/Telegram/Slack/Email)
- [x] 推薦引擎 — generateGuidanceResult() 根據角色推薦方案/產品/安裝指令/配置步驟
- [x] 智慧推薦 — developer→starter+Trap, small_business→pro, mid_enterprise→business+Report
- [x] 安裝指令產生 — curl + --plan + --notify 參數組合
- [x] 配置步驟產生 — 雙語，含合規/蜜罐特定步驟
- [x] 步驟導覽 — getNextStep/getPreviousStep/getTotalSteps

##### HTML 範本引擎 (`packages/panguard-web/src/templates/`)

- [x] generateHead — HTML5 + meta + OG + Twitter Card + canonical URL
- [x] generateNav — 品牌名稱 + 頁面連結
- [x] generateHero — 標語 + 安裝指令 (curl) + CTA 按鈕
- [x] generateFeatureCard — 產品標籤 + 標題 + 說明 + highlights 列表
- [x] generatePricingCard — 方案名稱/價格/功能 (included/not-included)，Pro highlighted
- [x] generateFooter — 品牌 + Panguard AI 署名

##### i18n 擴充

- [x] 新增 `panguardweb` 命名空間 — en/zh-TW 各 ~30 翻譯鍵
- [x] 涵蓋 brand._, hero._, nav._, persona._, pricing._, guidance._, footer.\*

##### 匯出整合

- [x] `src/index.ts` — 完整 barrel exports（types, content, pages, guidance, templates）

#### 驗證結果

- `pnpm build`: 8 個套件全部編譯通過
- `pnpm test`: 686 個測試全部通過（41 個測試檔案）
- `pnpm typecheck`: 全部通過，無型別錯誤
- `pnpm lint`: 0 errors, 253 warnings（安全插件預期警告 + CLI console.log）

#### 測試覆蓋 (新增 112 個測試)

| 測試檔案          | 測試數 | 涵蓋範圍                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ----------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| types.test.ts     | 9      | DEFAULT_WEB_CONFIG (4 項)/WebLanguage (2 種)/PersonaType (3 種)/PricingPlan (4 種)/PageId (6 頁)/GuidanceStepType (7 步)/型別安全 (GuidanceAnswers/WebConfig)                                                                                                                                                                                                                                                                                                       |
| content.test.ts   | 22     | getAllPersonas (3 人)/getPersona (developer/small_business/mid_enterprise/unknown)/painPoints 雙語/scenarios 完整性/bilingual names/人話通知 (無 jargon)/getAllPricingPlans (4 方案)/getPricingPlan (free/starter/pro/business/unknown)/bilingual names+taglines/features/ascending prices/getRecommendedPlan                                                                                                                                                       |
| pages.test.ts     | 24     | 6 頁面 (home/features/pricing/docs/guide/about)/getPageTitle (en/zh-TW/unknown)/bilingual titles/unique paths/getNavItems (5 項, 排除 guide)/5 產品特色/getProductFeature/bilingual content/highlights                                                                                                                                                                                                                                                              |
| guidance.test.ts  | 35     | 7 步驟/sequential numbers/bilingual titles/getGuidanceStep (welcome/persona_select/notification_setup/unknown)/step navigation (next/previous/full-traversal)/persona options (3 種)/generateGuidanceResult (developer→starter/small_business→pro/mid_enterprise→business/no-persona→free/always-scan/guard+chat/trap-for-server/report-for-enterprise/install-cmd/free-cmd/notify-flag/config-steps/compliance-step/honeypot-step/setup-time/zh-TW-steps/en-steps) |
| templates.test.ts | 22     | generateHead (en/zh-TW/meta/OG/canonical/twitter)/generateNav (brand/links/zh-TW)/generateHero (en/zh-TW/install-cmd/cta)/generateFeatureCard (en/zh-TW/highlights/all-products)/generatePricingCard (basic/highlighted/not-highlighted/features/included+not-included/all-plans/zh-TW)/generateFooter (brand/builtby/zh-TW)                                                                                                                                        |

#### Checkpoint 標準

- [x] 3 組目標用戶角色完整定義（痛點 + 場景故事 + 推薦方案）
- [x] 場景化通知文案全部用人話（零 Sigma/YARA/IOC/MITRE 術語）
- [x] 4 個定價方案（Free/Starter/Pro/Business）含完整功能比較
- [x] 7 步線上引導精靈（選角色→評估→推薦→安裝→完成）
- [x] 智慧推薦引擎（根據角色/環境/通知偏好自動推薦方案+產品+安裝指令）
- [x] HTML 範本引擎（SEO meta + OG + 雙語切換）
- [x] `pnpm build` / `pnpm test` / `pnpm typecheck` / `pnpm lint` 全過

---

### Phase 7：PanguardReport 產品開發 (完成於 2026-02-25)

#### 已完成

##### 型別定義 (`packages/panguard-report/src/types.ts`)

- [x] 完整型別定義 — ComplianceFramework (3 種: tw_cyber_security_act/iso27001/soc2), ControlStatus (4 種), ComplianceControl, EvaluatedControl, ComplianceFinding (5 severity + 4 source), ReportType (5 種), ReportFormat, ReportLanguage, ReportMetadata, ComplianceReportData, ExecutiveSummary, ComplianceStatistics (含 trend), ReportRecommendation (4 priority), ReportConfig
- [x] 預設配置 — DEFAULT_REPORT_CONFIG (zh-TW/tw_cyber_security_act/json/./reports)

##### 合規框架 (`packages/panguard-report/src/frameworks/`)

- [x] 資通安全管理法 — 10 個控制項 (TWCS-4.1~4.10): 存取控制/系統保護/網路安全/加密管理/多因子驗證/安全監控/事件應變/資產管理/弱點修補/安全稽核
- [x] ISO/IEC 27001:2022 — 12 個控制項 (Annex A): A.5.1 資訊安全政策/A.5.15 存取控制/A.5.23 雲端安全/A.6.1 篩選/A.7.1 實體安全/A.8.1 端點安全/A.8.5 認證/A.8.8 弱點管理/A.8.15 日誌/A.8.16 監控/A.8.20 網路安全/A.8.24 加密
- [x] SOC 2 — 10 個控制項 (Trust Services Criteria): CC6.1 存取控制/CC6.2 憑證管理/CC6.3 角色授權/CC6.6 防護措施/CC6.7 傳輸限制/CC6.8 弱點管理/CC7.1 偵測/CC7.2 監控/CC7.3 評估/CC8.1 變更管理
- [x] 框架註冊表 — getFrameworkControls(), getFrameworkName() (雙語), getSupportedFrameworks()

##### 合規映射引擎 (`packages/panguard-report/src/mapper/`)

- [x] evaluateControls — 自動映射 findings → controls (透過 relatedCategories 比對)，判定 pass/fail/partial/not_applicable
- [x] determineControlStatus — critical/high→fail, medium→partial, low/info/none→pass
- [x] buildEvidence — 證據收集（通過時標記無顯著發現，失敗時列出所有相關發現）
- [x] buildRemediation — 修復建議（含 URGENT 前綴標記）
- [x] generateExecutiveSummary — 加權分數計算 (partial=0.5), 主要風險/主要成果 (雙語)
- [x] generateStatistics — byStatus/byCategory/findingsBySeverity/compliancePercentage
- [x] generateRecommendations — 失敗→immediate/high, 部分→medium, 含預估工作量

##### 報告產生器 (`packages/panguard-report/src/generator/`)

- [x] generateComplianceReport — 完整報告產生（框架控制項→評估→摘要→統計→建議），唯一 reportId (RPT-YYYYMM-NNNN)
- [x] reportToJSON — JSON 序列化（Date→ISO string），pretty-print 2 spaces
- [x] generateSummaryText — 人類可讀摘要文字 (雙語)，含標題/期間/摘要/風險/建議/合規率

##### 報告範本 (`packages/panguard-report/src/templates/`)

- [x] getSectionLabels — 完整報告區段標籤 (24 個欄位: title/executiveSummary/controlDetails 等)，中英雙語
- [x] getStatusLabel — 4 種狀態標籤雙語 (pass→通過, fail→未通過, partial→部分符合, not_applicable→不適用)
- [x] getSeverityLabel — 5 種嚴重度標籤雙語 (critical→嚴重, high→高, medium→中, low→低, info→資訊)
- [x] getPriorityLabel — 4 種優先級標籤雙語 (immediate→立即, high→高, medium→中, low→低)
- [x] getFrameworkDescription — 3 個框架完整描述 (fullName/shortDescription/scope)，中英雙語

##### CLI (`packages/panguard-report/src/cli/`)

- [x] 完整 CLI — generate, list-frameworks, validate, summary, config, help
- [x] 參數解析 — --framework, --language, --format, --output-dir, --org, --input, --verbose
- [x] 雙語輸出 — 所有 CLI 訊息中英並列

##### i18n 擴充

- [x] 新增 `panguard-report` 命名空間 — en/zh-TW 各 ~30 翻譯鍵
- [x] 涵蓋 report._, framework._, summary._, control._, recommendation._, statistics._, cli.\*

##### 匯出整合

- [x] `src/index.ts` — 完整 barrel exports（types, frameworks, mapper, generator, templates, CLI）

#### 驗證結果

- `pnpm build`: 7 個套件全部編譯通過
- `pnpm test`: 574 個測試全部通過（36 個測試檔案）
- `pnpm typecheck`: 全部通過，無型別錯誤
- `pnpm lint`: 0 errors, 250 warnings（安全插件預期警告 + CLI console.log）

#### 測試覆蓋 (新增 146 個測試)

| 測試檔案           | 測試數 | 涵蓋範圍                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| types.test.ts      | 19     | DEFAULT_REPORT_CONFIG (6 項)/ComplianceFramework (3 種)/ControlStatus (4 種)/ReportType (5 種)/ReportFormat/ReportLanguage/severity (5 種)/source (4 種)/型別安全 (Control/Finding/Config/Metadata/Summary/Recommendation)                                                                                                                                               |
| frameworks.test.ts | 26     | getSupportedFrameworks/getFrameworkControls (3 框架+unknown)/getFrameworkName (3 框架x2 語言+unknown)/TW控制項 (數量/雙語/relatedCategories/唯一ID)/ISO控制項 (數量/雙語/唯一ID)/SOC2控制項 (數量/雙語/唯一ID)/跨框架一致性                                                                                                                                              |
| mapper.test.ts     | 32     | evaluateControls (pass/fail-critical/fail-high/partial-medium/pass-low/pass-info/category-matching/evidence/remediation/multi-control)/generateExecutiveSummary (counts/100%/failure-score/risks/zh-TW/achievements/empty)/generateStatistics (byStatus/bySeverity/byCategory/percentage/empty)/generateRecommendations (fail/partial/pass/sort/zh-TW/controlIds/effort) |
| generator.test.ts  | 28     | generateComplianceReport (3 框架/summary/statistics/findings/recommendations/exclude-recs/orgName/period/unique-ids/version/empty)/reportToJSON (serialize/valid-JSON/ISO-dates/pretty-print)/generateSummaryText (en/zh-TW/reportId/orgName/percentage/recommendations/framework/separators)                                                                            |
| templates.test.ts  | 25     | getSectionLabels (en/zh-TW/all-fields)/getStatusLabel (en/zh-TW/unknown)/getSeverityLabel (en/zh-TW/unknown)/getPriorityLabel (en/zh-TW/unknown)/getFrameworkDescription (3 框架x2 語言/scope)                                                                                                                                                                           |
| cli.test.ts        | 16     | parseCliArgs (help/generate/list-frameworks/validate/summary/config/framework/language/format/outputDir/org/input/verbose/-v/multiple)/buildConfigFromOptions (defaults/framework/language/format/outputDir/orgName)/formatConfig/formatFrameworkList/getHelpText (name/commands/options/examples/bilingual)                                                             |

#### Checkpoint 標準

- [x] 支援 3 大合規框架（資通安全管理法 + ISO 27001 + SOC 2）
- [x] 自動映射安全發現到合規控制項
- [x] 加權分數計算（pass=1.0, partial=0.5, fail=0.0）
- [x] 完整雙語報告產生（中英文）
- [x] 32 個合規控制項完整定義（TW:10 + ISO:12 + SOC2:10）
- [x] 報告範本完整（24 個區段標籤 + 狀態/嚴重度/優先級標籤 + 框架描述）
- [x] `pnpm build` / `pnpm test` / `pnpm typecheck` / `pnpm lint` 全過

---

### Phase 6：PanguardTrap 產品開發 (完成於 2026-02-25)

#### 已完成

##### 型別定義 (`packages/panguard-trap/src/types.ts`)

- [x] 完整型別定義 — TrapServiceType (8 種: ssh/http/ftp/smb/mysql/rdp/telnet/redis), TrapServiceStatus, TrapEngineStatus, TrapServiceConfig, TrapEvent, TrapSession, CredentialAttempt, AttackerSkillLevel, AttackerIntent (8 種), AttackerProfile, TrapIntelligence, TrapConfig, TrapService interface, TrapStatistics
- [x] 預設配置 — DEFAULT_SERVICE_CONFIGS (8 種服務各自的 port/banner/maxConnections/timeout), DEFAULT_TRAP_CONFIG (SSH+HTTP 預設啟用)

##### 假服務模擬器 (`packages/panguard-trap/src/services/`)

- [x] BaseTrapService — TCP 伺服器生命週期管理、Session 建立/結束/事件記錄、認證追蹤、MITRE 技術標記
- [x] SSHTrapService — SSH banner 模擬、認證暴力破解記錄、假檔案系統回應、13 種可疑指令偵測 (wget/chmod/crontab/base64/nc 等)、自動 MITRE 標記 (T1110/T1078/T1059/T1105/T1222/T1003 等)
- [x] HTTPTrapService — Apache 偽裝、11 種攻擊模式偵測 (SQLi/XSS/LFI/RCE/目錄遍歷 等)、6 個假頁面 (登入/admin/robots.txt/wp-login/.env)、表單認證提取
- [x] GenericTrapService — 6 種協定處理器：FTP (USER/PASS/LIST/PWD)、Telnet (login/shell)、MySQL (SHOW/SELECT/SQL commands)、Redis (PING/INFO/CONFIG/KEYS/EVAL)、SMB (share listing)、RDP (NLA credential prompt)

##### 攻擊者分析引擎 (`packages/panguard-trap/src/profiler/`)

- [x] 技術水準估計 — 4 級 (script_kiddie/intermediate/advanced/apt)，基於 14 種工具簽章 + 12 種進階指令模式 + 指令多樣性 + MITRE 技術數量
- [x] 意圖分類 — 8 種意圖 (reconnaissance/credential_harvesting/ransomware_deployment/cryptomining/data_theft/botnet_recruitment/lateral_movement/unknown)
- [x] 工具偵測 — 14 種工具簽章 (nmap/Metasploit/Hydra/sqlmap/Nikto/Burp Suite/Cobalt Strike/Mimikatz/BloodHound 等)
- [x] AttackerProfiler — IP→Profile 映射、多 session 累積分析、技術水準只升不降、認證模式追蹤

##### 蜜罐情報 (`packages/panguard-trap/src/intel/`)

- [x] buildTrapIntel — 匿名化情報建構（過濾私有 IP、保留公網 IP）
- [x] buildBatchIntel — 批次情報建構
- [x] generateIntelSummary — 情報摘要統計（攻擊類型分布、來源 IP 排名、服務分布）
- [x] 攻擊類型自動判定 — brute_force/exploit_attempt/cryptomining/webshell_upload/data_destruction/malware_download/reconnaissance/web_attack

##### TrapEngine (`packages/panguard-trap/src/trap-engine.ts`)

- [x] 中央協調器 — 管理所有蜜罐服務啟停
- [x] 整合 AttackerProfiler — 每個完成連線自動分析
- [x] 整合 Threat Cloud — 自動產生匿名化情報
- [x] 統計引擎 — 連線/IP/認證/指令/技術分布統計
- [x] 記憶體管理 — maxSessionsInMemory 限制

##### CLI (`packages/panguard-trap/src/cli/`)

- [x] 完整 CLI — start, stop, status, deploy, profiles, intel, config, help
- [x] 參數解析 — --services, --port, --data-dir, --no-cloud, --verbose
- [x] 雙語輸出 — 所有 CLI 訊息中英並列

##### i18n 擴充

- [x] 新增 `panguard-trap` 命名空間 — en/zh-TW 各 ~30 翻譯鍵
- [x] 涵蓋 engine._, service._, profiler._, intel._, cli.\*

##### 匯出整合

- [x] `src/index.ts` — 完整 barrel exports（types, services, profiler, intel, engine, CLI）

#### 驗證結果

- `pnpm build`: 7 個套件全部編譯通過
- `pnpm test`: 428 個測試全部通過（30 個測試檔案）
- `pnpm typecheck`: 全部通過，無型別錯誤
- `pnpm lint`: 0 errors, 222 warnings（安全插件預期警告 + CLI console.log）

#### 測試覆蓋 (新增 99 個測試)

| 測試檔案         | 測試數 | 涵蓋範圍                                                                                                     |
| ---------------- | ------ | ------------------------------------------------------------------------------------------------------------ |
| types.test.ts    | 15     | DEFAULT_SERVICE_CONFIGS (8 種)/DEFAULT_TRAP_CONFIG (啟用/停用/配置)/型別安全                                 |
| profiler.test.ts | 26     | 技術水準估計 (6 級)/意圖分類 (7 種)/工具偵測 (5 種)/AttackerProfiler (建立/更新/多 IP/查詢/排名/清除/不降級) |
| intel.test.ts    | 13     | buildTrapIntel (建構/認證/私有 IP 過濾/攻擊類型)/buildBatchIntel/generateIntelSummary                        |
| services.test.ts | 14     | createTrapService factory (8 種)/SSH init/HTTP init/Generic init (6 種)/unsupported type                     |
| engine.test.ts   | 13     | 啟停/統計/profiler/intel/sessions/服務列表/技術分布                                                          |
| cli.test.ts      | 18     | parseCliArgs (9 種)/buildConfigFromOptions (4 種)/formatStatistics/getHelpText (4 種)                        |

#### Checkpoint 標準

- [x] 8 種假服務模擬器完整實作（SSH/HTTP/FTP/Telnet/MySQL/Redis/SMB/RDP）
- [x] SSH 蜜罐捕獲暴力破解 + 登入後指令 + MITRE 技術標記
- [x] HTTP 蜜罐捕獲 SQLi/XSS/LFI/RCE/目錄遍歷
- [x] 攻擊者 Profiling：技術水準 4 級 + 意圖 8 種 + 工具 14 種
- [x] 匿名化情報：過濾私有 IP、保留攻擊模式、回饋 Threat Cloud
- [x] `pnpm build` / `pnpm test` / `pnpm typecheck` / `pnpm lint` 全過

---

### Phase 5：PanguardChat 產品開發 (完成於 2026-02-25)

#### 已完成

##### 型別定義 (`packages/panguard-chat/src/types.ts`)

- [x] 完整型別定義 — UserType, ChannelType, MessageLanguage, UserProfile, NotificationPreferences, FormattedMessage, ThreatAlert, SummaryReport, LearningProgress, ConfirmationRequest/Response, FollowUpContext, ConversationTurn, MessagingChannel interface, ChannelResult, WebhookConfig, ChatConfig, per-channel configs (LINE/Telegram/Slack/Email/Webhook)

##### Chat Agent (`packages/panguard-chat/src/agent/`)

- [x] System Prompt 建構器 — buildSystemPrompt(userType, language)，USER_TYPE_INSTRUCTIONS (developer/boss/it_admin)
- [x] 訊息格式化器 — formatAlert (依 userType 適配語氣), formatSummary (日報/週報), formatLearningProgress, formatConfirmation (帶快速回覆), formatPeacefulReport
- [x] ChatAgent 核心類別 — 多管道管理、告警發送、確認流程 (approve/reject/expire)、追問 Q&A (<2000 tokens)
- [x] 追問回覆引擎 — 基於規則的 pattern matching，24h context 過期，最大 10 輪對話
- [x] 語氣適配 — developer (CVE/MITRE/CLI)、boss (無術語/類比/影響)、it_admin (技術+合規)

##### 雙向通訊管道 (`packages/panguard-chat/src/channels/`)

- [x] LINE Bot — Flex Message 建構、severity 色彩 header、快速回覆按鈕、processWebhookEvent() 雙向處理
- [x] Telegram Bot — Inline Keyboard、callback query 處理、processUpdate() 雙向處理、multipart 檔案上傳
- [x] Slack Web API — Block Kit blocks + action buttons、processEvent() (message/block_actions)、verifySignature() 簽名驗證
- [x] Email SMTP — 原生 node:net + node:tls 零外部依賴、HTML 品牌化信件模板、MIME multipart 附件
- [x] Enterprise Webhook — bearer_token / hmac_signature / mTLS 三種認證、HMAC-SHA256 簽章、processCallback() 雙向處理

##### 告警模板 (`packages/panguard-chat/src/templates/`)

- [x] 7 種內建攻擊模板 — ssh_brute_force, ransomware_detected, sql_injection, suspicious_outbound, encoded_command, privilege_escalation, data_exfiltration
- [x] 每種含雙語 humanSummary、analogy、recommendedAction
- [x] 參數插值 — getHumanSummary() 支援 {{count}}, {{ip}}, {{user}} 等動態參數

##### 安裝引導 (`packages/panguard-chat/src/onboarding/`)

- [x] 3 步驟設定流程 — 管道選擇、用戶類型、語言
- [x] 管道專屬配置步驟 — LINE(2), Telegram(2), Slack(3), Email(6), Webhook(3)
- [x] buildConfigFromAnswers() — 從用戶回答建立 ChatConfig
- [x] getWelcomeMessage() — 雙語歡迎訊息 + 學習期說明
- [x] DEFAULT_PREFERENCES — 所有通知預設啟用

##### CLI (`packages/panguard-chat/src/cli/`)

- [x] 完整 CLI — setup, test, status, config, help 命令
- [x] 非互動模式 — --channel, --user-type, --lang 選項
- [x] 雙語輸出 — 所有 CLI 訊息中英並列

##### i18n 擴充

- [x] 新增 `panguard-chat` 命名空間 — en/zh-TW 各 ~40 翻譯鍵
- [x] 涵蓋 agent._, channel._, format._, onboarding._, template._, cli._

##### 匯出整合

- [x] `src/index.ts` — 完整 barrel exports（types, ChatAgent, formatters, channels, templates, onboarding, CLI）

#### 驗證結果

- `pnpm build`: 7 個套件全部編譯通過
- `pnpm test`: 329 個測試全部通過（24 個測試檔案）
- `pnpm typecheck`: 全部通過，無型別錯誤
- `pnpm lint`: 0 errors, 188 warnings（安全插件預期警告 + CLI console.log）

#### 測試覆蓋 (新增 108 個測試)

| 測試檔案           | 測試數 | 涵蓋範圍                                                                                                                                                           |
| ------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| formatter.test.ts  | 27     | alert formatting per userType/severity/quickReplies/summary/learning/confirmation/peaceful                                                                         |
| chat-agent.test.ts | 24     | init/sendAlert/sendSummary/sendLearningUpdate/sendPeacefulReport/confirm-approve-reject-expire/follow-up(what/serious/actions/recommend/no-context)/boss-no-jargon |
| prompts.test.ts    | 11     | userType instructions per language/system prompt building                                                                                                          |
| templates.test.ts  | 10     | template count/field validation/lookup/human summary with params                                                                                                   |
| onboarding.test.ts | 17     | setup steps/channel config steps/config building/welcome messages/default preferences                                                                              |
| channels.test.ts   | 19     | channel init/reply handlers/error handling/webhook event/Telegram update/Slack event processing                                                                    |

#### Checkpoint 標準

- [x] 能透過 LINE/Telegram 發送威脅告警（用人話）
- [x] 開發者收到的通知包含技術細節；老闆收到的只有結果和建議
- [x] 用戶追問「這是什麼？」能在 <2000 tokens 內回答
- [x] 週報能正確產出並推送
- [x] 用戶可以透過聊天介面確認或駁回 Respond Agent 的建議
- [x] 5 個雙向通訊管道完整實作（LINE/Telegram/Slack/Email/Webhook）
- [x] 安裝引導流程完整（3 步驟 + 管道專屬配置）
- [x] 7 種攻擊告警模板雙語支援
- [x] `pnpm build` / `pnpm test` / `pnpm typecheck` / `pnpm lint` 全過

---

### Phase 4：PanguardGuard 產品開發 (完成於 2026-02-25)

#### 已完成

##### 型別定義 + 配置系統 (`packages/panguard-guard/src/`)

- [x] 完整型別定義 — EnvironmentBaseline, ProcessPattern, ConnectionPattern, LoginPattern, PortPattern, DetectionResult, ThreatVerdict, Evidence, ResponseAction, ActionPolicy, LicenseInfo, GuardConfig, AnalyzeLLM
- [x] 配置系統 — loadConfig() 從 YAML/JSON 讀取，DEFAULT_DATA_DIR, 預設值

##### i18n 擴充

- [x] 新增 `panguard-guard` 命名空間 — en/zh-TW 各 ~30 翻譯鍵

##### Context Memory (`packages/panguard-guard/src/memory/`)

- [x] Baseline 模組 — createEmptyBaseline(), checkDeviation(), updateBaseline()
- [x] 偏離偵測 — 新程序 (confidence 70), 新網路目的地 (confidence 60), 新登入模式, 新 Port
- [x] Learning 模組 — isLearningComplete(), getLearningProgress(), getRemainingDays(), switchToProtectionMode(), getBaselineSummary()
- [x] 持久化 — loadBaseline(), saveBaseline() JSON 檔案儲存

##### Multi-Agent 架構 (`packages/panguard-guard/src/agent/`)

- [x] DetectAgent — ruleEngine.match() + checkThreatIntel() 威脅情報比對
- [x] AnalyzeAgent — 加權信心分數 (rule 0.4, baseline 0.3, AI 0.3)，證據收集，支援可選 LLM
- [x] RespondAgent — 平台特定回應 (blockIP: iptables/netsh/pf, killProcess, disableAccount, isolateFile)
- [x] ReportAgent — JSONL 事件記錄 + 學習期基線更新 + 匿名化數據產生

##### Dynamic Reasoning 調查引擎 (`packages/panguard-guard/src/investigation/`)

- [x] InvestigationEngine — 8 個調查工具，動態推理，MAX_STEPS=8 防無限迴圈
- [x] 調查工具 — checkIPHistory, checkUserPrivilege, checkTimeAnomaly, checkGeoLocation, checkRelatedEvents, checkProcessTree, checkFileReputation, checkNetworkPattern
- [x] 動態 follow-up — 根據中間結果追加調查步驟（高風險 IP → 追加地理位置+關聯事件）

##### 通知系統 (`packages/panguard-guard/src/notify/`)

- [x] LINE Notify — HTTPS POST 到 LINE Notify API
- [x] Telegram Bot — Telegram Bot API + Markdown 格式
- [x] Slack Webhook — Slack Incoming Webhooks + 色彩附件
- [x] Email — 原生 SMTP 實作（node:net + node:tls，零外部依賴）
- [x] 統一發送器 — sendNotifications() 透過 Promise.allSettled 平行發送所有已配置管道

##### 集體威脅智慧 (`packages/panguard-guard/src/threat-cloud/`)

- [x] ThreatCloudClient — HTTP 上傳、規則拉取、本地 JSON 快取、離線佇列
- [x] 匿名化 — 去除內網 IP、用戶名、主機名，保留攻擊類型和來源 IP
- [x] 快取 — 本地 JSON 檔案快取，flushQueue() 離線回傳

##### GuardEngine 主引擎 (`packages/panguard-guard/src/guard-engine.ts`)

- [x] 中央協調器 — 連接 MonitorEngine → DetectAgent → AnalyzeAgent → RespondAgent → ReportAgent
- [x] 整合 InvestigationEngine — 非 benign 事件觸發深度調查
- [x] 通知整合 — 自動發送通知給所有已配置管道
- [x] Threat Cloud 整合 — 自動上傳匿名化威脅數據
- [x] Dashboard 整合 — WebSocket 即時推送事件和狀態
- [x] 學習期自動轉換 — 7 天學習期結束自動切換到防護模式
- [x] 基線定期保存 — 每 5 分鐘自動保存基線

##### Daemon/Service (`packages/panguard-guard/src/daemon/`)

- [x] PidFile 管理 — 建立/讀取/移除/isRunning() 檢查
- [x] Watchdog — 定期健康檢查，自動重啟崩潰引擎
- [x] 跨平台服務安裝 — macOS launchd plist / Linux systemd unit / Windows sc.exe
- [x] 服務解除安裝 — 跨平台移除

##### Web Dashboard (`packages/panguard-guard/src/dashboard/`)

- [x] HTTP 伺服器 — 內建 node:http，零外部依賴
- [x] WebSocket — 原生 WebSocket 實作（node:crypto handshake + frame 解析）
- [x] 暗色主題 HTML — 狀態卡片、事件時間軸、威脅地圖、設定頁
- [x] 語言切換 — EN/ZH 即時切換
- [x] REST API — /api/status, /api/events, /api/threat-map, /api/verdicts, /api/config

##### 授權系統 (`packages/panguard-guard/src/license/`)

- [x] License Key 格式 — CLAW-(FREE|PRO|ENT)-XXXX-XXXX-XXXX + checksum
- [x] 三級授權 — Free (基本監控), Pro (AI 分析+自動回應+通知), Enterprise (全功能+1000端點)
- [x] Feature Gating — hasFeature() 功能門檢查
- [x] 測試金鑰生成 — generateTestLicenseKey()

##### 一鍵安裝 (`packages/panguard-guard/src/install/`)

- [x] Bash 腳本 — macOS/Linux 自動安裝 (detect OS/ARCH → download → systemd/launchd → start)
- [x] PowerShell 腳本 — Windows 自動安裝

##### CLI (`packages/panguard-guard/src/cli/`)

- [x] 完整 CLI — start, stop, status, install, uninstall, config, generate-key, install-script, help
- [x] 雙語輸出 — 所有 CLI 訊息中英並列

##### 匯出整合

- [x] `src/index.ts` — 完整 barrel exports（types, config, engine, agents, memory, investigation, notify, threat-cloud, dashboard, license, daemon, install, cli）

#### 驗證結果

- `pnpm build`: 7 個套件全部編譯通過
- `pnpm test`: 213 個測試全部通過（18 個測試檔案）
- `pnpm typecheck`: 全部通過，無型別錯誤
- `pnpm lint`: 0 errors, 145 warnings（安全插件預期警告 + CLI console.log）

#### 測試覆蓋 (新增 38 個測試)

| 測試檔案        | 測試數 | 涵蓋範圍                                                                                                                     |
| --------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------- |
| memory.test.ts  | 17     | 基線建立/偏離偵測(程序/網路)/基線更新/學習進度/完成判斷/模式切換/摘要                                                        |
| agent.test.ts   | 12     | DetectAgent(無比對/規則比對/計數)/AnalyzeAgent(無AI/嚴重度/威脅情報/計數)/RespondAgent(學習模式/自動回應/通知/記錄/模式切換) |
| license.test.ts | 9      | 空金鑰/空白金鑰/無效格式/Free生成驗證/Pro生成驗證/Enterprise生成驗證/功能檢查/Enterprise功能/錯誤checksum                    |

#### Checkpoint 標準

- [x] Detect → Analyze → Respond → Report 管線完整運作
- [x] Confidence >= 85% 自動處理，< 85% 通知用戶，< 50% 僅記錄
- [x] LINE/Telegram/Slack/Email 通知模組完整
- [x] 學習期 7 天自動轉換防護模式
- [x] Dashboard 即時更新（WebSocket）
- [x] Daemon 跨平台服務安裝（systemd/launchd/Windows Service）
- [x] 授權系統 Free/Pro/Enterprise 分級
- [x] 集體威脅智慧匿名化上傳 + 快取
- [x] Dynamic Reasoning 調查引擎 8 個工具
- [x] `pnpm build` / `pnpm test` / `pnpm typecheck` / `pnpm lint` 全過

---

### Phase 3：PanguardScan 產品開發 (完成於 2026-02-25)

#### 已完成

##### 掃描器模組 (`packages/panguard-scan/src/scanners/`)

- [x] 型別定義 — ScanConfig, Finding, ScanResult, SEVERITY_ORDER, sortBySeverity
- [x] 環境偵察整合器 — `discover()` 呼叫全部 core 偵察函式，組裝 DiscoveryResult
- [x] 密碼策略檢查 — macOS pwpolicy / Linux PAM / Windows net accounts
- [x] 開放埠檢查 — 危險埠清單比對 (Telnet 23, FTP 21, NetBIOS 135-139, RDP 3389 等)
- [x] SSL 憑證檢查 — tls.connect() 檢查 HTTPS 憑證過期，5 秒超時
- [x] 排程任務檢查 — launchctl/crontab/schtasks 可疑排程偵測
- [x] 共享資料夾檢查 — sharing/samba/net share everyone 存取偵測
- [x] 掃描編排器 — `runScan()` 整合所有掃描，quick/full 模式，增強風險評分

##### 報告模組 (`packages/panguard-scan/src/report/`)

- [x] 樣式定義 — 色彩 (primary/accent/severity)、字型、A4 版面常數
- [x] 合規對照表 — 台灣《資通安全管理法》10 條重點條目 (4.1-4.10)，雙語
- [x] PDF 產生器 — PDFKit 報告產生，CJK 系統字型偵測
- [x] 封面頁 — 品牌名稱、掃描日期、主機名、風險分數色碼圓圈
- [x] 執行摘要 — 風險等級、各嚴重度統計、系統概覽
- [x] 發現列表 — 逐條發現：嚴重度色碼 + 標題 + 描述 + 修復建議
- [x] 修復建議 — 按優先級分組 (Immediate/High/Medium/Low)，去重排列
- [x] 合規對照 — 條目 vs 符合/不符合/部分符合表格

##### CLI 介面 (`packages/panguard-scan/src/cli/`)

- [x] Commander 進入點 — `panguard-scan --quick --output <path> --lang <en|zh-TW> --verbose`
- [x] 指令邏輯 — `executeScan()` 含進度顯示、風險摘要、PDF 產生

##### i18n 擴充

- [x] 新增 `panguard-scan` 命名空間 — en/zh-TW 各 ~50 翻譯鍵

##### 匯出整合

- [x] `src/index.ts` — 匯出 PANGUARD_SCAN_VERSION, runScan, generatePdfReport, 型別

#### 驗證結果

- `pnpm build`: 7 個套件全部編譯通過
- `pnpm test`: 175 個測試全部通過（15 個測試檔案）
- `pnpm typecheck`: 全部通過，無型別錯誤
- `pnpm lint`: 0 errors, 81 warnings（安全插件預期警告）

#### 測試覆蓋 (新增 46 個測試)

| 測試檔案         | 測試數 | 涵蓋範圍                                                                               |
| ---------------- | ------ | -------------------------------------------------------------------------------------- |
| scanners.test.ts | 19     | sortBySeverity/SEVERITY_ORDER/checkUnnecessaryPorts/合規對照表/mapFindingsToCompliance |
| cli.test.ts      | 12     | 版本常數/ScanConfig 型別/SEVERITY_ORDER/sortBySeverity 排序/模組匯出                   |
| report.test.ts   | 15     | COLORS/FONTS/LAYOUT/severityColor/合規條目/mapFindings/報告模組匯出                    |

#### Checkpoint 標準

- [x] macOS 上執行，60 秒內產出 PDF 報告
- [x] 報告內容完整（封面 + 摘要 + 發現 + 修復 + 合規）
- [x] 中英文版本正確（panguard-scan 命名空間 ~50 鍵）
- [x] 風險評分與發現的弱點一致（增強評分 = 基礎 + 額外發現加權）
- [x] `pnpm build` / `pnpm test` / `pnpm typecheck` / `pnpm lint` 全過

---

### Phase 2：核心引擎開發 (完成於 2026-02-25)

#### 已完成

##### 2A: 環境偵察引擎 (`packages/core/src/discovery/`)

- [x] OS 偵測器 — 跨平台 (darwin/linux/win32)，使用 `execFile` 避免 shell injection
- [x] 網路掃描器 — IP/Port/Connection 掃描 (lsof/ss/netstat)，30+ port-to-service 映射
- [x] 服務偵測器 — launchctl/systemctl/sc query 服務列舉
- [x] 安全工具偵測 — 18 種已知安全工具資料庫 (Defender, Wazuh, CrowdStrike 等)
- [x] 防火牆檢查 — socketfilterfw/iptables/ufw/netsh 跨平台狀態
- [x] 使用者稽核 — dscl/passwd/net user 帳號列舉
- [x] 風險評分 — 7 因子加權 (0-100)，含 5 級風險等級

##### 2B: AI/LLM 統一介面 (`packages/core/src/ai/`)

- [x] 工廠模式 `createLLM()` — 支援 Ollama/Claude/OpenAI
- [x] Ollama Provider — HTTP fetch localhost:11434，CJK token 估算
- [x] Claude Provider — 動態 import `@anthropic-ai/sdk`，優雅降級
- [x] OpenAI Provider — 動態 import `openai`，優雅降級
- [x] 雙語 Prompt 模板 — 事件分類、威脅分析、報告生成 (MITRE ATT&CK)
- [x] Response Parser — JSON 提取 + fallback 解析
- [x] Token Tracker — 多模型計費估算

##### 2C: Sigma 規則引擎 (`packages/core/src/rules/`)

- [x] Sigma YAML 解析器 — js-yaml 解析 + 必要欄位驗證
- [x] 事件比對器 — wildcard, |contains, |startswith, |endswith, |re 修飾符
- [x] 條件解析器 — 遞迴下降解析 AND/OR/NOT 含括號
- [x] 規則載入器 — 目錄載入 + fs.watch 熱載入 (300ms debounce)
- [x] RuleEngine 類別 — loadRules/addRule/removeRule/match/reload/destroy
- [x] 5 條內建 Sigma 規則 — 暴力破解、可疑程序、異常網路、權限提升、檔案完整性

##### 2D: 系統監控引擎 (`packages/core/src/monitor/`)

- [x] MonitorEngine — extends EventEmitter，統一 start/stop/on('event')
- [x] 日誌監控 — macOS `log stream` / Linux `tail -F` / Windows `wevtutil`
- [x] 網路監控 — 連線差異偵測，定期輪詢
- [x] 程序監控 — 程序生命週期追蹤
- [x] 檔案完整性監控 — SHA-256 hash 比對
- [x] 威脅情報 — 10 筆內建惡意 IP/CIDR，自動比對
- [x] 事件標準化器 — 統一轉為 SecurityEvent 格式

##### 2E: 資安工具對接器 (`packages/core/src/adapters/`)

- [x] 抽象基底 — 共用嚴重等級映射和 SecurityEvent 轉換
- [x] Windows Defender Adapter — PowerShell/MpCmdRun，非 Windows 優雅降級
- [x] Wazuh Adapter — REST API + JWT 認證，level 0-15 映射
- [x] Syslog Adapter — RFC 5424 UDP 接收器，10K 緩衝
- [x] Adapter Registry — 根據 discovery 結果自動啟用對應 adapter

##### i18n 擴充

- [x] 新增 `discovery` 命名空間 — 覆蓋所有 Phase 2 模組翻譯 (zh-TW + en)

#### 驗證結果

- `pnpm build`: 7 個套件全部編譯通過
- `pnpm test`: 129 個測試全部通過（12 個測試檔案）
- `pnpm typecheck`: 全部通過，無型別錯誤
- `pnpm lint`: 0 errors, 68 warnings（安全插件預期警告）

#### 測試覆蓋 (新增 44 個測試)

| 測試檔案          | 測試數 | 涵蓋範圍                                         |
| ----------------- | ------ | ------------------------------------------------ |
| discovery.test.ts | 12     | OS/網路/服務/安全工具/防火牆/使用者/風險評分     |
| rules.test.ts     | 10     | YAML 解析/事件比對/wildcard/AND-OR/規則載入/引擎 |
| monitor.test.ts   | 8      | 事件標準化/程序/檔案 hash/威脅情報/引擎啟停      |
| ai.test.ts        | 9      | 工廠/prompt 模板/response parser/token tracker   |
| adapters.test.ts  | 5      | Registry/Defender 降級/Wazuh 降級/Syslog 解析    |

---

### Phase 1：Panguard Fork - 安全強化 (完成於 2026-02-25)

#### 已完成

- [x] 建立 `@panguard-ai/security-hardening` 套件結構 — 2026-02-25
- [x] 定義安全相關型別系統（SecurityPolicy, CsrfToken, AuditEvent 等）— 2026-02-25
- [x] WebSocket 安全模組（CVE-2026-25253 修復）— 2026-02-25
- [x] 憑證安全儲存 — 2026-02-25
- [x] 沙盒系統 — 2026-02-25
- [x] 權限系統 — 2026-02-25
- [x] 稽核日誌 — 2026-02-25
- [x] 漏洞掃描器 — 2026-02-25
- [x] 撰寫 75 個安全測試（7 個測試檔案）— 2026-02-25

#### 驗證結果

- `pnpm build`: 7 個套件全部編譯通過
- `pnpm test`: 85 個測試全部通過（10 i18n + 75 安全測試）
- `pnpm typecheck`: 全部通過，無型別錯誤
- `pnpm lint`: 0 errors, 33 warnings（安全插件預期警告）

---

### Phase 0：專案初始化 (完成於 2025-02-25)

#### 已完成

- [x] 初始化 pnpm monorepo 專案結構
- [x] 設定 TypeScript 配置（tsconfig.json，strict mode）
- [x] 設定 ESLint + Prettier
- [x] 設定 vitest 測試框架
- [x] 建立 i18n 基礎架構（中/英文）
- [x] 建立 `packages/core/` 共用模組骨架
- [x] 建立 `progress.md` 進度追蹤文件
- [x] 寫基礎 CI 腳本（lint + test + build）
- [x] 建立所有產品套件骨架（panguard-scan, panguard-guard, panguard-chat, panguard-trap, panguard-report）

---

### 下一步

1. npm 發布 — @panguard-ai/\* 套件發布到 npm registry
2. 官網部署 — Vercel/Netlify 部署 packages/web
3. E2E 測試 — Playwright/Cypress 端到端測試
4. 外部 API 整合 — LINE/Telegram/Slack/Ollama 實際連線測試
5. Docker 化 — Dockerfile + docker-compose 完整部署方案
