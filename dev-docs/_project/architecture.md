# 架構總覽

> 自動產生 | `./dev-docs/update.sh _project`

## Monorepo 結構

```
panguard-ai/
├── packages/
│   ├── core/              基礎層：AI 適配器、規則引擎、i18n、CLI 工具
│   ├── panguard/          統一 CLI：18 指令、互動選單、auth-guard
│   ├── panguard-scan/     60 秒安全掃描 + PDF 報告
│   ├── panguard-guard/    5 個 AI Agent 即時防護 + 自動回應
│   ├── panguard-trap/     智慧蜜罐 (8 種服務)
│   ├── panguard-chat/     AI 安全副駕 (5 通道通知)
│   ├── panguard-report/   合規報告 (資安法/ISO 27001/SOC 2)
│   ├── panguard-auth/     認證伺服器 (OAuth PKCE, SQLite)
│   ├── panguard-web/      情境式內容引擎
│   ├── threat-cloud/      威脅情報 API (IoC 儲存/信譽引擎)
│   ├── website/           官網 (Next.js 14, 41 頁雙語)
│   └── admin/             管理後台 (HTML/JS, 未完成)
├── security-hardening/    共用安全庫
├── config/                偵測規則 (Sigma/YARA/Falco/Suricata)
├── scripts/               建置/安裝/規則更新腳本
├── docs/                  23 篇使用者文件
├── tests/                 整合測試 + E2E 測試
└── dev-docs/              開發資料 (本資料夾)
```

## 套件相依圖

```
                     ┌──────────┐
                     │   core   │  所有套件的基礎
                     └────┬─────┘
                          │
           ┌──────────────┼──────────────────┐
           │              │                  │
    ┌──────▼──────┐ ┌─────▼──────┐ ┌─────────▼─────────┐
    │ sec-harden  │ │  panguard  │ │   threat-cloud    │
    │ (安全庫)    │ │  (CLI)     │ │   (獨立 API)      │
    └──────┬──────┘ └─────┬──────┘ └───────────────────┘
           │              │
    ┌──────┼──────┐  匯入所有模組
    │      │      │       │
  scan  guard   auth  ┌───┼───┬──────┬──────┬──────┐
                      scan guard trap chat report web
```

## 三層 AI 漏斗

```
事件進入 ─→ [Layer 1: 規則引擎 Sigma+YARA] ─ 90% 處理
                    │
              未匹配 10%
                    │
            [Layer 2: 本地 AI Ollama] ─ 7% 處理
                    │
              需深度分析 3%
                    │
            [Layer 3: 雲端 AI Claude/GPT-4] ─ 3% 處理
```

## Guard 五大 AI Agent

| Agent | 職責 | 處理量 |
|-------|------|--------|
| Detect Agent | 監控系統事件、規則匹配、三層分流 | 100% 事件 |
| Analyze Agent | Layer 3 深度推理 (9 種調查工具) | ~3% 事件 |
| Respond Agent | 根據信心度執行封鎖/隔離/通知 | 確認威脅 |
| Report Agent | 更新基線、學習回饋、合規報告 | 所有結果 |
| Chat Agent | 技術翻譯成人話、後續 Q&A | 所有通知 |

## 資料流

```
用戶系統 ──→ Guard (監控) ──→ Detect (規則匹配)
                                    │
                              ┌─────┼─────┐
                              │     │     │
                           Layer1 Layer2 Layer3
                              │     │     │
                              └─────┼─────┘
                                    │
                              Analyze (深度分析)
                                    │
                              Respond (自動回應)
                                    │
                         ┌──────────┼──────────┐
                         │          │          │
                     Block IP   Quarantine   Notify
                                    │
                              Chat (通知用戶)
                              LINE/Telegram/Slack
```
