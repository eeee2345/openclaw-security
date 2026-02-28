# Panguard Guard

> 自動產生 | `./dev-docs/update.sh guard`

## 概述

AI 即時端點防護系統。5 個 AI Agent 協作，三層漏斗架構，7 天學習模式，自動偵測 + 回應。

## 數據

| 項目 | 數據 |
|------|------|
| 套件名 | `@panguard-ai/panguard-guard` |
| 程式碼 | 7814 行 / 32 檔 |
| 測試 | 7 個測試檔 |
| 匯出 | 17 個公開 API |
| 位置 | `packages/panguard-guard/src/` |
| 方案門檻 | Community (基礎封鎖), Solo+ (AI 分析) |

## 五大 Agent

| Agent | 功能 | 觸發條件 |
|-------|------|----------|
| Detect | 事件監控 + 規則匹配 + 三層分流 | 所有事件 |
| Analyze | 9 種調查工具深度推理 | Layer 3 事件 (~3%) |
| Respond | 封鎖 IP / 隔離檔案 / 終止程序 | 確認威脅 |
| Report | 基線更新 + 學習回饋 | 所有結果 |
| Chat | 技術翻譯成人話 | 需通知用戶 |

## 監控來源

| 平台 | 來源 |
|------|------|
| Linux | auditd, syslog, /proc/net, inotify |
| macOS | FSEvents, syslog |
| Windows | ETW, Sysmon, Event Log |
| 網路 | Suricata IDS |
| Kernel | Falco eBPF |

## CLI 指令

```bash
panguard guard start       # 啟動防護
panguard guard stop        # 停止防護 (需確認)
panguard guard status      # 查看狀態
panguard guard install     # 安裝為系統服務
panguard guard uninstall   # 移除系統服務
panguard guard config      # 查看/修改設定
panguard guard generate-key # 產生測試金鑰
```

## 模式

- **Learning Mode** (前 7 天): 建立基線，僅記錄不封鎖
- **Protection Mode**: 自動偵測 + 回應

## 測試檔案

- `agent.test.ts` - Agent 邏輯
- `agent-client.test.ts` - Agent 通訊
- `falco-monitor.test.ts` - Falco 整合
- `license.test.ts` - 授權驗證
- `memory.test.ts` - Context Memory
- `response.test.ts` - 自動回應
- `suricata-monitor.test.ts` - Suricata 整合

## 依賴

- `@panguard-ai/core` - 基礎工具 + AI 適配器
- `@panguard-ai/security-hardening` - 安全庫

## 待辦

- [ ] Windows Sysmon 原生整合
- [ ] Dashboard 即時儀表板
- [ ] 自訂回應規則
