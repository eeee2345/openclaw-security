# Panguard Guard / AI 即時監控指南 `[STARTER]`

> 5 個 AI Agent 24/7 守護你的系統。學習你的環境，偵測異常，自動回應威脅。
>
> 啟動和停止 Guard 需要 **Starter** 以上方案。狀態查詢和設定檢視為 Free。

---

## 快速開始

```bash
# 登入（如果還沒有）
panguard login

# 啟動 Guard（需要 Starter）
panguard guard start

# 查看狀態（Free）
panguard guard status

# 停止 Guard
panguard guard stop
```

---

## 運作模式

Guard 有兩個模式，自動切換：

### 學習模式（Day 1-7）

安裝後的前 7 天，Guard 觀察系統正常行為：

```
  Mode:       Learning (Day 3/7)
  Monitoring: processes, network, files
  Baseline:   42% complete
```

- 不會產生告警（避免誤報）
- 記錄程序、網路、檔案的正常模式
- 每日透過 Chat 發送學習進度摘要

### 保護模式（Day 8+）

7 天後自動切換：

```
  Mode:       Protection
  Score:      85/100 (Grade: A)
  Threats:    0 active
  Blocked:    12 IPs today
```

- 偏離基線的行為觸發告警
- 依信心度自動或手動回應
- 即時透過 Chat 通知

詳見 [7 天學習期](../concepts/learning-mode.md)。

---

## 5 個 AI Agent

Guard 的核心是 5 個串聯的 AI Agent，形成完整的偵測-分析-回應管線：

```
  事件流入
     |
     v
  [Detect Agent]     偵測：規則比對 + 異常偵測
     |
     v
  [Analyze Agent]    分析：三層 AI 漏斗深度分析
     |
     v
  [Respond Agent]    回應：自動或手動執行防禦動作
     |
     v
  [Report Agent]     報告：更新基線 + 產生報告
     |
     v
  [Investigation]    調查：攻擊鏈還原 + 根因分析
```

### Detect Agent

監控系統事件，用規則引擎即時比對：

- Sigma 規則匹配（42 條內建規則）
- YARA 檔案掃描
- 行為基線偏離偵測
- 威脅情報關聯

### Analyze Agent

對 Detect 標記的可疑事件進行深度分析：

- Layer 1：規則引擎（90%，< 1ms）
- Layer 2：本地 AI / Ollama（7%，< 5s）
- Layer 3：雲端 AI（3%，< 30s）

詳見 [三層 AI 架構](../concepts/three-layer-ai.md)。

### Respond Agent

根據分析結果執行回應動作：

| 動作 | 說明 | 平台支援 |
|------|------|---------|
| IP 封鎖 | 封鎖惡意 IP | macOS (pfctl)、Linux (iptables)、Windows (netsh) |
| 檔案隔離 | 隔離可疑檔案 + SHA-256 記錄 | 全平台 |
| 程序終止 | 終止惡意程序 | 全平台 |

**信心度機制**：

| 信心度 | 動作 |
|--------|------|
| > 90% | 自動執行，事後通知 |
| 70-90% | 透過 Chat 詢問你確認後執行 |
| < 70% | 僅通知，不執行 |

### Report Agent

更新系統基線，產生安全報告：

- 更新行為基線（持續學習）
- 記錄所有事件和回應動作
- 產生每日/每週安全摘要
- 更新安全分數

### Investigation Agent（Enterprise）

攻擊事件的深度調查：

- 攻擊鏈還原（時間軸）
- 根因分析
- 影響範圍評估
- 修復建議

---

## 查看狀態

```bash
panguard guard status
```

```
  ╔══════════════════════════════════════╗
  ║       PANGUARD [▣] AI               ║
  ║       Guard Engine                  ║
  ╚══════════════════════════════════════╝

  ── Guard Status ───────────────────────

  Status:     Running
  Mode:       Protection
  PID:        12345
  Uptime:     14d 6h 33m
  Score:      85/100 (Grade: A)
  Threats:    0 active
  Events:     134,567 processed
  Rules:      42 Sigma + 15 YARA
  Feeds:      5 active

  ── Recent Activity ────────────────────

  [14:23] Blocked IP 203.0.113.50 (ThreatFox match)
  [12:01] Score updated: 83 -> 85 (improving)
  [08:45] Daily summary sent via LINE
```

---

## 規則引擎

### Sigma 規則

Guard 內建 42 條 Sigma 規則，覆蓋常見攻擊模式。你也可以自訂規則：

```yaml
# 自訂規則範例：偵測大量失敗 SSH 登入
title: SSH Brute Force Attempt
logsource:
  category: authentication
  product: any
detection:
  selection:
    event_type: login_failed
    service: ssh
  condition: selection
level: high
```

將 `.yml` 檔案放入 Guard 的規則目錄，Guard 會自動載入。支援即時監控目錄變更（hot reload）。

詳見 [Sigma 規則撰寫指南](../reference/sigma-rules.md)。

### YARA 規則

用於偵測惡意檔案：

```yara
rule WebShell {
  strings:
    $php = "<?php eval(" nocase
    $asp = "<%execute(" nocase
  condition:
    any of them
}
```

詳見 [YARA 規則撰寫指南](../reference/yara-rules.md)。

---

## 威脅情報

Guard 自動整合 5 個威脅情報來源：

- abuse.ch ThreatFox（IoC 資料庫）
- abuse.ch URLhaus（惡意 URL）
- abuse.ch Feodo Tracker（C2 伺服器）
- GreyNoise（IP 聲譽）
- AbuseIPDB（IP 檢舉）

詳見 [威脅情報](../concepts/threat-intelligence.md)。

---

## 安全分數與成就

Guard 持續計算 0-100 安全分數，並追蹤 12 個成就徽章。

詳見 [安全分數系統](../concepts/security-score.md)。

---

## Internal Monitoring (WebSocket)

Guard 引擎內建 WebSocket 監控介面，供進階除錯使用：

- 預設 port：3100
- 即時事件流
- 安全分數視覺化
- WebSocket 安全（CSRF + Origin 驗證）

此為內部工具，非面向使用者的介面。主要操作請使用 CLI (`panguard guard status`)。

---

## 訂閱等級

Guard 功能依訂閱等級分級：

| 功能 | Free | Starter | Pro | Enterprise |
|------|------|---------|-----|-----------|
| 狀態查詢 | v | v | v | v |
| 基本偵測 | - | v | v | v |
| Sigma 規則 | - | v | v | v |
| Chat 通知 | - | v | v | v |
| AI 深度分析 | - | v | v | v |
| 自動回應 | - | v | v | v |
| YARA 掃描 | - | v | v | v |
| Threat Cloud | - | - | - | v |
| Investigation | - | - | - | v |

管理訂閱：[panguard.ai/pricing](https://panguard.ai/pricing)

---

## 系統服務

將 Guard 安裝為開機自動啟動的系統服務：

```bash
panguard guard install
```

詳見 [系統服務安裝指南](system-service.md)。

---

## CLI 選項

```
panguard guard <command> [options]

Commands:
  start              啟動 Guard 引擎（Starter）
  stop               停止 Guard 引擎（Starter）
  status             顯示狀態（Free）
  install            安裝為系統服務（Starter）
  uninstall          移除系統服務（Starter）
  config             顯示目前設定（Free）
  help               顯示說明

Options:
  --data-dir <path>      資料目錄（預設：~/.panguard-guard）
```

完整 CLI 參考見 [CLI 指令參考](../reference/cli.md)。

---

## osquery 整合

如果你的系統安裝了 [osquery](https://osquery.io)，Guard 會自動偵測並使用它來取得更精確的系統資訊：

- 程序列表（含完整路徑和命令列）
- 監聽 port（含對應程序）
- 使用者列表和登入紀錄
- 系統資訊和核心模組
- 網路介面

如果 osquery 未安裝，Guard 會優雅降級到 shell 指令方式，功能完全不受影響。
