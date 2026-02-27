# Panguard Report / 合規報告指南 `[PRO]`

> 自動產生符合法規框架的安全合規報告，讓稽核不再痛苦。
>
> 產生報告和摘要需要 **Pro** 以上方案。

---

## 快速開始

```bash
# 產生台灣資安法合規報告
panguard report generate --framework tw_cyber_security_act --language zh-TW

# 產生 ISO 27001 報告
panguard report generate --framework iso27001

# 產生 SOC 2 報告
panguard report generate --framework soc2

# 查看支援的合規框架
panguard report list-frameworks
```

---

## 支援的合規框架

### 台灣資通安全管理法

```bash
panguard report generate --framework tw_cyber_security_act --language zh-TW
```

10 個控制項：

| 控制項     | 說明             |
| ---------- | ---------------- |
| 資安政策   | 資通安全管理政策 |
| 存取控制   | 系統存取權限管理 |
| 加密管理   | 資料加密機制     |
| 實體安全   | 實體環境安全     |
| 營運安全   | 日常營運安全管理 |
| 通訊安全   | 網路通訊安全     |
| 系統開發   | 系統開發安全     |
| 供應商管理 | 供應鏈安全管理   |
| 事件管理   | 資安事件處理程序 |
| 業務持續   | 業務持續運作計畫 |

### ISO 27001

```bash
panguard report generate --framework iso27001
```

12 個控制項，涵蓋資訊安全管理系統（ISMS）核心要求。

### SOC 2

```bash
panguard report generate --framework soc2
```

10 個控制項，涵蓋 Trust Services Criteria（安全性、可用性、處理完整性、機密性、隱私）。

---

## 報告格式

### JSON 格式（預設）

```bash
panguard report generate --framework iso27001 --format json --output-dir ./reports
```

適合程式化處理和自動化整合。

### PDF 格式

```bash
panguard report generate --framework iso27001 --format pdf --output-dir ./reports
```

適合提交給稽核人員。

---

## 報告內容

每份合規報告包含：

1. **組織資訊** — 組織名稱、報告日期、評估範圍
2. **框架概覽** — 適用的合規框架說明
3. **控制項評估** — 每個控制項的合規狀態
   - Compliant（合規）
   - Partially Compliant（部分合規）
   - Non-Compliant（不合規）
   - Not Assessed（未評估）
4. **發現明細** — 不合規項目的具體問題和證據
5. **修復建議** — 針對每個不合規項目的改善步驟
6. **合規摘要** — 整體合規率和風險評估

---

## 搭配 Scan 使用

Scan 的掃描結果可以作為 Report 的輸入：

```bash
# 1. 先掃描收集安全發現
panguard scan --output scan-findings.pdf

# 2. 用發現產生合規報告
panguard report generate \
  --framework tw_cyber_security_act \
  --input findings.json \
  --org "你的公司名稱" \
  --language zh-TW \
  --output-dir ./reports
```

---

## 驗證輸入檔案

```bash
panguard report validate --input findings.json
```

驗證輸入的 findings JSON 檔案格式是否正確。

---

## 快速合規摘要

不需要完整報告，只想看合規狀態：

```bash
panguard report summary --framework iso27001
```

```
  ── ISO 27001 Compliance Summary ───────

  Overall:    72% compliant
  Compliant:  8/12 controls
  Partial:    2/12 controls
  Gap:        2/12 controls

  Priority fixes:
  1. Access Control - Enforce MFA
  2. Incident Response - Define procedures
```

---

## CLI 選項

```
panguard report <command> [options]

Commands:
  generate           產生合規報告
  list-frameworks    列出支援的合規框架
  validate           驗證輸入檔案
  summary            顯示合規摘要
  config             顯示目前設定
  help               顯示說明

Options:
  --framework <name>     合規框架（tw_cyber_security_act|iso27001|soc2）
  --language <lang>      報告語言（en|zh-TW）
  --format <fmt>         輸出格式（json|pdf）
  --output-dir <path>    輸出目錄
  --org <name>           組織名稱
  --input <file>         輸入檔案（JSON 格式的安全發現）
  --verbose, -v          詳細輸出
```

完整 CLI 參考見 [CLI 指令參考](../reference/cli.md)。
