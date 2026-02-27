# Panguard Scan / 安全掃描指南 `[FREE / STARTER]`

> 60 秒掃描你的系統，找出安全弱點，產生修復建議。
>
> 快速掃描（`--quick`）為 **Free**，完整掃描需要 **Starter** 以上。

---

## 快速開始

```bash
# 快速掃描（~30 秒）
panguard scan --quick

# 完整掃描（~60 秒）
panguard scan

# 產生 PDF 報告
panguard scan --output report.pdf

# 繁體中文模式
panguard scan --lang zh-TW
```

---

## 快速掃描 vs 完整掃描

| 項目           | 快速模式 `--quick` | 完整模式（預設） |
| -------------- | ------------------ | ---------------- |
| 耗時           | ~30 秒             | ~60 秒           |
| OS 偵測        | v                  | v                |
| 網路介面       | v                  | v                |
| 開放 Port      | v                  | v                |
| 執行中服務     | v                  | v                |
| 密碼政策       | v                  | v                |
| 防火牆狀態     | v                  | v                |
| 安全工具偵測   | v                  | v                |
| SSL 憑證驗證   | -                  | v                |
| 排程任務稽核   | -                  | v                |
| 共享資料夾安全 | -                  | v                |
| 風險評分       | v                  | v                |
| PDF 報告       | 需加 `--output`    | 需加 `--output`  |

---

## 掃描項目詳解

### 系統環境偵察

偵測作業系統版本、核心版本、系統架構：

```
  OS:       macOS 14.2 (Darwin 23.2.0)
  Arch:     arm64
  Hostname: my-server
```

### 網路掃描

列出所有網路介面和開放 port：

```
  ── Network Interfaces ─────────────────

  en0    192.168.1.100  (Wi-Fi)
  lo0    127.0.0.1      (Loopback)

  ── Open Ports ─────────────────────────

  Port   Proto  Service     PID    Risk
  22     tcp    sshd        1234   HIGH
  80     tcp    nginx       5678   LOW
  443    tcp    nginx       5678   LOW
  3306   tcp    mysqld      9012   MEDIUM
```

**危險 Port 警告**：Scan 會標記暴露在 0.0.0.0 的高風險 port（如 SSH 22、MySQL 3306、Redis 6379）。

### 密碼政策檢查

檢查系統密碼政策是否足夠強：

- 最小密碼長度
- 密碼複雜度要求
- 密碼過期政策
- 帳號鎖定政策

### SSL 憑證驗證（完整模式）

檢查系統上的 SSL 憑證：

- 是否過期
- 是否自簽
- 加密強度是否足夠
- 憑證鏈是否完整

### 排程任務稽核（完整模式）

檢查 cron job 和排程任務：

- 可疑腳本偵測（下載指令、反向 shell）
- 非常規排程時間
- 不尋常的執行路徑

### 共享資料夾安全（完整模式）

檢查共享資料夾權限：

- 過度開放的權限
- 匿名存取
- 敏感檔案暴露

---

## 風險評分

每次掃描都會產生 0-100 的風險評分：

```
  Score: 62/100 [████████████░░░░░░░░] Grade: C
```

評分基於 8 個因子，詳見[安全分數系統](../concepts/security-score.md)。

---

## PDF 報告

```bash
panguard scan --output my-report.pdf
```

報告內容：

1. **封面** — 組織名稱、掃描日期、品牌標誌
2. **執行摘要** — 風險評分、等級、發現數量統計
3. **發現明細表** — 每個發現的嚴重等級、描述、位置
4. **修復建議** — 針對每個發現的具體修復步驟
5. **合規對應** — 發現與合規框架（ISO 27001 / SOC 2 / 台灣資安法）的對應

報告預設語言為英文。加 `--lang zh-TW` 可產生繁體中文報告。

---

## 掃描結果嚴重等級

| 等級     | 說明                 | 處理建議      |
| -------- | -------------------- | ------------- |
| CRITICAL | 立即有被入侵的風險   | 立刻處理      |
| HIGH     | 高度安全風險         | 24 小時內處理 |
| MEDIUM   | 中等風險，建議改善   | 一週內處理    |
| LOW      | 低風險，最佳實踐建議 | 有空時處理    |
| INFO     | 資訊性發現           | 了解即可      |

---

## 搭配其他產品使用

### Scan + Guard

先用 Scan 了解目前狀態，再用 Guard 持續保護：

```bash
# 1. 先掃描一次
panguard scan --output baseline.pdf

# 2. 根據結果修復問題

# 3. 啟動持續保護
panguard guard start

# 4. 定期重新掃描確認改善
panguard scan --output weekly-check.pdf
```

### Scan + Report

用 Scan 的發現產生合規報告：

```bash
# 掃描結果自動作為合規報告的輸入
panguard scan --output scan-result.pdf
```

---

## CLI 選項

```
panguard scan [options]

Options:
  --quick              快速模式（~30 秒）
  --output <path>      PDF 報告輸出路徑（預設：panguard scan-report.pdf）
  --lang <en|zh-TW>    語言（預設：en）
  --verbose            詳細輸出
```

完整 CLI 參考見 [CLI 指令參考](../reference/cli.md)。
