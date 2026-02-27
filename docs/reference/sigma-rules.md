# Sigma Rules / Sigma 規則撰寫指南

> 用 YAML 寫安全偵測規則。一條規則可以在所有平台上運作。

---

## 什麼是 Sigma？

Sigma 是安全社群開發的通用規則格式，類似 Snort/YARA，但用 YAML 撰寫，專門針對日誌和事件偵測。Panguard Guard 原生支援 Sigma 規則。

---

## 規則格式

一條 Sigma 規則由以下部分組成：

```yaml
title: Rule Title # 規則標題
id: unique-id # 唯一識別碼
status: test # 狀態：test / stable / experimental
description: What this rule detects # 規則說明
logsource: # 日誌來源
  category: process_creation
  product: any
detection: # 偵測邏輯
  selection:
    field_name: value
  condition: selection
level: high # 嚴重等級：informational / low / medium / high / critical
```

---

## 基本範例

### 偵測可疑程序

```yaml
title: Suspicious PowerShell Download
id: rule-ps-download
status: stable
description: Detects PowerShell downloading files from the internet
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process_name: powershell.exe
    cmdline|contains:
      - 'Invoke-WebRequest'
      - 'wget'
      - 'curl'
      - 'DownloadString'
  condition: selection
level: high
```

### 偵測 SSH 暴力破解

```yaml
title: SSH Brute Force Attempt
id: rule-ssh-brute
status: stable
description: Detects multiple failed SSH login attempts
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

### 偵測可疑網路連線

```yaml
title: Connection to Known C2 Range
id: rule-c2-cidr
status: stable
description: Detects connections to known C2 IP ranges
logsource:
  category: network
  product: any
detection:
  selection:
    destination_ip|cidr:
      - '203.0.113.0/24'
      - '198.51.100.0/24'
  condition: selection
level: critical
```

---

## 偵測邏輯

### Selection（選取）

Selection 定義要匹配的欄位和值：

```yaml
detection:
  selection:
    field_name: value              # 精確匹配
    field_name:                    # 多值 OR 匹配
      - value1
      - value2
```

同一個 selection 內的多個欄位是 AND 關係：

```yaml
detection:
  selection:
    process_name: cmd.exe # AND
    cmdline|contains: '/c' # AND
    user: SYSTEM # 三個條件同時滿足
```

### Condition（條件）

#### 基本條件

```yaml
condition: selection                       # 單一 selection
condition: selection1 AND selection2       # AND
condition: selection1 OR selection2        # OR
condition: NOT filter                      # NOT
condition: selection AND NOT filter        # 組合
```

#### 括號群組

```yaml
condition: (sel_a OR sel_b) AND NOT filter
```

#### 聚合表達式

```yaml
condition: 1 of them        # 任一 selection 匹配
condition: all of them       # 所有 selection 都匹配
condition: 1 of sel*         # 任一 sel_ 前綴的 selection 匹配
condition: all of filter*    # 所有 filter_ 前綴的 selection 都匹配
```

### 完整範例：多 Selection + 聚合

```yaml
title: Suspicious Activity Combo
detection:
  sel_download:
    cmdline|contains: 'wget'
  sel_chmod:
    cmdline|contains: 'chmod +x'
  sel_execute:
    cmdline|contains: './'
  filter_known:
    user: deploy
  condition: 1 of sel* AND NOT filter_known
```

---

## 比對修飾符

修飾符用 `|` 附加在欄位名稱後面，改變比對方式：

### 字串修飾符

| 修飾符 | 說明        | 範例       |
| ------ | ----------- | ---------- | --------- | --------------------- |
| `      | contains`   | 包含子字串 | `cmdline  | contains: 'wget'`     |
| `      | startswith` | 開頭匹配   | `path     | startswith: '/tmp'`   |
| `      | endswith`   | 結尾匹配   | `filename | endswith: '.exe'`     |
| `      | re`         | 正則表達式 | `cmdline  | re: 'curl._-o._\.sh'` |

### 數值修飾符

| 修飾符 | 說明 | 範例     |
| ------ | ---- | -------- | ------------ | ----------- |
| `      | gt`  | 大於     | `port        | gt: '1024'` |
| `      | gte` | 大於等於 | `port        | gte: '80'`  |
| `      | lt`  | 小於     | `port        | lt: '1024'` |
| `      | lte` | 小於等於 | `connections | lte: '100'` |

### 網路修飾符

| 修飾符 | 說明  | 範例        |
| ------ | ----- | ----------- | ------- | ----------------------- |
| `      | cidr` | IP 範圍匹配 | `src_ip | cidr: '192.168.1.0/24'` |

### 編碼修飾符

| 修飾符 | 說明    | 範例                    |
| ------ | ------- | ----------------------- | --------- | ------------------ |
| `      | base64` | Base64 編碼匹配         | `cmdline  | base64: 'command'` |
| `      | utf8`   | UTF-8 編碼匹配          | `data     | utf8: 'text'`      |
| `      | wide`   | Wide string（UTF-16LE） | `filename | wide: 'virus'`     |

### 萬用字元

值可以使用萬用字元（不需要修飾符）：

```yaml
detection:
  selection:
    filename: '*.exe' # * 匹配任意字串
    path: '/tmp/????' # ? 匹配單一字元
```

---

## 放置規則

將 `.yml` 檔案放入 Guard 的規則目錄：

```
~/.panguard-guard/rules/sigma/
```

Guard 支援即時監控規則目錄變更（hot reload），新增或修改規則會自動載入，不需要重啟。

---

## 測試規則

建議在非正式環境先測試規則：

1. 將 `status` 設為 `test`
2. 用 `--verbose` 啟動 Guard 觀察匹配結果
3. 確認無誤後改為 `stable`

---

## 內建規則

Guard 內建 42 條 Sigma 規則，涵蓋：

- 暴力破解偵測
- 可疑程序執行
- C2 通訊偵測
- 權限提升
- 橫向移動
- 資料外洩
- Web Shell 偵測
- 加密貨幣挖礦

---

## 相關文件

- [三層 AI 架構](../concepts/three-layer-ai.md)
- [Panguard Guard 使用指南](../guides/guard.md)
- [YARA 規則撰寫指南](yara-rules.md)
