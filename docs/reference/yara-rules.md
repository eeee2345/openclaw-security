# YARA Rules / YARA 規則撰寫指南

> 用 pattern matching 偵測惡意檔案。比 grep 強大，比 AI 便宜。

---

## 什麼是 YARA？

YARA 是惡意程式研究員開發的 pattern matching 工具，用來識別和分類惡意檔案。你寫一條規則描述惡意檔案的特徵，YARA 就能在你的系統上找到匹配的檔案。

Panguard Guard 支援原生 YARA 引擎。如果系統未安裝 YARA，會自動降級為 regex fallback（功能略減但仍可用）。

---

## 規則格式

```yara
rule RuleName {
    meta:
        description = "Rule description"
        author = "Your Name"
        severity = "high"

    strings:
        $string1 = "text pattern"
        $string2 = { hex pattern }
        $regex1 = /regex pattern/

    condition:
        any of them
}
```

---

## 基本範例

### 偵測 Web Shell

```yara
rule PHP_WebShell {
    meta:
        description = "Detects common PHP web shells"
        severity = "critical"

    strings:
        $eval = "eval($_" nocase
        $exec = "exec($_" nocase
        $system = "system($_" nocase
        $passthru = "passthru(" nocase
        $shell_exec = "shell_exec(" nocase
        $base64 = "base64_decode(" nocase

    condition:
        2 of them
}
```

### 偵測可疑腳本

```yara
rule Suspicious_Shell_Script {
    meta:
        description = "Detects potentially malicious shell scripts"
        severity = "high"

    strings:
        $shebang = "#!/bin/bash" nocase
        $wget = "wget " nocase
        $curl = "curl " nocase
        $chmod = "chmod +x" nocase
        $rm_rf = "rm -rf /" nocase
        $reverse_shell = "/dev/tcp/" nocase
        $nc = "nc -e" nocase

    condition:
        $shebang and ($rm_rf or $reverse_shell or $nc or (($wget or $curl) and $chmod))
}
```

### 偵測加密貨幣礦工

```yara
rule Crypto_Miner {
    meta:
        description = "Detects cryptocurrency mining software"
        severity = "medium"

    strings:
        $stratum = "stratum+tcp://" nocase
        $xmrig = "xmrig" nocase
        $pool = "mining pool" nocase
        $wallet = /[0-9a-fA-F]{64}/
        $hashrate = "hashrate" nocase

    condition:
        2 of them
}
```

---

## Strings 語法

### 文字字串

```yara
$text = "plain text"              // 大小寫敏感
$text = "plain text" nocase       // 大小寫不敏感
$text = "plain text" wide         // UTF-16 寬字元
$text = "plain text" ascii wide   // 同時匹配 ASCII 和 UTF-16
```

### Hex 字串

```yara
$hex = { 4D 5A 90 00 }           // 精確匹配位元組
$hex = { 4D 5A ?? 00 }           // ?? 匹配任意位元組
$hex = { 4D 5A [2-4] 00 }        // [2-4] 匹配 2-4 個任意位元組
```

### 正則表達式

```yara
$re = /https?:\/\/[a-z0-9.]+\.(ru|cn|tk)/
$re = /eval\s*\(\s*base64_decode/ nocase
```

---

## Condition 語法

### 基本條件

```yara
condition:
    $string1                      // 特定字串存在
    any of them                   // 任一字串匹配
    all of them                   // 所有字串匹配
    2 of them                     // 至少 2 個匹配
    $string1 and $string2         // AND
    $string1 or $string2          // OR
    not $string1                  // NOT
```

### 進階條件

```yara
condition:
    filesize < 1MB                // 檔案大小
    #string1 > 5                  // 字串出現次數 > 5
    $string1 at 0                 // 字串在檔案開頭
    $string1 in (0..1024)         // 字串在前 1024 bytes 內
    uint16(0) == 0x5A4D           // MZ header（PE 檔案）
```

---

## 放置規則

將 `.yar` 或 `.yara` 檔案放入 Guard 的規則目錄：

```
~/.panguard-guard/rules/yara/
```

Guard 會自動載入此目錄下的所有 YARA 規則。

---

## 原生 vs Fallback

| 功能          | 原生 YARA | Regex Fallback |
| ------------- | --------- | -------------- |
| 文字字串      | v         | v              |
| Hex 字串      | v         | -              |
| 正則表達式    | v         | v              |
| nocase 修飾符 | v         | v              |
| wide 修飾符   | v         | -              |
| 檔案大小條件  | v         | -              |
| 位元組偏移    | v         | -              |
| 效能          | 快        | 中等           |

### 安裝原生 YARA

```bash
# macOS
brew install yara

# Ubuntu/Debian
sudo apt install yara

# CentOS/RHEL
sudo yum install yara
```

如果不安裝，Panguard 會自動使用 regex fallback，基本偵測功能不受影響。

---

## 最佳實踐

1. **從簡單開始** — 先用幾個關鍵字串，再逐步增加精確度
2. **避免太寬泛** — 太寬泛的規則會產生大量誤報
3. **加 meta 資訊** — 方便管理和追蹤
4. **測試再部署** — 先在測試環境確認無誤
5. **定期更新** — 關注安全社群分享的規則

---

## 相關文件

- [三層 AI 架構](../concepts/three-layer-ai.md)
- [Panguard Guard 使用指南](../guides/guard.md)
- [Sigma 規則撰寫指南](sigma-rules.md)
