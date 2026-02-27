# System Service / 安裝為系統服務

> 讓 Guard 隨系統開機自動啟動，7x24 不間斷保護。

---

## 快速安裝

```bash
# 安裝為系統服務
panguard guard install

# 移除系統服務
panguard guard uninstall
```

---

## 各平台支援

### macOS — launchd

Guard 會建立 LaunchDaemon plist 檔案：

```
/Library/LaunchDaemons/ai.panguard.guard.plist
```

安裝後行為：

- 開機自動啟動
- 異常退出自動重啟
- 日誌寫入 `/var/log/panguard guard.log`

管理指令：

```bash
# 查看服務狀態
sudo launchctl list | grep panguard

# 手動啟動
sudo launchctl load /Library/LaunchDaemons/ai.panguard.guard.plist

# 手動停止
sudo launchctl unload /Library/LaunchDaemons/ai.panguard.guard.plist
```

### Linux — systemd

Guard 會建立 systemd service 單元檔案：

```
/etc/systemd/system/panguard guard.service
```

安裝後行為：

- 開機自動啟動（`systemctl enable`）
- 異常退出自動重啟（`Restart=always`）
- 日誌透過 journald 管理

管理指令：

```bash
# 查看服務狀態
systemctl status panguard guard

# 手動啟動/停止
sudo systemctl start panguard guard
sudo systemctl stop panguard guard

# 查看日誌
journalctl -u panguard guard -f
```

### Windows — sc.exe

Guard 會註冊為 Windows 服務：

```
服務名稱：PanguardGuard
顯示名稱：Panguard Guard AI
```

安裝後行為：

- 開機自動啟動
- 異常退出自動重啟
- 日誌寫入 Event Log

管理指令：

```powershell
# 查看服務狀態
sc.exe query PanguardGuard

# 手動啟動/停止
sc.exe start PanguardGuard
sc.exe stop PanguardGuard
```

---

## 安裝腳本

產生一鍵安裝腳本（適合批量部署）：

```bash
# 產生安裝腳本
panguard guard install-script

# 輸出的腳本可直接在目標機器執行
# 目標機器需要各自執行 panguard login 完成認證
```

安裝腳本會自動：

1. 下載 Panguard AI
2. 安裝依賴
3. 安裝為系統服務
4. 啟動 Guard（使用者需先完成 `panguard login`）

---

## Watchdog 健康監控

Guard 的系統服務包含 Watchdog 機制：

- 每 60 秒檢查 Guard 程序是否正常運行
- 記憶體使用量異常時自動重啟
- CPU 使用量異常時自動降級
- 重啟次數超過閾值時停止並通知

---

## PID 管理

Guard 使用 PID 檔案管理程序狀態：

```
~/.panguard guard/guard.pid
```

- 啟動時寫入 PID
- 停止時清除 PID 檔案
- 防止重複啟動
- 支援優雅關閉（SIGTERM / SIGINT）

---

## 資料目錄

系統服務的資料目錄預設：

| 平台    | 預設路徑                    |
| ------- | --------------------------- |
| macOS   | `~/.panguard guard/`        |
| Linux   | `~/.panguard guard/`        |
| Windows | `%APPDATA%\panguard guard\` |

可透過 `--data-dir` 自訂：

```bash
panguard guard start --data-dir /opt/panguard/data
```

資料目錄包含：

- `guard.pid` — PID 檔案
- `baseline/` — 行為基線資料
- `rules/` — 自訂規則
- `logs/` — 事件日誌
- `config.json` — 設定檔

---

## 相關文件

- [Panguard Guard 使用指南](guard.md)
- [設定檔格式](../reference/configuration.md)
