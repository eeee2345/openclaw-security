# CLI Reference / CLI 完整指令參考

> 所有 Panguard AI 命令列工具的指令、子指令和選項。

Panguard AI 使用統一 CLI 入口。所有功能都透過 `panguard` 指令存取。

```bash
panguard <command> [options]
```

---

## 認證指令

### panguard login

登入 Panguard AI 帳號。開啟瀏覽器完成 OAuth 認證後，token 儲存在本地。

```bash
panguard login [options]
```

| 選項              | 類型    | 預設值                | 說明                                          |
| ----------------- | ------- | --------------------- | --------------------------------------------- |
| `--api-url <url>` | string  | `https://panguard.ai` | 認證伺服器 URL                                |
| `--no-browser`    | boolean | `false`               | 印出 URL 而非開啟瀏覽器（for SSH / headless） |
| `--lang <lang>`   | string  | `zh-TW`               | 語言（`en` 或 `zh-TW`）                       |

```bash
# 標準登入
panguard login

# SSH / 無頭伺服器
panguard login --no-browser

# 指定自建伺服器
panguard login --api-url http://localhost:3100
```

---

### panguard logout

登出 Panguard AI。刪除本地 token 並通知伺服器。

```bash
panguard logout [options]
```

| 選項            | 類型   | 預設值  | 說明 |
| --------------- | ------ | ------- | ---- |
| `--lang <lang>` | string | `zh-TW` | 語言 |

---

### panguard whoami

顯示目前登入帳號資訊。

```bash
panguard whoami [options]
```

| 選項            | 類型    | 預設值  | 說明          |
| --------------- | ------- | ------- | ------------- |
| `--json`        | boolean | `false` | JSON 格式輸出 |
| `--lang <lang>` | string  | `zh-TW` | 語言          |

```bash
# 顯示帳號資訊
panguard whoami

# JSON 格式（for scripting）
panguard whoami --json
```

---

## 設定精靈

### panguard init

互動式設定精靈。引導語言、防護模式、通知管道、AI 偏好等設定。不需要登入。

```bash
panguard init [options]
```

| 選項              | 類型   | 預設值                    | 說明       |
| ----------------- | ------ | ------------------------- | ---------- |
| `--config <path>` | string | `~/.panguard/config.json` | 設定檔路徑 |
| `--lang <lang>`   | string | -                         | 語言覆寫   |

---

## 安全掃描

### panguard scan `[FREE / STARTER]`

60 秒安全掃描工具。快速掃描（`--quick`）為 Free，完整掃描需要 Starter。

```bash
panguard scan [options]
```

| 選項              | 類型    | 預設值                     | 說明                          |
| ----------------- | ------- | -------------------------- | ----------------------------- |
| `--quick`         | boolean | `false`                    | 快速模式（~30 秒，Free 可用） |
| `--output <path>` | string  | `panguard-scan-report.pdf` | PDF 報告輸出路徑              |
| `--lang <lang>`   | string  | `en`                       | 語言（`en` 或 `zh-TW`）       |
| `--verbose`       | boolean | `false`                    | 詳細輸出                      |

```bash
# 快速掃描（Free）
panguard scan --quick

# 完整掃描 + 繁體中文 PDF 報告（Starter）
panguard scan --output report.pdf --lang zh-TW
```

---

## 即時防護

### panguard guard `[FREE / STARTER]`

AI 即時監控守護引擎。狀態查詢為 Free，啟動/停止需要 Starter。

```bash
panguard guard <command> [options]
```

#### 子指令

| 子指令      | 等級    | 說明            |
| ----------- | ------- | --------------- |
| `start`     | Starter | 啟動 Guard 引擎 |
| `stop`      | Starter | 停止 Guard 引擎 |
| `status`    | Free    | 顯示引擎狀態    |
| `install`   | Starter | 安裝為系統服務  |
| `uninstall` | Starter | 移除系統服務    |
| `config`    | Free    | 顯示目前設定    |
| `help`      | -       | 顯示說明        |

#### 選項

| 選項                | 類型   | 預設值              | 說明     |
| ------------------- | ------ | ------------------- | -------- |
| `--data-dir <path>` | string | `~/.panguard-guard` | 資料目錄 |

```bash
# 啟動 Guard（Starter）
panguard guard start

# 查看狀態（Free）
panguard guard status

# 自訂資料目錄
panguard guard start --data-dir /opt/panguard/data

# 安裝為系統服務
panguard guard install
```

---

## 通知管理

### panguard chat `[STARTER]`

AI 安全通知管理工具。setup/test 需要 Starter。

```bash
panguard chat <command> [options]
```

#### 子指令

| 子指令   | 等級    | 說明               |
| -------- | ------- | ------------------ |
| `setup`  | Starter | 互動式通知設定精靈 |
| `test`   | Starter | 發送測試通知       |
| `status` | Free    | 顯示管道狀態       |
| `config` | Free    | 顯示目前設定       |
| `prefs`  | Starter | 查看/更新通知偏好  |

#### 選項

| 選項                 | 類型   | 可用值                                          | 說明       |
| -------------------- | ------ | ----------------------------------------------- | ---------- |
| `--channel <type>`   | string | `line`, `telegram`, `slack`, `email`, `webhook` | 通知管道   |
| `--user-type <type>` | string | `developer`, `boss`, `it_admin`                 | 使用者角色 |
| `--lang <lang>`      | string | `en`, `zh-TW`                                   | 語言       |

```bash
# 互動式設定
panguard chat setup

# LINE + 老闆模式 + 繁體中文
panguard chat setup --channel line --user-type boss --lang zh-TW

# 測試通知
panguard chat test

# 查看通知偏好
panguard chat prefs

# 更新偏好
panguard chat prefs --critical on --daily off
```

---

## 部署

### panguard deploy `[STARTER]`

部署已配置的服務。需要先執行 `panguard init`。

```bash
panguard deploy [options]
```

| 選項              | 類型    | 預設值                    | 說明                 |
| ----------------- | ------- | ------------------------- | -------------------- |
| `--config <path>` | string  | `~/.panguard/config.json` | 設定檔路徑           |
| `--dry-run`       | boolean | `false`                   | 顯示部署計畫但不執行 |
| `--lang <lang>`   | string  | -                         | 語言覆寫             |

```bash
# 查看部署計畫
panguard deploy --dry-run

# 執行部署
panguard deploy
```

---

## 系統狀態

### panguard status `[FREE]`

顯示系統整體狀態。

```bash
panguard status [options]
```

| 選項              | 類型    | 預設值                    | 說明          |
| ----------------- | ------- | ------------------------- | ------------- |
| `--json`          | boolean | `false`                   | JSON 格式輸出 |
| `--config <path>` | string  | `~/.panguard/config.json` | 設定檔路徑    |
| `--lang <lang>`   | string  | -                         | 語言覆寫      |

```bash
# 品牌化狀態面板
panguard status

# JSON 格式
panguard status --json
```

---

## 合規報告

### panguard report `[PRO]`

合規報告產生工具。

```bash
panguard report <command> [options]
```

#### 子指令

| 子指令            | 等級 | 說明               |
| ----------------- | ---- | ------------------ |
| `generate`        | Pro  | 產生合規報告       |
| `summary`         | Pro  | 顯示合規摘要       |
| `list-frameworks` | Free | 列出支援的合規框架 |
| `validate`        | Free | 驗證輸入檔案       |
| `config`          | Free | 顯示目前設定       |

#### 選項

| 選項                  | 類型   | 可用值                                      | 說明     |
| --------------------- | ------ | ------------------------------------------- | -------- |
| `--framework <name>`  | string | `tw_cyber_security_act`, `iso27001`, `soc2` | 合規框架 |
| `--language <lang>`   | string | `en`, `zh-TW`                               | 報告語言 |
| `--format <fmt>`      | string | `json`, `pdf`                               | 輸出格式 |
| `--output-dir <path>` | string | -                                           | 輸出目錄 |
| `--org <name>`        | string | -                                           | 組織名稱 |

```bash
# 台灣資安法報告
panguard report generate --framework tw_cyber_security_act --language zh-TW

# ISO 27001 PDF 報告
panguard report generate --framework iso27001 --format pdf

# 合規摘要
panguard report summary --framework soc2
```

---

## 蜜罐系統

### panguard trap `[PRO]`

智慧蜜罐管理工具。start/stop 需要 Pro，status/config/profiles/intel 不需要。

```bash
panguard trap <command> [options]
```

#### 子指令

| 子指令     | 等級 | 說明             |
| ---------- | ---- | ---------------- |
| `start`    | Pro  | 啟動蜜罐服務     |
| `stop`     | Pro  | 停止蜜罐服務     |
| `status`   | Free | 顯示狀態和統計   |
| `config`   | Free | 顯示目前設定     |
| `profiles` | Free | 顯示攻擊者側寫   |
| `intel`    | Free | 顯示威脅情報摘要 |

#### 選項

| 選項                 | 類型    | 可用值                                    | 說明                   |
| -------------------- | ------- | ----------------------------------------- | ---------------------- |
| `--services <types>` | string  | `ssh,http,ftp,smb,mysql,rdp,telnet,redis` | 服務類型（逗號分隔）   |
| `--data-dir <path>`  | string  | -                                         | 資料目錄               |
| `--no-cloud`         | boolean | -                                         | 停用 Threat Cloud 上傳 |

```bash
# 啟動 SSH 和 HTTP 蜜罐
panguard trap start --services ssh,http

# 查看攻擊者側寫
panguard trap profiles

# 不上傳到 Threat Cloud
panguard trap start --services ssh --no-cloud
```

---

## 威脅情報

### panguard threat `[ENTERPRISE]`

威脅情報 API 伺服器管理。

```bash
panguard threat <command> [options]
```

#### 子指令

| 子指令  | 等級       | 說明                         |
| ------- | ---------- | ---------------------------- |
| `start` | Enterprise | 啟動 Threat Cloud API 伺服器 |
| `stats` | Solo       | 顯示威脅情報統計             |

#### 選項

| 選項              | 類型   | 預設值              | 說明              |
| ----------------- | ------ | ------------------- | ----------------- |
| `--port <number>` | number | `8080`              | 監聽 port         |
| `--host <string>` | string | `127.0.0.1`         | 監聽位址          |
| `--db <path>`     | string | `./threat-cloud.db` | SQLite 資料庫路徑 |

```bash
# 啟動伺服器
panguard threat start

# 自訂 port 和 host
panguard threat start --port 9090 --host 0.0.0.0

# 查看威脅統計
panguard threat stats
```

---

## 功能展示

### panguard demo `[FREE]`

展示 Panguard AI 品牌渲染和功能。不需要登入。

```bash
panguard demo
```

---

## 全域選項

所有指令都支援以下選項：

| 選項              | 說明     |
| ----------------- | -------- |
| `--help`, `-h`    | 顯示說明 |
| `--version`, `-V` | 顯示版本 |

---

## 功能等級總覽

| 指令                      | Free | Starter | Pro | Enterprise |
| ------------------------- | ---- | ------- | --- | ---------- |
| `login / logout / whoami` | v    | v       | v   | v          |
| `init`                    | v    | v       | v   | v          |
| `status`                  | v    | v       | v   | v          |
| `demo`                    | v    | v       | v   | v          |
| `scan --quick`            | v    | v       | v   | v          |
| `scan` (full)             | -    | v       | v   | v          |
| `guard start`             | -    | v       | v   | v          |
| `chat setup`              | -    | v       | v   | v          |
| `deploy`                  | -    | v       | v   | v          |
| `report generate`         | -    | -       | v   | v          |
| `trap start`              | -    | -       | v   | v          |
| `threat start`            | -    | -       | -   | v          |
