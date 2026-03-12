# 快速使用手冊 / Quick Start Guide

> 從安裝到使用每一個功能的完整操作指南。

---

## 安裝與建置

### 從原始碼安裝（目前推薦）

```bash
git clone https://github.com/panguard-ai/panguard-ai.git
cd panguard-ai
pnpm install
pnpm build
```

### 啟動 CLI

安裝完成後，有兩種方式執行 CLI：

```bash
# 方式 1：使用 bin wrapper（推薦）
./bin/panguard --help

# 方式 2：使用 pnpm script
pnpm cli -- --help
```

### 確認版本

```bash
./bin/panguard --version
# 輸出: 0.1.0
```

---

## 登入

### 標準登入（有瀏覽器環境）

```bash
./bin/panguard login
```

CLI 會自動開啟瀏覽器，使用 Google 帳號或 Email + 密碼完成登入。登入成功後終端機顯示帳號資訊。

### SSH / 無頭伺服器登入

```bash
./bin/panguard login --no-browser
```

CLI 會印出認證 URL，複製到其他裝置的瀏覽器開啟即可。

### 指定自建伺服器

```bash
./bin/panguard login --api-url http://localhost:3100
```

### 確認登入狀態

```bash
./bin/panguard whoami
```

### 登出

```bash
./bin/panguard logout
```

---

## 安全掃描

### 快速掃描

```bash
./bin/panguard scan --quick
```

約 30 秒完成基礎檢查，包含：

- 作業系統偵測
- 開放端口掃描
- 防火牆狀態
- 使用者帳號稽核
- 風險評分

### 完整掃描

```bash
./bin/panguard scan
```

約 60 秒，額外包含：

- 活躍連線偵測
- SSL 憑證檢查
- 排程任務稽核
- 共享資料夾安全檢查
- 系統更新狀態

### 繁體中文輸出

```bash
./bin/panguard scan --lang zh-TW
```

### 產生 PDF 報告

```bash
./bin/panguard scan --output my-report.pdf
```

---

## 即時防護 Guard

Guard 持續監控系統，偵測異常行為。所有使用者皆可使用。

### 啟動防護

```bash
./bin/panguard guard start
```

Guard 的運作方式：

1. **前 7 天（學習模式）**：AI 觀察系統正常行為，建立基線
2. **第 8 天起（保護模式）**：自動偵測異常，執行回應動作

### 查看狀態

```bash
./bin/panguard guard status
```

### 停止防護

```bash
./bin/panguard guard stop
```

---

## 通知設定 Chat

偵測到威脅時自動通知你。所有使用者皆可使用。

### 互動式設定

```bash
./bin/panguard chat setup
```

引導你選擇通知管道（LINE / Telegram / Slack / Email / Webhook）和訊息風格。

### 指定管道設定

```bash
# LINE 通知，老闆模式（人話摘要）
./bin/panguard chat setup --channel line --user-type boss

# Slack 通知，IT 管理員模式（修復步驟）
./bin/panguard chat setup --channel slack --user-type it_admin
```

### 測試通知

```bash
./bin/panguard chat test
```

---

## 蜜罐系統 Trap（Coming Soon）

部署蜜罐服務，捕捉攻擊者行為。此功能尚在開發中。

### 部署蜜罐

```bash
./bin/panguard trap deploy
```

### 查看狀態

```bash
./bin/panguard trap status
```

蜜罐會開啟真實的 TCP 端口，模擬 SSH / HTTP / FTP 等服務，記錄所有連入嘗試。

---

## 合規報告 Report（Coming Soon）

產生符合國際標準的合規評估報告。此功能尚在開發中。

### 支援框架

| 框架                    | 說明                                       |
| ----------------------- | ------------------------------------------ |
| `tw_cyber_security_act` | 台灣資通安全管理法（10 控制項）            |
| `iso27001`              | ISO/IEC 27001:2022（30 控制項）            |
| `soc2`                  | SOC 2 Trust Services Criteria（10 控制項） |

### 產生報告

```bash
# 台灣資通安全法報告（中文）
./bin/panguard report --framework tw_cyber_security_act --lang zh-TW

# ISO 27001 報告（英文）
./bin/panguard report --framework iso27001 --lang en

# SOC 2 報告
./bin/panguard report --framework soc2
```

報告包含：執行摘要、控制項評估、證據、統計、修復建議。

---

## 功能總覽

所有功能對所有使用者免費開放：

| 功能       | 說明                       |
| ---------- | -------------------------- |
| 快速掃描   | 基礎安全檢查              |
| 完整掃描   | 深度安全掃描              |
| Guard 防護 | AI 即時監控與自動回應     |
| 通知管道   | 不限數量                  |
| Trap 蜜罐  | Coming Soon               |
| 合規報告   | Coming Soon               |
| 威脅情報   | 已整合 5 個威脅情報來源   |

規則引擎內建 3,760 條 Sigma 規則、5,961 條 YARA 規則、69 條 ATR 規則。

---

## 其他常用指令

```bash
# 設定精靈
./bin/panguard init

# 系統狀態總覽
./bin/panguard status

# 部署所有已設定的服務
./bin/panguard deploy

# 自動化展示
./bin/panguard demo

# 威脅情報查詢
./bin/panguard threat
```

---

## 常見問題

### CLI 找不到 panguard 指令？

目前 npm 套件尚未發佈。請使用以下方式：

```bash
./bin/panguard --help      # bin wrapper
pnpm cli -- --help         # pnpm script
```

### 掃描沒有反應？

1. 確認 Node.js >= 20：`node --version`
2. 確認已建置：`pnpm build`
3. 確認 CLI 可執行：`./bin/panguard --version`

### Guard 啟動失敗？

1. 確認已登入：`./bin/panguard whoami`
2. 如果端口衝突，Guard 會自動選擇可用端口

### 登入時瀏覽器沒開啟？

使用 `--no-browser` 選項手動開啟 URL：

```bash
./bin/panguard login --no-browser
```

---

## 相關文件

- [快速開始](../getting-started.md) -- 5 分鐘上手
- [認證架構](../concepts/authentication.md) -- 登入流程技術說明
- [CLI 指令參考](../reference/cli.md) -- 完整指令文件
- [帳號設定](./account-setup.md) -- 帳號建立指南
