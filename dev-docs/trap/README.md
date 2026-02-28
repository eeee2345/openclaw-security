# Panguard Trap

> 自動產生 | `./dev-docs/update.sh trap`

## 概述

智慧蜜罐系統。部署假服務吸引攻擊者，記錄行為、分析技能等級、建立攻擊者側寫，回饋至 Threat Cloud。

## 數據

| 項目 | 數據 |
|------|------|
| 套件名 | `@panguard-ai/panguard-trap` |
| 程式碼 | 3043 行 / 12 檔 |
| 測試 | 6 個測試檔 |
| 匯出 | 34 個公開 API |
| 位置 | `packages/panguard-trap/src/` |
| 方案門檻 | Solo (基本蜜罐), Pro (全蜜罐) |

## 支援服務

| 服務 | 預設埠 | 預設 | 偵測能力 |
|------|--------|------|----------|
| SSH | 2222 | 啟用 | 13 種 MITRE 技術 (暴力破解、提權、指令執行) |
| HTTP | 8080 | 啟用 | 目錄遍歷、SQL 注入、XSS、RCE、Webshell |
| FTP | - | 停用 | 通用協定偵測 |
| MySQL | - | 停用 | 通用協定偵測 |
| Telnet | - | 停用 | 通用協定偵測 |
| Redis | - | 停用 | 通用協定偵測 |
| SMB | - | 停用 | 通用協定偵測 |
| RDP | - | 停用 | 通用協定偵測 |

## 主要模組

| 模組 | 路徑 | 功能 |
|------|------|------|
| 引擎 | `src/trap-engine.ts` | 中央協調器 — 管理所有蜜罐服務 |
| 服務 | `src/services/` | SSH / HTTP / Generic 蜜罐實作 |
| 側寫 | `src/profiler/` | 攻擊者技能評估 + 意圖分類 |
| 情報 | `src/intel/` | 匿名化威脅情報上傳 |

## 攻擊者側寫

**技能等級**: script_kiddie / intermediate / advanced / apt (0-100 分)

**意圖分類**: 偵察 / 憑證竊取 / 勒索部署 / 挖礦 / 資料竊取 / 殭屍網路 / 橫向移動

**工具偵測**: Nmap, Metasploit, Burp Suite, Cobalt Strike, Mimikatz, BloodHound 等 40+ 工具

## CLI 指令

```bash
panguard-trap start      # 啟動蜜罐
panguard-trap stop       # 停止蜜罐
panguard-trap status     # 即時統計 (sessions, credentials, uptime)
panguard-trap deploy     # 部署特定服務
panguard-trap profiles   # 列出攻擊者側寫
panguard-trap intel      # 顯示威脅情報摘要
```

## 依賴

- `@panguard-ai/core` - 基礎工具
- `ssh2` (選配) - 完整 SSH-2.0 協定支援

## 待辦

- [ ] Docker 部署模板
- [ ] 更多協定模擬 (MQTT, CoAP)
- [ ] 攻擊者地理分佈視覺化
