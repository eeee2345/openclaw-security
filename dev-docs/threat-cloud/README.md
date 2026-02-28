# Threat Cloud

> 自動產生 | `./dev-docs/update.sh threat-cloud`

## 概述

社群威脅情報平台。彙整所有 Guard / Trap 上報的匿名威脅數據，自動產生規則、建立攻擊活動關聯、分發 IoC。

## 數據

| 項目 | 數據 |
|------|------|
| 套件名 | `@panguard-ai/threat-cloud` |
| 程式碼 | 4352 行 / 14 檔 |
| 測試 | 11 個測試檔 |
| 匯出 | 9 類別 + 31 型別 |
| 位置 | `packages/threat-cloud/src/` |
| 方案門檻 | Community (免費查詢) |

## 主要模組

| 模組 | 路徑 | 功能 |
|------|------|------|
| Server | `src/server.ts` | HTTP API (12 端點) |
| Database | `src/database.ts` | SQLite + 8 版 Migration |
| IoC Store | `src/ioc-store.ts` | IoC CRUD + 去重 + 分頁 |
| Reputation | `src/reputation-engine.ts` | 加權信譽評分 |
| Correlation | `src/correlation-engine.ts` | IP/Pattern 攻擊活動關聯 |
| Rule Gen | `src/rule-generator.ts` | 自動 Sigma 規則產生 |
| Query | `src/query-handlers.ts` | 時間序列 / 地理分佈 / MITRE 熱力圖 |
| Feed | `src/feed-distributor.ts` | 封鎖清單 + IoC Feed 分發 |
| Audit | `src/audit-logger.ts` | 操作來源追蹤 |
| Scheduler | `src/scheduler.ts` | 背景任務排程 |

## API 端點

| 方法 | 路徑 | 功能 |
|------|------|------|
| POST | `/api/threats` | 上傳匿名威脅數據 (Guard) |
| POST | `/api/trap-intel` | 上傳蜜罐情報 (Trap) |
| GET | `/api/rules` | 取得規則 (?since= 篩選) |
| POST | `/api/rules` | 發布社群規則 |
| GET | `/api/stats` | 威脅統計 |
| GET | `/api/iocs` | 搜尋 / 列出 IoC |
| GET | `/api/iocs/:value` | 查詢單一 IoC |
| POST | `/api/sightings` | 記錄 IoC 目擊 |
| GET | `/api/campaigns` | 攻擊活動清單 |
| GET | `/api/audit-log` | 稽核日誌 |
| GET | `/health` | 健康檢查 |

## 信譽評分權重

| 因子 | 權重 |
|------|------|
| 目擊頻率 | 30% |
| 嚴重程度 | 25% |
| 時效性 (指數衰減, 30 天半衰期) | 20% |
| 來源多樣性 | 15% |
| 信心度 | 10% |

## 背景排程

| 任務 | 間隔 |
|------|------|
| 信譽重算 | 1 小時 |
| 攻擊活動掃描 | 5 分鐘 |
| 規則產生 | 6 小時 |
| 資料生命週期清理 | 24 小時 |

## 預載威脅來源

IPsum / Feodo Tracker / Blocklist.de / Spamhaus DROP / CINS Army / URLhaus (全部免費)

## 依賴

- `better-sqlite3` - SQLite 資料庫

## 待辦

- [ ] STIX/TAXII 標準格式
- [ ] 更多免費威脅來源整合
- [ ] Web 介面
