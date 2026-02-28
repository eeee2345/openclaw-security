# Panguard AI - 開發資料索引

> 自動產生於 2026-02-28 | 執行 `./dev-docs/update.sh` 更新

## 專案總覽

| 項目 | 數據 |
|------|------|
| 版本 | v0.1.0 |
| 套件數 | 13 |
| 總程式碼 | ~68719 行 |
| 測試檔 | 65 個 |
| 官網頁面 | 41 頁 (雙語) |
| 偵測規則 | 3,158 條 |
| 授權 | MIT |
| 最後更新 | 2026-02-28 |

## 產品線索引

| 產品 | 資料夾 | 程式碼 | 測試 | 方案門檻 |
|------|--------|--------|------|----------|
| [Core 基礎層](core/) | `packages/core` | 14,849 行 / 58 檔 | 12 | - |
| [Panguard Scan](scan/) | `packages/panguard-scan` | 5,306 行 / 26 檔 | 3 | Community |
| [Panguard Guard](guard/) | `packages/panguard-guard` | 7,814 行 / 32 檔 | 7 | Community |
| [Panguard Chat](chat/) | `packages/panguard-chat` | 4,532 行 / 20 檔 | 6 | Solo |
| [Panguard Trap](trap/) | `packages/panguard-trap` | 3,043 行 / 12 檔 | 6 | Solo |
| [Panguard Report](report/) | `packages/panguard-report` | 2,061 行 / 12 檔 | 6 | Business |
| [Threat Cloud](threat-cloud/) | `packages/threat-cloud` | 3,485 行 / 12 檔 | 9 | Community |
| [Auth Server](auth/) | `packages/panguard-auth` | 2,422 行 / 10 檔 | 5 | - |
| [CLI 統一入口](cli/) | `packages/panguard` | 6,684 行 / 32 檔 | 1 | - |
| [Website 官網](website/) | `packages/website` | Next.js 14 | 2 | - |
| [Security Hardening](security-hardening/) | `security-hardening` | 1,659 行 / 19 檔 | 6 | - |

## 專案層級文件

| 文件 | 說明 |
|------|------|
| [架構總覽](_project/architecture.md) | 套件相依、三層 AI、資料流 |
| [定價方案](_project/pricing.md) | 4 個訂閱方案 + 合規報告單次定價 |
| [技術棧](_project/tech-stack.md) | 語言、框架、工具鏈 |
| [部署配置](_project/deployment.md) | Docker、Railway、Vercel、系統服務 |

## 更新方式

```bash
# 更新全部
./dev-docs/update.sh

# 更新單一產品
./dev-docs/update.sh scan
./dev-docs/update.sh guard

# 更新專案層級
./dev-docs/update.sh _project
```
