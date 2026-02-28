# 定價方案

> 自動產生 | `./dev-docs/update.sh _project`

## 訂閱方案

| 方案 | 月費 | 機器數 | 包含功能 |
|------|------|--------|----------|
| **Community** | $0 | 1 台 | Scan + Guard 基礎封鎖 + Threat Cloud |
| **Solo** | $9 (NT$270) | 3 台 | + 完整回應 + Chat + Trap 基本 + Ollama |
| **Pro** | $29 (NT$870) | 10 台 | + 雲端 AI + 全蜜罐 + Dashboard |
| **Business** | $79 (NT$2,370) | 25 台 | + 合規報告(月含1份) + Webhook + 優先支援 |

## 功能對應表 (FEATURE_TIER)

| 功能 | 方案門檻 | 程式碼 key |
|------|----------|-----------|
| 安全掃描 | Community | `scan: 'free'` |
| 守護引擎 | Community | `guard: 'free'` |
| 威脅情報 | Community | `'threat-cloud': 'free'` |
| 功能展示 | Community | `demo: 'free'` |
| 初始設定 | Community | `setup: 'free'` |
| 通知系統 | Solo | `notifications: 'solo'` |
| 蜜罐系統 | Solo | `trap: 'solo'` |
| 合規報告 | Business | `report: 'business'` |

## 合規報告單次定價

| 報告類型 | 價格 | Business 訂閱折扣 |
|----------|------|-------------------|
| 資安法準備度評估 | $299 | 50% off |
| ISO 27001 準備度評估 | $499 | 50% off |
| SOC 2 準備度評估 | $699 | 50% off |
| 合規組合包 (3 項全含) | $999 | 50% off |

> 標明「準備度評估 ≠ 正式認證」

## 幣別規則

- 英文介面: USD
- 中文介面: TWD (NT$)

## 程式碼位置

- CLI 定價常數: `packages/panguard/src/cli/auth-guard.ts` → `PRICING_TIERS`, `COMPLIANCE_PRICING`
- 功能門檻: `packages/panguard/src/cli/auth-guard.ts` → `FEATURE_TIER`
- 方案等級: `packages/panguard/src/cli/credentials.ts` → `TIER_LEVEL`
- 顯示名稱: `packages/panguard/src/cli/credentials.ts` → `tierDisplayName()`
- 網站定價: `packages/website/src/app/[locale]/pricing/PricingCards.tsx`
- 網站翻譯: `packages/website/messages/{en,zh}.json` → `pricingPage`
