# Core 基礎層

> 自動產生 | `./dev-docs/update.sh core`

## 概述

所有套件的共用基礎，提供 AI 適配器、規則引擎、國際化、系統發現、CLI 工具函數。

## 數據

| 項目 | 數據 |
|------|------|
| 套件名 | `@panguard-ai/core` |
| 程式碼 | 14849 行 / 58 檔 |
| 測試 | 12 個測試檔 |
| 匯出 | 19 個公開 API |
| 位置 | `packages/core/src/` |

## 主要模組

| 模組 | 路徑 | 功能 |
|------|------|------|
| AI 適配器 | `src/ai/` | OpenAI, Anthropic, Ollama 統一介面 |
| 規則引擎 | `src/rules/` | Sigma 解析 + YARA 匹配 |
| 評分系統 | `src/scoring/` | 風險評分 0-100, A-F 分級 |
| 發現引擎 | `src/discovery/` | 系統環境偵測 (OS, 服務, 埠號) |
| 國際化 | `src/i18n/` | i18next 雙語支援 |
| CLI 工具 | `src/cli/` | 色彩、spinner、table、box、banner |
| 監控 | `src/monitor/` | 事件監控基礎類別 |
| 威脅情報 | `src/threat-intel/` | 威脅來源整合 |

## 關鍵匯出

```typescript
// CLI 工具
c, symbols, box, spinner, table, header, divider, scoreDisplay, statusPanel,
colorSeverity, formatDuration, timeAgo, stripAnsi, visLen

// 評分
scoreToGrade  // A>=90, B>=75, C>=60, D>=40, F<40

// AI
createAIAdapter, AIAdapter

// 規則
SigmaEngine, YaraScanner
```

## 測試檔案

- `adapters.test.ts` - AI 適配器
- `ai.test.ts` - AI 整合
- `cli.test.ts` - CLI 工具
- `discovery.test.ts` - 系統發現
- `i18n.test.ts` - 國際化
- `monitor.test.ts` - 監控系統
- `osquery.test.ts` - OSQuery
- `rules.test.ts` - 規則引擎
- `scoring.test.ts` - 風險評分
- `sigma-enhanced.test.ts` - Sigma 規則
- `threat-intel-feeds.test.ts` - 威脅來源
- `yara.test.ts` - YARA 規則

## 被誰依賴

所有其他套件都依賴 core。
