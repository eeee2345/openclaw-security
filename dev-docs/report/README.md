# Panguard Report

> 自動產生 | `./dev-docs/update.sh report`

## 概述

AI 合規報告產生器。支援台灣資安法、ISO 27001、SOC 2 三大框架，多信號相關性評分，雙語輸出。

## 數據

| 項目 | 數據 |
|------|------|
| 套件名 | `@panguard-ai/panguard-report` |
| 程式碼 | 2061 行 / 12 檔 |
| 測試 | 6 個測試檔 |
| 匯出 | 25+ 個公開 API |
| 位置 | `packages/panguard-report/src/` |
| 方案門檻 | Business (月含 1 份), 額外報告 50% off |

## 合規框架

| 框架 | 控制項數 | 價格 |
|------|----------|------|
| 台灣資安法 (資通安全管理法) | 10 項 | $299 |
| ISO/IEC 27001:2022 | 21 項 (Annex A) | $499 |
| SOC 2 Type II | 10 項 | $699 |
| 組合包 (全部) | 41 項 | $999 |

## 主要模組

| 模組 | 路徑 | 功能 |
|------|------|------|
| 框架 | `src/frameworks/` | 三大框架控制項定義 |
| 映射器 | `src/mapper/` | 多信號相關性評分 (發現 → 控制項) |
| 產生器 | `src/generator/` | 報告組裝 + 序列化 |
| 模板 | `src/templates/` | 雙語標籤 + 格式化 |

## 相關性評分

| 信號 | 分數 |
|------|------|
| 類別完全匹配 | +10 |
| 類別部分匹配 | +3 |
| 控制項描述關鍵字 | +2 |
| CVE + 漏洞管理 | +5 (加分) |
| 門檻 | >= 5 才配對 |

## 報告輸出

```typescript
interface ComplianceReportData {
  id: string;           // RPT-YYYYMM-XXXX
  metadata: ReportMetadata;
  executiveSummary: ExecutiveSummary;
  controls: EvaluatedControl[];
  statistics: ComplianceStatistics;
  recommendations: ReportRecommendation[];
}
```

## CLI 指令

```bash
panguard report generate --framework iso27001    # 產生 ISO 報告
panguard report generate --framework tw-cyber    # 台灣資安法
panguard report generate --framework soc2        # SOC 2
panguard report list-frameworks                  # 列出支援框架
panguard report summary                          # 摘要預覽
```

## 依賴

- `@panguard-ai/core` - 基礎工具

## 待辦

- [ ] PDF 輸出 (整合 pdfkit)
- [ ] 歷史比較報告
- [ ] GDPR 框架
