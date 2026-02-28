# Panguard Scan

> 自動產生 | `./dev-docs/update.sh scan`

## 概述

60 秒安全健檢工具。掃描系統漏洞、設定錯誤、權限問題，產出風險評分 + PDF 報告。

## 數據

| 項目 | 數據 |
|------|------|
| 套件名 | `@panguard-ai/panguard-scan` |
| 程式碼 | 5306 行 / 26 檔 |
| 測試 | 3 個測試檔 |
| 匯出 | 8 個公開 API |
| 位置 | `packages/panguard-scan/src/` |
| 方案門檻 | Community (免費) |

## 主要模組

| 模組 | 路徑 | 功能 |
|------|------|------|
| 掃描器 | `src/scanners/` | 系統、網路、檔案掃描引擎 |
| 報告 | `src/report/` | PDF 報告產生 (pdfkit) |
| CLI | `src/cli/` | 命令列介面 |

## CLI 指令

```bash
panguard scan                # 互動模式 (quick/full 選擇)
panguard scan --quick        # 快速掃描 (~30 秒)
panguard scan --output pdf   # 輸出 PDF
panguard scan --lang zh-TW   # 中文報告
panguard scan --verbose      # 詳細輸出
panguard scan --fix          # 自動修復 (Solo+)
```

## 輸出格式

```typescript
interface ScanResult {
  riskScore: number;       // 0-100
  findings: Finding[];     // 發現清單
  scanDuration: number;    // 毫秒
  scannedAt: string;       // ISO timestamp
}
```

## 依賴

- `@panguard-ai/core` - 基礎工具
- `@panguard-ai/security-hardening` - 漏洞掃描器
- `pdfkit` - PDF 產生
- `commander` - CLI 框架

## 待辦

- [ ] Windows 完整支援 (目前部分)
- [ ] 自訂掃描規則
- [ ] 歷史比較報告
