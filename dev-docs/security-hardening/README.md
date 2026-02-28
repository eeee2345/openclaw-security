# Security Hardening

> 自動產生 | `./dev-docs/update.sh security-hardening`

## 概述

安全強化庫。提供 WebSocket 安全、憑證加密儲存、指令沙箱、權限策略、稽核日誌、漏洞掃描。

## 數據

| 項目 | 數據 |
|------|------|
| 套件名 | `@panguard-ai/security-hardening` |
| 程式碼 | 1659 行 / 19 檔 |
| 測試 | 6 個測試檔 |
| 匯出 | 6 個子路徑匯出 |
| 位置 | `security-hardening/src/` |

## 模組

| 模組 | 路徑 | 功能 |
|------|------|------|
| WebSocket | `src/websocket/` | Origin 驗證 + CSRF Token + URL 清理 (CVE-2026-25253) |
| 憑證 | `src/credentials/` | AES-256-GCM 加密儲存 + 明文掃描 + 遷移 |
| 沙箱 | `src/sandbox/` | 指令白名單 + 檔案系統路徑守衛 |
| 權限 | `src/permissions/` | 安全策略載入 + 操作許可檢查 |
| 稽核 | `src/audit/` | 事件記錄 + Syslog 轉接 |
| 掃描 | `src/scanner/` | 漏洞掃描 + 安全稽核報告 |

## 子路徑匯出

```javascript
import { validateOrigin } from '@panguard-ai/security-hardening/websocket';
import { EncryptedFileCredentialStore } from '@panguard-ai/security-hardening/credentials';
import { isCommandAllowed } from '@panguard-ai/security-hardening/sandbox';
import { loadSecurityPolicy } from '@panguard-ai/security-hardening/permissions';
import { logAuditEvent } from '@panguard-ai/security-hardening/audit';
import { runSecurityAudit } from '@panguard-ai/security-hardening/scanner';
```

## 關鍵匯出

| 模組 | 匯出 |
|------|------|
| WebSocket | `validateOrigin`, `createOriginValidator`, `CsrfTokenManager`, `validateGatewayUrl`, `sanitizeWebSocketUrl` |
| 憑證 | `InMemoryCredentialStore`, `EncryptedFileCredentialStore`, `scanPlaintextCredentials`, `migrateCredentials` |
| 沙箱 | `isPathAllowed`, `createFilesystemGuard`, `isCommandAllowed`, `createCommandValidator` |
| 權限 | `loadSecurityPolicy`, `isOperationAllowed`, `DEFAULT_SECURITY_POLICY` |
| 稽核 | `logAuditEvent`, `logWebSocketConnect`, `logCredentialAccess`, `logFileAccess`, `SyslogAdapter` |
| 掃描 | `runSecurityAudit` |

## 被誰依賴

- `@panguard-ai/panguard-auth` - 認證系統
- `@panguard-ai/panguard` (CLI) - 安全強化指令

## 依賴

- `@panguard-ai/core` - 基礎工具
- `zod` - Schema 驗證

## 待辦

- [ ] 更多 CVE 掃描規則
- [ ] 自動修復建議
- [ ] CIS Benchmark 整合
