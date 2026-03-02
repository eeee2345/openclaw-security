# Security Policy / 安全政策

## Supported Versions / 支援版本

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < Latest | No       |

Only the latest release receives security updates.
僅最新版本接受安全性更新。

## Reporting Vulnerabilities / 回報漏洞

If you discover a security vulnerability, please report it responsibly.
如果您發現安全漏洞，請負責任地回報。

**Email:** security@panguard-ai.io

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

請包含：
- 漏洞描述
- 重現步驟
- 潛在影響評估
- 建議修復方案（如有）

## Response Timeline / 回應時間

| Phase | Target |
|-------|--------|
| Acknowledgment / 確認 | 24 hours |
| Assessment / 評估 | 72 hours |
| CRITICAL fix / 緊急修復 | 7 days |
| HIGH fix / 高優先修復 | 14 days |
| MEDIUM fix / 中優先修復 | 30 days |

## Disclosure Policy / 揭露政策

We follow a 90-day responsible disclosure policy. If a fix is not available within 90 days, the reporter may disclose the vulnerability publicly.
我們遵循 90 天負責任揭露政策。若 90 天內未修復，回報者可公開揭露。

## Encryption & Authentication / 加密與驗證

| Component | Method |
|-----------|--------|
| Password hashing | scrypt (N=65536, r=8, p=1, keylen=64) |
| Session tokens | SHA-256 hash stored; 32-byte random plaintext sent to client |
| TOTP secrets | AES-256-GCM encrypted at rest |
| Reset tokens | SHA-256 hash stored; plaintext sent via email |
| Transport | TLS 1.2+ (HSTS enabled with preload) |

## Code Security Rules / 程式碼安全規則

### 1. No Dynamic Code Execution / 禁止動態程式碼執行

- Never use `eval()` or `Function()` constructor
- 禁止使用 `eval()` 或 `Function()` 建構函式

### 2. Input Validation / 輸入驗證

- All external input must be validated using Zod schemas
- Sanitize file paths to prevent directory traversal
- 所有外部輸入必須使用 Zod schema 驗證
- 清理檔案路徑以防止目錄遍歷

### 3. Credential Management / 憑證管理

- No plaintext credential storage
- Use platform-specific secure storage (Keychain, Credential Manager, libsecret)
- Use environment variables for development
- 禁止明文儲存憑證
- 使用平台特定的安全儲存（Keychain、Credential Manager、libsecret）
- 開發環境使用環境變數

### 4. Process Execution / 程序執行

- Always use `execFile()` instead of `exec()` to prevent shell injection
- Validate all command arguments
- 一律使用 `execFile()` 而非 `exec()` 以防止 shell injection
- 驗證所有命令參數

### 5. Dependencies / 相依套件

- Run `pnpm audit` regularly
- Keep dependencies updated
- Review new dependencies before adding
- 定期執行 `pnpm audit`
- 保持相依套件更新
- 新增相依套件前進行審查

### 6. TypeScript Safety / TypeScript 安全

- Strict mode enabled across all packages
- No `any` types unless explicitly justified with comments
- 所有套件啟用嚴格模式
- 除非有明確理由並加註釋，否則禁止使用 `any` 類型

## Security Headers / 安全標頭

The marketing website sets the following security headers:

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Content-Security-Policy` (with script-src self)

## Known Limitations / 已知限制

- CSP uses `unsafe-inline` for script-src due to Next.js JSON-LD requirements
- Website rate limiting is per-instance on serverless (Vercel WAF recommended for production)

## License / 授權

This project is MIT licensed. Security vulnerability reports are appreciated and will be credited in release notes (with reporter's permission).
本專案採用 MIT 授權。安全漏洞回報將在發行說明中致謝（經回報者同意）。
