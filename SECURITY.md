# Security Policy / 安全政策

## Reporting Vulnerabilities / 回報漏洞

If you discover a security vulnerability, please report it responsibly.
如果您發現安全漏洞，請負責任地回報。

Email: security@panguard-ai.io

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

## Known Issues / 已知問題

See `progress.md` for current security-related issues and their status.
請參閱 `progress.md` 了解目前安全相關問題及其狀態。
