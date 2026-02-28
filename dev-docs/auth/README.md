# Panguard Auth

> 自動產生 | `./dev-docs/update.sh auth`

## 概述

認證與帳號管理系統。Waitlist、註冊登入、Google OAuth (PKCE)、CLI Token 交換、管理後台 API。

## 數據

| 項目 | 數據 |
|------|------|
| 套件名 | `@panguard-ai/panguard-auth` |
| 程式碼 | 2422 行 / 10 檔 |
| 測試 | 5 個測試檔 |
| 匯出 | 20+ 函數 + 15+ 型別 |
| 位置 | `packages/panguard-auth/src/` |

## 主要模組

| 模組 | 路徑 | 功能 |
|------|------|------|
| Auth | `src/auth.ts` | scrypt 密碼雜湊 / Session Token / 驗證 Token |
| Database | `src/database.ts` | SQLite — waitlist, users, sessions, purchases, audit |
| Routes | `src/routes.ts` | 32 個 HTTP 路由處理器 |
| Middleware | `src/middleware.ts` | Bearer Token 驗證 + Admin 檢查 |
| Email | `src/email-verify.ts` | 原生 SMTP + STARTTLS 驗證信 |
| OAuth | `src/google-oauth.ts` | Google OAuth 2.0 + PKCE (RFC 7636) |
| Sheets | `src/google-sheets.ts` | Waitlist → Google Sheets 同步 |
| Rate Limit | `src/rate-limiter.ts` | 滑動窗口速率限制 |

## 路由清單

| 類別 | 路由數 | 功能 |
|------|--------|------|
| Waitlist | 4 | 加入 / 驗證 / 統計 / 清單 |
| Auth | 5 | 註冊 / 登入 / 登出 / me / CLI 交換 |
| OAuth | 3 | Google 授權 / Callback / CLI Auth |
| Admin Users | 6 | 列表 / 搜尋 / 更新方案 / 更新角色 / 儀表板 / Sessions |
| Admin Waitlist | 2 | 核准 / 拒絕 |
| Admin Sessions | 2 | 列表 / 撤銷 |
| Admin Analytics | 1 | 活動記錄 |

## 安全特性

- scrypt 密碼雜湊 (N=16384, r=8, p=1)
- Timing-safe 比較 (防時序攻擊)
- PKCE for OAuth (防 CSRF)
- Session 過期 (Web: 24hr, CLI: 30 天)
- 請求大小限制 (1 MB)
- 稽核日誌

## 資料表

| 表名 | 用途 |
|------|------|
| waitlist | 等候名單 (email, 驗證狀態, 來源) |
| users | 用戶 (密碼, 方案, 角色, 到期日) |
| sessions | 登入 Session |
| report_purchases | 報告購買記錄 |
| audit_log | 操作稽核 |

## 依賴

- `@panguard-ai/security-hardening` - 安全庫
- `better-sqlite3` - SQLite
- Node.js 內建 (crypto, net, tls)

## 待辦

- [ ] Refresh Token 機制
- [ ] 密碼重設流程
- [ ] MFA (TOTP)
