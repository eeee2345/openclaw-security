# Panguard CLI

> 自動產生 | `./dev-docs/update.sh cli`

## 概述

統一 CLI 入口。整合所有產品線的指令，提供互動選單、身份驗證、方案權限控制。

## 數據

| 項目 | 數據 |
|------|------|
| 套件名 | `@panguard-ai/panguard` |
| 程式碼 | 6684 行 / 32 檔 |
| 測試 | 1 個測試檔 |
| 位置 | `packages/panguard/src/` |

## 架構

```
src/
  cli/
    index.ts          # CLI 入口 (Commander.js)
    interactive.ts     # 互動式選單
    menu.ts           # 箭頭鍵選單系統 (零依賴 ANSI)
    theme.ts          # 色彩主題 + 方案標籤
    auth-guard.ts     # 功能權限 + 定價 + 升級提示
    credentials.ts    # AES-256-GCM 加密憑證
    ux-helpers.ts     # 麵包屑 + 下一步 + 確認
    commands/         # 17 個子命令
  init/               # 初始設定精靈
  manager/            # Manager-Agent 分散式架構
```

## 17 個子命令

| 指令 | 功能 | 方案 |
|------|------|------|
| scan | 安全掃描 | Community |
| guard | 即時防護 | Community |
| threat | Threat Cloud | Community |
| demo | 功能展示 | Community |
| setup/init | 初始設定 | Community |
| status | 系統狀態 | Community |
| login/logout/whoami | 帳號管理 | Community |
| chat | 通知設定 | Solo+ |
| trap | 蜜罐管理 | Solo+ |
| hardening | 安全強化 | Solo+ |
| report | 合規報告 | Business |
| admin | 管理後台 | Admin |
| serve | API 伺服器 | - |
| deploy | Threat Cloud 部署 | - |
| manager | 分散式管理 | - |

## 互動模式特性

- 箭頭鍵選單 (無第三方依賴)
- 麵包屑路徑指示器
- 動態模組計數 (`3/6 unlocked`)
- 操作完成後下一步引導
- 首次用戶偵測 + 引導
- 破壞性操作確認
- 正面優先的功能呈現

## 依賴

- `commander` - CLI 框架
- 所有其他 `@panguard-ai/*` 套件 (workspace)

## 待辦

- [ ] Tab 自動完成
- [ ] 指令別名
- [ ] 設定檔 (~/.panguard/config.json)
