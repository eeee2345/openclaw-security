# Panguard Website

> 自動產生 | `./dev-docs/update.sh website`

## 概述

官方行銷網站。Next.js 14 App Router，雙語 (EN/ZH)，41 頁，Framer Motion 動畫。

## 數據

| 項目 | 數據 |
|------|------|
| 套件名 | `packages/website` |
| 程式碼 | 15997 行 / 140 檔 |
| 測試 | 2 個測試檔 |
| 位置 | `packages/website/src/` |
| 部署 | Vercel |

## 頁面結構

| 區塊 | 頁面數 | 內容 |
|------|--------|------|
| 首頁 | 1 | Hero + 20 個元件 |
| 產品 | 6 | product, scan, guard, chat, trap, report |
| 方案 | 3 | developers, smb, enterprise |
| 法律 | 8 | terms, privacy, cookies, sla, dpa, security, acceptable-use, responsible-disclosure |
| 文件 | 3 | docs, getting-started, api |
| 其他 | 20 | pricing, blog, changelog, company, careers, contact, demo, trust, status... |

## 技術架構

| 層級 | 技術 |
|------|------|
| 框架 | Next.js 14 (App Router) |
| 樣式 | Tailwind CSS |
| 動畫 | Framer Motion |
| 圖示 | Lucide React |
| 國際化 | next-intl (EN/ZH) |
| 路由 | `[locale]/` 動態路由 |

## 元件分類

| 類別 | 數量 | 包含 |
|------|------|------|
| 首頁元件 | 20 | Hero, Pricing, ProductGrid, TechReveal, TrustLayer... |
| UI 元件 | 10 | Button, Card, BrandLogo, CLIShowcase, SectionTitle... |
| 動畫元件 | 4 | CountUp, FadeIn, RevealText, StaggerGroup |
| Hooks | 2 | useInViewport, useScrollReveal |

## API 路由

| 路徑 | 功能 |
|------|------|
| `/api/contact` | 聯絡表單提交 |
| `/api/demo` | Demo 預約 |
| `/api/waitlist` | 加入等候名單 |
| `/api/install` | 安裝指令 (含 Windows) |

## 依賴

- `next` 14.2.35
- `react` ^18
- `next-intl` ^4.8.3
- `framer-motion` ^12.34.3
- `lucide-react` ^0.575.0
- `tailwindcss` ^3.4.1

## 待辦

- [ ] Blog CMS 整合
- [ ] 客戶案例頁面內容
- [ ] 效能優化 (圖片 lazy loading)
