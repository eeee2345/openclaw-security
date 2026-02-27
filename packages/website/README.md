# @panguard-ai/website

Official website for [Panguard AI](https://panguard.ai) -- AI-powered endpoint security for developers and SMBs.

## Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Styling**: Tailwind CSS + Framer Motion
- **i18n**: `next-intl` (English / Traditional Chinese)
- **Icons**: Lucide React
- **Package manager**: pnpm (monorepo workspace)

## Getting Started

```bash
# From the monorepo root
pnpm install
pnpm run website:dev

# Or from this package directly
pnpm dev
```

The site runs at [http://localhost:3000](http://localhost:3000).

## Project Structure

```
src/
  app/
    [locale]/          # Locale-scoped pages (en, zh)
      (home)/          # Homepage sections
      contact/         # Contact form
      demo/            # Demo request
      legal/           # Privacy, Terms, DPA, SLA, etc.
      pricing/         # Pricing page
      product/         # Product sub-pages (scan, guard, chat, trap, report)
      solutions/       # Industry solutions
    api/               # API routes (contact, demo, scan, waitlist)
  components/
    home/              # Homepage section components
    layout/            # NavBar, Footer, etc.
    product/           # Product page components
    ui/                # Shared UI primitives (BrandLogo, SectionWrapper, etc.)
  lib/                 # Utilities (validate, rate-limit, remote-scan, sheets, constants)
  messages/            # i18n JSON (en.json, zh.json)
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `LEAD_WEBHOOK_URL` | No | Webhook URL for lead capture (Zapier, Make, etc.) |

## Scripts

| Script | Description |
|---|---|
| `pnpm dev` | Start dev server |
| `pnpm build` | Production build |
| `pnpm start` | Start production server |
| `pnpm lint` | Run ESLint |
| `pnpm typecheck` | Run TypeScript type checking |

## License

See [LICENSE](../../LICENSE) in the monorepo root.
