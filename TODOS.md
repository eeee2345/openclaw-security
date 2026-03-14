# TODOS

Deferred work items from pre-launch review (2026-03-14).

## P1 - Guard Engine Refactor

**guard-engine.ts** (1,516 lines) is a god object. Extract into focused modules:

- [ ] `rule-loader.ts` -- Sigma/YARA/ATR rule loading and parsing
- [ ] `rule-sync.ts` -- Threat Cloud sync (1-hour interval, retry logic)
- [ ] `event-processor.ts` -- Event matching pipeline (Layer 1-3)
- [ ] `response-engine.ts` -- Confidence-based response (log/notify/execute)
- [ ] `guard-lifecycle.ts` -- Start/stop/health/status orchestration

**Why:** Single 1,500-line file is hard to test, review, and extend. Each module should be <400 lines.

**Effort:** L (3-5 sessions)

## P2 - serve.ts Refactor

**serve.ts** (1,649 lines) -- CLI server command, second largest file:

- [ ] Extract auth route handlers into `serve-auth.ts`
- [ ] Extract admin route handlers into `serve-admin.ts`
- [ ] Extract Threat Cloud route handlers into `serve-tc.ts`
- [ ] Extract health/static/middleware into `serve-core.ts`

**Why:** Actively modified (billing removal touched it), growing. Hard to review at 1,600+ lines.

**Effort:** M (1-2 sessions)

## P2 - Validation Consolidation

Input validation is scattered across packages. Consolidate into `packages/core/src/validation.ts`:

- [ ] Rule schema validation (ATR, Sigma, YARA)
- [ ] Config validation (guard, scan, CLI)
- [ ] API input validation (threat-cloud endpoints)

**Why:** DRY. Same validation logic duplicated in 3+ places.

**Effort:** M (1-2 sessions)

## P2 - CSP Nonce for Website

Add Content-Security-Policy with nonce-based script loading:

- [ ] Next.js middleware to generate nonce per request
- [ ] Apply nonce to inline scripts (jsonLd, js-ready, Plausible)
- [ ] Add CSP headers (script-src, style-src, connect-src)

**Why:** Hardens against XSS. Currently no CSP headers.

**Effort:** S (1 session)

## P2 - Memory Monitoring for Guard

Guard daemon runs long-lived. Add memory monitoring:

- [ ] Track heap usage in guard status output
- [ ] Warn when heap exceeds 80% of limit
- [ ] Graceful restart on OOM risk

**Why:** Guard runs 24/7. Memory leaks will eventually crash it.

**Effort:** S (1 session)

## P3 - respond-agent.ts Refactor

**respond-agent.ts** (1,171 lines) -- another god object:

- [ ] Extract prompt templates into separate files
- [ ] Extract tool definitions into a registry
- [ ] Separate LLM call logic from response formatting

**Effort:** M (1-2 sessions)

## P3 - interactive.ts Refactor

**interactive.ts** (1,912 lines) -- CLI interactive mode:

- [ ] Extract command handlers into individual files
- [ ] Extract prompt/display helpers
- [ ] Add command registry pattern

**Effort:** L (2-3 sessions)

## P3 - E2E Test Coverage

Current E2E covers public pages only. Add:

- [ ] Navigation flow (header links, footer links, locale switch)
- [ ] Mobile responsive checks (hamburger menu, layout)
- [ ] 404 page verification
- [ ] All legal pages (privacy, terms, SLA)

**Effort:** M (1-2 sessions)
