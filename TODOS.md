# TODOS

Deferred work items from pre-launch review (2026-03-14).

## ~~P1 - Guard Engine Refactor~~ DONE (2026-03-14)

Split guard-engine.ts (1,516 lines) into: rule-loader.ts, rule-sync.ts, event-processor.ts, response-engine.ts, guard-lifecycle.ts

## ~~P2 - serve.ts Refactor~~ DONE (2026-03-14)

Split serve.ts (1,649 lines) into: serve-auth.ts, serve-admin.ts, serve-tc.ts, serve-core.ts, serve-types.ts

## ~~P2 - Validation Consolidation~~ DONE (2026-03-14)

Consolidated with Zod schemas in packages/core/src/validation.ts (commit 25f28cb3)

## ~~P2 - CSP Nonce for Website~~ DONE (already implemented)

middleware.ts generates per-request nonce, builds CSP header, all inline scripts use nonce attribute via getNonce() helper.

## ~~P2 - Memory Monitoring for Guard~~ DONE (already implemented)

All 3 items already exist in guard-engine.ts: checkMemoryPressure() with 60% warning / 80% critical thresholds, consecutive-check tracking, forced GC, and memory_critical event emission.

## ~~P3 - respond-agent.ts Refactor~~ DONE (2026-03-15)

Split respond-agent.ts (1,171 lines) into: types.ts, safety-rules.ts, action-rate-limiter.ts, evidence-extractor.ts, action-manifest.ts, escalation-tracker.ts, os-actions.ts (commit d2a35c82)

## ~~P3 - interactive.ts Refactor~~ DONE (2026-03-15)

Split interactive.ts (1,912 lines) into: lang.ts, menu-defs.ts, render.ts + 5 action files (commit d2a35c82)

## ~~P3 - E2E Test Coverage~~ DONE (2026-03-15)

Added: legal-pages.spec.ts (8 legal pages + zh variants), mobile-responsive.spec.ts (viewport, hamburger, overflow), locale-switch.spec.ts (EN/ZH switching, persistence), enhanced navigation.spec.ts (product pages, footer links, content pages).

## P2 - Merge TC Handler Dual Implementation (L)

`threat-cloud/src/server.ts` and `panguard/src/cli/commands/serve-tc.ts` implement the same 7 API endpoints independently. Now that both share Zod schemas from `@panguard-ai/core`, refactor to extract shared handler logic into a common module to prevent future divergence. Key files: `packages/threat-cloud/src/server.ts`, `packages/panguard/src/cli/commands/serve-tc.ts`, `packages/core/src/utils/validation.ts`.

## P2 - Flywheel Core Component Unit Tests (XL)

The 6 flywheel core components currently have minimal direct test coverage:
- `skill-watcher.ts` (SkillWatcher: config watch, auto-audit trigger, blacklist check)
- `llm-reviewer.ts` (LLM reviewer: analyzeSkills, reviewProposal, parseVerdict)
- `rule-sync.ts` (Rule sync: YARA download, rule file write, path sanitization)
- `server.ts` (TC server: all 7 POST handlers with Zod validation)
- `atr-action-handlers.ts` (ATR actions: quarantine, reduce permissions, path sanitization)
- `os-actions.ts` (OS actions: isolateFile with SAFE_PATHS/DENY_PATHS)

Target: unit tests covering happy path, error path, and edge cases (path traversal, malformed input, LLM failure) for each component.

## P3 - Dashboard WebSocket Token Auth (S)

Guard dashboard WebSocket endpoint (`/ws`) has no authentication. Add token-based auth: generate a one-time token on dashboard page load, validate on WS upgrade, reject unauthenticated connections. Low risk since dashboard binds to localhost, but needed for defense-in-depth.
