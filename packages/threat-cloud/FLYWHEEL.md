# Threat Cloud: Collective Immunity Flywheel

How individual scans become collective protection — fully automated, no voting required.

## The Flow

```
User A installs PanGuard
  → Skill Auditor scans installed MCP skills
  → Finds suspicious pattern in "some-mcp-server"
  → POST /api/skill-threats (anonymized hash + findings)
  → Database: confirmations = 1, status = 'pending'

User B independently scans the same skill
  → Same pattern hash matches
  → confirmations = 2, status = 'pending'

User C also reports
  → confirmations = 3
  → status auto-promotes to 'confirmed'

Every 15 minutes: promoteConfirmedProposals()
  → LLM Reviewer checks confirmed proposals
  → If approved: proposal becomes a rule in the rules table
  → status = 'promoted'

Every 1 hour: Guard syncThreatCloud()
  → All users fetch new rules via GET /api/atr-rules
  → New rule is active everywhere

Result: User D installs the same skill
  → Skill Auditor already has the rule
  → Blocked before it can do damage
```

## Why No Voting?

Voting requires:
- UI for users to review threats (complex)
- Users with expertise to judge (rare)
- Enough active voters for quorum (chicken-and-egg)
- Anti-gaming measures (bot prevention)

Automatic consensus requires:
- N >= 3 independent reports with same pattern hash
- LLM review for quality gate
- That's it.

Three independent scanners agreeing is stronger evidence than
three humans clicking a button. The scanners are deterministic
and not susceptible to social engineering.

## Thresholds

| Threshold | Value | Configurable |
|-----------|-------|-------------|
| Confirmations to auto-confirm | 3 | DB constant |
| Promotion cycle interval | 15 min | `PROMOTION_INTERVAL_MS` |
| Guard sync interval | 1 hour | `syncThreatCloud()` |
| LLM review required for promotion | Yes | `llm_review_verdict IS NOT NULL` |
| LLM must approve | Yes | `verdict.approved === true` |

## What Each Component Does

| Component | Role |
|-----------|------|
| Skill Auditor | Scans locally, reports findings |
| Threat Cloud API | Aggregates reports, counts confirmations |
| LLM Reviewer | Quality gate — prevents bad rules from promoting |
| Promotion cron | Converts confirmed+approved proposals to rules |
| Guard sync | Distributes new rules to all users |
| Skill Whitelist | Safe skills confirmed by 3+ reports |
| Skill Blacklist | Dangerous skills aggregated from reports |

## Privacy

- Skill names are hashed (SHA-256) before transmission
- No user data, API keys, or file contents are sent
- Only pattern hashes and risk scores are shared
- Client IP is anonymized (last octet zeroed)
