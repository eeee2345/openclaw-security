# PanguardGuard Privacy Policy

## Threat Intelligence Sharing

By default, PanguardGuard uploads **anonymized** threat data to Panguard Threat Cloud.
This creates a collective defense network: every installation contributes to and
benefits from shared threat intelligence.

**You can fully opt out** with `--no-telemetry`:

```bash
panguard-guard start --no-telemetry
```

## What Is Uploaded

When a threat is detected, the following anonymized data is uploaded:

| Field | Example | Contains PII? |
|-------|---------|---------------|
| `attackSourceIP` | `192.168.xxx.xxx` | No (last two octets masked) |
| `attackType` | `prompt-injection` | No |
| `mitreTechnique` | `T1059` | No |
| `sigmaRuleMatched` | `sigma-001,sigma-042` | No |
| `atrRulesMatched` | `ATR-2026-001,ATR-2026-010` | No |
| `atrCategory` | `prompt-injection` | No |
| `timestamp` | `2026-03-08T12:00:00Z` | No |
| `region` | `US` | No (country only) |
| `severity` | `high` | No |
| `autoResponseTaken` | `block_input` | No |
| `panguardVersion` | `0.1.0` | No |
| `osType` | `linux` | No |
| `patternHash` | `a1b2c3...` | No (SHA-256 of pattern) |
| `confidence` | `0.85` | No |

### What Is NOT Uploaded

- User prompts or LLM inputs/outputs
- File contents or file paths
- API keys, tokens, or credentials
- Hostnames, usernames, or process names
- Full IP addresses (last two octets always masked)
- Any personally identifiable information (PII)

## Verifying Upload Data

Use `--show-upload-data` to see exactly what is uploaded before it is sent:

```bash
panguard-guard start --show-upload-data
```

This prints the full JSON payload to the console before each upload, so you can
verify that no sensitive data is included.

## Anonymization Method

### IP Addresses

Source IPs are anonymized by masking the last two octets:
- `10.0.45.123` becomes `10.0.xxx.xxx`

This preserves network-level correlation (same /16 subnet) while preventing
identification of specific hosts.

### Pattern Hashing

Attack patterns are SHA-256 hashed. The hash allows Threat Cloud to correlate
similar attacks across installations without storing the actual attack content.

## Data Flow

```
[Guard Engine]
    | threat detected
    v
[Report Agent]
    | anonymize: mask IP, hash patterns, strip PII
    v
[Threat Cloud Client]
    | batch upload (50 events/batch, HTTPS)
    v
[Panguard Threat Cloud]
    | aggregate, generate community rules
    v
[Guard Engine]
    | hourly sync: fetch new community rules
    v
[Better protection for everyone]
```

## Data Retention

Uploaded threat data is retained in Panguard Threat Cloud for 90 days, after which
it is automatically purged. Aggregated statistics (rule hit counts, regional trends)
are retained indefinitely but contain no per-event data.

## Open Source Verification

All anonymization logic is open source and auditable:

- Anonymization: `src/agent/report-agent.ts` (`generateAnonymizedData()`)
- Upload client: `src/threat-cloud/index.ts`
- ATR rules: [github.com/panguard-ai/agent-threat-rules](https://github.com/panguard-ai/agent-threat-rules)
