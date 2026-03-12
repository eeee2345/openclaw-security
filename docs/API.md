# API Reference

> Complete REST API documentation for all Panguard AI HTTP services.

## Table of Contents

- [Manager API](#manager-api)
  - [Authentication](#manager-authentication)
  - [Rate Limiting](#manager-rate-limiting)
  - [Response Format](#response-format)
  - [Health Check](#get-health)
  - [Agent Management](#agent-management)
  - [Threat Reporting](#threat-reporting)
  - [Dashboard Overview](#dashboard-overview)
  - [Policy Management](#policy-management)
  - [SSE Event Stream](#sse-event-stream)
- [Auth Server API](#auth-server-api)
  - [User Registration](#post-apiauthregister)
  - [Login](#post-apiauthlogin)
  - [Session Management](#session-management)
  - [Password Reset](#password-reset)
  - [GDPR Endpoints](#gdpr-endpoints)
  - [TOTP Two-Factor Authentication](#totp-two-factor-authentication)
  - [Admin Endpoints](#admin-endpoints)
- [Threat Cloud API](#threat-cloud-api)
  - [Threat Data Upload](#post-apithreats)
  - [Trap Intelligence Upload](#post-apitrap-intel)
  - [Rules](#rules-endpoints)
  - [IoC Endpoints](#ioc-endpoints)
  - [Query Endpoints](#query-endpoints)
  - [Feed Endpoints](#feed-endpoints)
  - [Campaign Endpoints](#campaign-endpoints)
  - [Sighting and Audit Endpoints](#sighting-and-audit-endpoints)
- [Guard Agent Client API](#guard-agent-client-api)
- [Error Codes](#error-codes)

---

## Manager API

**Source**: `packages/panguard-manager/src/server.ts`

**Default Port**: `8443`

**Base URL**: `http://<manager-host>:8443`

**Content-Type**: All request and response bodies use `application/json` (except SSE stream).

### Security Headers

All responses include:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 0`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (production only)

### CORS

Controlled via the `CORS_ALLOWED_ORIGINS` environment variable (comma-separated). Wildcard (`*`) is only allowed in non-production environments.

---

### Manager Authentication

All endpoints (except `/health`) require Bearer token authentication.

**Header**: `Authorization: Bearer <token>`

The token is compared against the configured `authToken` using SHA-256 hashing with `crypto.timingSafeEqual` to prevent timing attacks. If no `authToken` is configured, authentication is disabled (development mode only).

```bash
curl -H "Authorization: Bearer YOUR_AUTH_TOKEN" \
     http://localhost:8443/api/agents
```

---

### Manager Rate Limiting

- **Limit**: 60 requests per minute per client IP
- **Window**: 60 seconds (sliding)
- **Response on limit exceeded**: `429 Too Many Requests`

```json
{
  "ok": false,
  "error": "Rate limit exceeded"
}
```

---

### Response Format

All responses follow a consistent envelope format.

**Success**:

```json
{
  "ok": true,
  "data": { ... }
}
```

**Error**:

```json
{
  "ok": false,
  "error": "Human-readable error message"
}
```

---

### GET /health

Health check endpoint. **No authentication required.**

**Response** `200`:

```json
{
  "ok": true,
  "data": {
    "status": "healthy",
    "uptime": 3600.5,
    "agents": 12,
    "running": true
  }
}
```

---

### Agent Management

#### POST /api/agents/register

Register a new Guard agent with the Manager.

**Request Body**:

```json
{
  "hostname": "web-server-01",
  "os": "linux",
  "arch": "x64",
  "version": "1.0.0",
  "ip": "192.168.1.100",
  "organizationId": "org-abc123"
}
```

| Field            | Type     | Required | Description                                   |
| ---------------- | -------- | -------- | --------------------------------------------- |
| `hostname`       | `string` | Yes      | Agent hostname                                |
| `os`             | `string` | Yes      | Operating system (`linux`, `darwin`, `win32`) |
| `arch`           | `string` | Yes      | CPU architecture (`x64`, `arm64`)             |
| `version`        | `string` | Yes      | Guard agent version                           |
| `ip`             | `string` | No       | Agent IP address                              |
| `organizationId` | `string` | No       | Organization ID for multi-tenant deployments  |

**Response** `201`:

```json
{
  "ok": true,
  "data": {
    "agentId": "agt-1709000000-abc123",
    "hostname": "web-server-01",
    "platform": { "os": "linux", "arch": "x64", "ip": "192.168.1.100" },
    "version": "1.0.0",
    "registeredAt": "2026-03-03T00:00:00.000Z",
    "lastHeartbeat": "2026-03-03T00:00:00.000Z",
    "status": "online",
    "organizationId": "org-abc123"
  }
}
```

**Errors**: `400` missing fields, `409` max agents exceeded.

**SSE Broadcast**: `agent_online`

---

#### POST /api/agents/:id/heartbeat

Send a heartbeat from a Guard agent.

**Request Body**:

```json
{
  "timestamp": "2026-03-03T00:01:00.000Z",
  "cpuUsage": 23.5,
  "memUsage": 45.2,
  "activeMonitors": 6,
  "threatCount": 3,
  "eventsProcessed": 1500,
  "mode": "protection",
  "uptime": 86400
}
```

| Field             | Type     | Description                                     |
| ----------------- | -------- | ----------------------------------------------- |
| `timestamp`       | `string` | ISO 8601 timestamp                              |
| `cpuUsage`        | `number` | CPU usage percentage                            |
| `memUsage`        | `number` | Memory usage percentage                         |
| `activeMonitors`  | `number` | Number of active monitors                       |
| `threatCount`     | `number` | Total threats detected                          |
| `eventsProcessed` | `number` | Total events processed                          |
| `mode`            | `string` | Current guard mode (`learning` or `protection`) |
| `uptime`          | `number` | Agent uptime in milliseconds                    |

**Response** `200`: Updated agent registration.

**Errors**: `400` invalid body, `404` agent not found.

---

#### DELETE /api/agents/:id

Deregister a Guard agent.

**Response** `200`:

```json
{
  "ok": true,
  "data": { "agentId": "agt-123", "removed": true }
}
```

**SSE Broadcast**: `agent_offline`

---

#### GET /api/agents

List all registered agents. Supports `?org_id=` for organization filtering (requires database).

**Response** `200`: Array of agent objects.

---

#### GET /api/agents/:id

Get details for a single agent.

**Response** `200`: Full `AgentRegistration` object. `404` if not found.

---

### Threat Reporting

#### POST /api/agents/:id/events

Submit threat events from a Guard agent.

**Request Body**:

```json
{
  "threats": [
    {
      "event": {
        "id": "evt-001",
        "source": "network",
        "category": "intrusion",
        "severity": "high",
        "description": "Suspicious inbound connection from known C2 server",
        "timestamp": "2026-03-03T00:00:00.000Z",
        "host": "web-server-01",
        "metadata": { "sourceIP": "203.0.113.50", "destPort": 4444 },
        "raw": {}
      },
      "verdict": {
        "conclusion": "malicious",
        "confidence": 92,
        "action": "block_ip"
      }
    }
  ],
  "reportedAt": "2026-03-03T00:00:01.000Z"
}
```

**Response** `200`:

```json
{
  "ok": true,
  "data": {
    "accepted": 1,
    "threats": [
      {
        "id": "agg-1709000000-xyz789",
        "originalThreat": { ... },
        "sourceAgentId": "agt-123",
        "sourceHostname": "web-server-01",
        "receivedAt": "2026-03-03T00:00:01.000Z",
        "correlatedWith": ["agg-1709000000-abc456"]
      }
    ]
  }
}
```

**SSE Broadcast**: `threats_reported`

**Cross-Agent Correlation**: The `ThreatAggregator` correlates by same source IP, malware hash, and attack pattern.

---

#### GET /api/threats

Get recent threats. Supports `?since=` (ISO 8601, default 1h ago) and `?org_id=`.

---

#### GET /api/threats/summary

Aggregated threat summary.

**Response** `200`:

```json
{
  "ok": true,
  "data": {
    "totalThreats": 150,
    "criticalCount": 5,
    "highCount": 23,
    "suspiciousCount": 45,
    "uniqueAttackers": 12,
    "affectedAgents": 8,
    "correlatedGroups": 3
  }
}
```

---

### Dashboard Overview

#### GET /api/overview

Comprehensive dashboard overview. Supports `?org_id=`.

**Response** `200`:

```json
{
  "ok": true,
  "data": {
    "totalAgents": 12,
    "onlineAgents": 10,
    "staleAgents": 1,
    "offlineAgents": 1,
    "agents": [
      {
        "agentId": "agt-123",
        "hostname": "web-server-01",
        "status": "online",
        "lastHeartbeat": "2026-03-03T00:01:00.000Z",
        "threatCount": 3
      }
    ],
    "threatSummary": { ... },
    "activePolicyVersion": 5,
    "uptimeMs": 86400000
  }
}
```

---

### Policy Management

#### POST /api/policy

Create a new security policy and optionally broadcast to all active agents.

**Request Body**:

```json
{
  "rules": [
    {
      "ruleId": "pol-001",
      "type": "block_ip",
      "condition": { "ip": "203.0.113.50" },
      "action": "block",
      "severity": "critical",
      "description": "Block known C2 server"
    }
  ],
  "broadcast": true
}
```

**Policy Rule Types**: `block_ip`, `alert_threshold`, `auto_respond`, `custom`

**Response** `201`:

```json
{
  "ok": true,
  "data": {
    "policyId": "pol-1709000000-abc123",
    "version": 6,
    "rules": [ ... ],
    "updatedAt": "2026-03-03T00:00:00.000Z",
    "appliedTo": ["agt-123", "agt-456", "agt-789"]
  }
}
```

**SSE Broadcast**: `policy_created`

---

#### GET /api/policy/active

Get the currently active global policy. Returns `data: null` if none.

---

#### GET /api/policy/agent/:id

Get the policy applicable to a specific agent (may include agent-specific overrides).

---

### SSE Event Stream

#### GET /api/events/stream

Server-Sent Events connection for real-time updates.

**Response Headers**:

```
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
X-Accel-Buffering: no
```

**Keep-Alive**: Comment (`:keep-alive`) sent every 30 seconds.

**Event Types**:

| Event Type         | Trigger                | Data                          |
| ------------------ | ---------------------- | ----------------------------- |
| `connected`        | Connection established | `{ timestamp }`               |
| `agent_online`     | New agent registers    | `{ agentId, hostname }`       |
| `agent_offline`    | Agent deregisters      | `{ agentId }`                 |
| `threats_reported` | Threats submitted      | `{ agentId, count, threats }` |
| `policy_created`   | New policy created     | `{ policyId, version }`       |

**Event Format**:

```
data: {"type":"threats_reported","data":{...},"timestamp":"2026-03-03T00:00:00.000Z"}
```

```bash
curl -N -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8443/api/events/stream
```

---

## Auth Server API

**Source**: `packages/panguard-auth/src/routes/`

**Default Port**: `3000`

All auth endpoints use the same `{ ok, data/error }` envelope format. Rate limiting is per-IP with configurable windows.

---

### POST /api/auth/register

Register a new user account.

**Request Body**:

```json
{
  "email": "user@example.com",
  "name": "John Doe",
  "password": "securePassword123"
}
```

| Field      | Type     | Validation                 |
| ---------- | -------- | -------------------------- |
| `email`    | `string` | Must be valid email format |
| `name`     | `string` | Required, non-empty        |
| `password` | `string` | 8-128 characters           |

**Response** `201`:

```json
{
  "ok": true,
  "data": {
    "user": {
      "id": 1,
      "email": "user@example.com",
      "name": "John Doe",
      "role": "user"
    },
    "token": "session-token-here",
    "expiresAt": "2026-03-10T00:00:00.000Z"
  }
}
```

**Security**: Duplicate email returns `200` with generic message (prevents account enumeration). Dummy password hash is performed for timing safety.

---

### POST /api/auth/login

Authenticate with email and password. Supports TOTP 2FA.

**Request Body**:

```json
{
  "email": "user@example.com",
  "password": "securePassword123",
  "totpCode": "123456",
  "backupCode": "ABCDEF12"
}
```

| Field        | Type     | Required    | Description              |
| ------------ | -------- | ----------- | ------------------------ |
| `email`      | `string` | Yes         | User email               |
| `password`   | `string` | Yes         | User password            |
| `totpCode`   | `string` | Conditional | Required if 2FA enabled  |
| `backupCode` | `string` | Conditional | Alternative to TOTP code |

**Response when 2FA required** `200`:

```json
{
  "ok": true,
  "data": {
    "requiresTwoFactor": true,
    "message": "Two-factor authentication required. Send totpCode or backupCode."
  }
}
```

**Response on success** `200`:

```json
{
  "ok": true,
  "data": {
    "user": { ... },
    "token": "session-token-here",
    "expiresAt": "2026-03-10T00:00:00.000Z"
  }
}
```

**Security**: Suspended accounts receive `403`. Timing-safe password comparison prevents enumeration.

---

### Session Management

#### POST /api/auth/logout

Invalidate the current session.

**Headers**: `Authorization: Bearer <token>`

**Response** `200`:

```json
{ "ok": true, "data": { "message": "Logged out" } }
```

#### GET /api/auth/me

Get the authenticated user's profile.

**Response** `200`: Public user object.

---

### Password Reset

#### POST /api/auth/forgot-password

Request a password reset link.

**Request Body**: `{ "email": "user@example.com" }`

**Response** `200`: Always returns success to prevent email enumeration. Reset email is sent if configured (SMTP settings required).

#### POST /api/auth/reset-password

Complete a password reset.

**Request Body**:

```json
{
  "token": "reset-token-from-email",
  "password": "newSecurePassword123"
}
```

**Response** `200`: Invalidates all existing sessions (forces re-login).

---

### GDPR Endpoints

#### DELETE /api/auth/delete-account

Permanently delete the authenticated user's account and all data. Requires password confirmation.

**Request Body**: `{ "password": "currentPassword" }`

**Response** `200`:

```json
{
  "ok": true,
  "data": {
    "message": "Account permanently deleted.",
    "tablesAffected": ["users", "sessions", "usage_events", ...]
  }
}
```

**Safety**: Prevents deletion of the only admin account.

#### GET /api/auth/export-data

Export all data belonging to the authenticated user (GDPR portability).

**Response**: Downloadable JSON file with `Content-Disposition` header.

---

### TOTP Two-Factor Authentication

The auth server supports TOTP-based two-factor authentication with backup codes. Endpoints include:

- **POST /api/auth/totp/setup** -- Generate TOTP secret and QR code
- **POST /api/auth/totp/verify** -- Verify TOTP code to enable 2FA
- **POST /api/auth/totp/disable** -- Disable 2FA (requires password)

---

### Admin Endpoints

All admin endpoints require `role: "admin"` authentication.

| Method   | Path                           | Description                           |
| -------- | ------------------------------ | ------------------------------------- |
| `GET`    | `/api/admin/users`             | List all users                        |
| `GET`    | `/api/admin/users/search?q=`   | Search users                          |
| `GET`    | `/api/admin/users/:id`         | User detail with usage/sessions/audit |
| `PATCH`  | `/api/admin/users/:id/tier`    | Update user role level                |
| `PATCH`  | `/api/admin/users/:id/role`    | Update user role                      |
| `PATCH`  | `/api/admin/users/:id/suspend` | Suspend/unsuspend user                |
| `GET`    | `/api/admin/stats`             | User and waitlist statistics          |
| `GET`    | `/api/admin/dashboard`         | Admin dashboard stats                 |
| `GET`    | `/api/admin/sessions`          | Active sessions                       |
| `DELETE` | `/api/admin/sessions/:id`      | Revoke session                        |
| `GET`    | `/api/admin/activity?limit=`   | Recent activity                       |
| `GET`    | `/api/admin/audit-log`         | Filtered audit log                    |
| `GET`    | `/api/admin/audit-log/actions` | Distinct audit actions                |
| `GET`    | `/api/admin/usage`             | Usage overview by user and tier       |
| `GET`    | `/api/admin/usage/:userId`     | Per-user usage detail                 |
| `POST`   | `/api/admin/bulk-action`       | Bulk operations (max 100 users)       |

**Bulk Action Types**: `change_role`, `suspend`, `unsuspend`

**Bulk Action Request**:

```json
{
  "userIds": [1, 2, 3],
  "action": "change_role",
  "value": "admin"
}
```

---

## Threat Cloud API

**Source**: `packages/threat-cloud/src/server.ts`

**Default Port**: Configurable via `ServerConfig`

**Authentication**: API key via `Authorization: Bearer <api-key>`. Keys are hashed with SHA-256 and compared with `timingSafeEqual`. Write endpoints always require authentication. Read-only endpoints optionally require it (configurable).

**Rate Limiting**: Per-IP (configurable), per-API-key (30 req/min for writes).

---

### POST /api/threats

Upload anonymized threat data. Supports single event and batch formats.

**Single Event**:

```json
{
  "attackSourceIP": "203.0.113.50",
  "attackType": "brute_force",
  "mitreTechnique": "T1110",
  "sigmaRuleMatched": "sigma_brute_force_ssh",
  "timestamp": "2026-03-03T00:00:00.000Z",
  "region": "TW",
  "industry": "technology"
}
```

**Batch Format** (max 100 events):

```json
{
  "events": [
    { "attackSourceIP": "...", ... },
    { "attackSourceIP": "...", ... }
  ]
}
```

**Response** `201`:

```json
{
  "ok": true,
  "data": {
    "message": "Threat data received",
    "enrichedId": 42
  }
}
```

IP addresses are automatically /16-anonymized (GDPR compliant). IoCs are extracted and added to the IoC store.

---

### POST /api/trap-intel

Upload honeypot intelligence data. Supports single and batch (max 100).

**Request Body**:

```json
{
  "sourceIP": "203.0.113.50",
  "attackType": "credential_harvesting",
  "timestamp": "2026-03-03T00:00:00.000Z",
  "mitreTechniques": ["T1110", "T1021"],
  "serviceType": "ssh",
  "skillLevel": "intermediate",
  "intent": "credential_harvesting",
  "region": "TW",
  "topCredentials": [
    { "username": "root", "count": 50 },
    { "username": "admin", "count": 30 }
  ]
}
```

---

### Rules Endpoints

#### GET /api/rules

Fetch community Sigma rules. Supports `?since=<ISO timestamp>` filter.

#### POST /api/rules

Publish a new community rule. Requires API key. Rule content must be valid Sigma YAML (max 64KB).

**Request Body**:

```json
{
  "ruleId": "community-rule-001",
  "ruleContent": "title: SSH Brute Force\ndetection:\n  condition: ...",
  "source": "community",
  "publishedAt": "2026-03-03T00:00:00.000Z"
}
```

---

### IoC Endpoints

#### GET /api/iocs

Search IoCs with filters.

| Parameter       | Type     | Description                           |
| --------------- | -------- | ------------------------------------- |
| `type`          | `string` | `ip`, `domain`, `hash`, `url`         |
| `source`        | `string` | `guard`, `trap`, `external`           |
| `minReputation` | `number` | Minimum reputation score (0-100)      |
| `status`        | `string` | `active`, `expired`, `false_positive` |
| `since`         | `string` | ISO timestamp                         |
| `search`        | `string` | Free-text search                      |
| `page`          | `number` | Page number (default 1)               |
| `limit`         | `number` | Results per page (default 50)         |

#### GET /api/iocs/:value

Lookup a single IoC with context (related threat count, sightings).

---

### Query Endpoints

| Method | Path                       | Description                | Parameters                                           |
| ------ | -------------------------- | -------------------------- | ---------------------------------------------------- |
| `GET`  | `/api/stats`               | Enhanced threat statistics | --                                                   |
| `GET`  | `/api/query/timeseries`    | Time series data           | `granularity` (hour/day/week), `since`, `attackType` |
| `GET`  | `/api/query/geo`           | Geographic distribution    | `since`                                              |
| `GET`  | `/api/query/trends`        | Threat trends              | `periodDays` (default 7)                             |
| `GET`  | `/api/query/mitre-heatmap` | MITRE ATT&CK heatmap       | `since`                                              |

---

### Feed Endpoints

| Method | Path                          | Response Type      | Description                                                 |
| ------ | ----------------------------- | ------------------ | ----------------------------------------------------------- |
| `GET`  | `/api/feeds/ip-blocklist`     | `text/plain`       | IP blocklist (one per line). `?minReputation=` (default 70) |
| `GET`  | `/api/feeds/domain-blocklist` | `text/plain`       | Domain blocklist. `?minReputation=` (default 70)            |
| `GET`  | `/api/feeds/iocs`             | `application/json` | IoC feed. `?minReputation=`, `?limit=`, `?since=`           |
| `GET`  | `/api/feeds/agent-update`     | `application/json` | Agent update bundle (rules + IoCs). `?since=`               |

---

### Campaign Endpoints

| Method | Path                   | Description                                     |
| ------ | ---------------------- | ----------------------------------------------- |
| `GET`  | `/api/campaigns`       | List campaigns. `?page=`, `?limit=`, `?status=` |
| `GET`  | `/api/campaigns/stats` | Campaign statistics                             |
| `GET`  | `/api/campaigns/:id`   | Campaign detail with associated events          |

---

### Sighting and Audit Endpoints

#### POST /api/sightings

Record a sighting (positive, negative, or false_positive) for an IoC.

**Request Body**:

```json
{
  "iocId": 42,
  "type": "positive",
  "source": "guard-agent-01",
  "details": "Confirmed C2 communication"
}
```

#### GET /api/sightings

Get sightings for an IoC. Required: `?iocId=`. Supports `?page=`, `?limit=`.

#### GET /api/audit-log

Query the audit log. Filters: `?action=`, `?entityType=`, `?entityId=`, `?since=`, `?limit=`.

---

## Guard Agent Client API

The `PanguardAgentClient` (`packages/panguard-guard/src/agent-client/`) manages communication between a Guard agent and the Manager server.

**Programmatic API**:

```typescript
import { PanguardAgentClient } from '@panguard-ai/panguard-guard';

const client = new PanguardAgentClient({
  managerUrl: 'http://manager:8443',
  authToken: 'your-token',
  hostname: 'web-server-01',
  os: 'linux',
  arch: 'x64',
  version: '1.0.0',
});

// Register with Manager
const registration = await client.register();

// Send heartbeat
await client.heartbeat({
  cpuUsage: 23.5,
  memUsage: 45.2,
  activeMonitors: 6,
  threatCount: 3,
  eventsProcessed: 1500,
  mode: 'protection',
  uptime: 86400,
});

// Report threats
await client.reportThreats(threatEvents);

// Poll for policy updates
const policy = await client.getPolicy();

// Deregister
await client.deregister();
```

---

## Error Codes

| HTTP Status | Meaning                                                               |
| ----------- | --------------------------------------------------------------------- |
| `200`       | Success                                                               |
| `201`       | Created (registration, policy, rule)                                  |
| `204`       | No Content (OPTIONS preflight)                                        |
| `400`       | Bad Request -- missing or invalid fields                              |
| `401`       | Unauthorized -- missing or invalid authentication                     |
| `403`       | Forbidden -- insufficient permissions or suspended account            |
| `404`       | Not Found -- resource or endpoint not found                           |
| `405`       | Method Not Allowed                                                    |
| `409`       | Conflict -- duplicate or constraint violation                         |
| `413`       | Payload Too Large                                                     |
| `415`       | Unsupported Media Type -- POST without `application/json`             |
| `429`       | Too Many Requests -- rate limit exceeded                              |
| `500`       | Internal Server Error                                                 |
| `503`       | Service Unavailable -- server not configured (e.g., missing API keys) |
