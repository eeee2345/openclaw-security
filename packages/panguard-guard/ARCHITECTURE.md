# PanguardGuard Architecture

## Detection Pipeline

PanguardGuard processes security events through a 5-stage pipeline:

```
SecurityEvent
    |
    v
[1. DETECT] ---- Sigma rules + YARA scan + ATR (Agent Threat Rules)
    |
    v
[2. ANALYZE] --- AI-powered threat analysis (optional, tier-gated)
    |
    v
[3. RESPOND] --- Auto-block, alert, quarantine, kill agent
    |
    v
[4. REPORT] ---- Log to audit trail, anonymize for upload
    |
    v
[5. UPLOAD] ---- Anonymized threat data to Threat Cloud (opt-out available)
```

### Stage 1: Detect

Three detection engines run in parallel:

| Engine | Source | Rules | Format |
|--------|--------|-------|--------|
| **Sigma** | Built-in + community + Threat Cloud | ~200+ | Sigma YAML |
| **YARA** | Built-in + custom | ~50+ | YARA rules |
| **ATR** | Built-in (agent-threat-rules package) + custom | 27 | ATR YAML |

ATR rules specifically detect AI agent threats: prompt injection, tool poisoning,
context exfiltration, agent manipulation, privilege escalation, excessive autonomy,
and skill compromise.

### Stage 2: Analyze

When AI analysis is enabled (Solo tier and above), the AnalyzeAgent evaluates
detections against the environment baseline to determine threat severity,
MITRE ATT&CK mapping, and confidence score.

### Stage 3: Respond

The RespondAgent executes response actions based on threat verdict:
- `block_input` / `block_output` -- Block malicious I/O
- `block_tool` -- Prevent tool execution
- `alert` -- Notify operators
- `quarantine_session` -- Isolate agent session
- `kill_agent` -- Terminate agent process
- `snapshot` -- Capture session state for forensics
- `escalate` -- Escalate to human reviewer

### Stage 4: Report

Every event is logged to an append-only audit trail (`events.jsonl`).
For non-benign events, anonymized threat data is generated for Threat Cloud upload.

### Stage 5: Upload

Anonymized data is batched (50 events/batch) and uploaded to Panguard Threat Cloud.
This is fully opt-out: use `--no-telemetry` to disable.

## Graceful Degradation

PanguardGuard operates at 4 levels depending on available resources:

| Level | Available | Detection | Analysis | Response |
|-------|-----------|-----------|----------|----------|
| **L1** | Rules only (offline) | Sigma + YARA + ATR | Rule-based | Auto-block |
| **L2** | + AI model | Full pipeline | AI-powered | Full |
| **L3** | + Threat Cloud | + community rules | + threat intel | + IP blocklist |
| **L4** | + Manager | + distributed | + cross-node | + coordinated |

The system never fails silently. If a component is unavailable, it logs the
degradation and continues with available capabilities.

## ATR Integration

ATR (Agent Threat Rules) provides detection for AI-specific threats.
The `GuardATREngine` wrapper converts `SecurityEvent` objects into `AgentEvent`
format and evaluates them against ATR rules.

```
SecurityEvent.source mapping:
  agent_input / llm_input   -> AgentEvent type: llm_input
  agent_output / llm_output -> AgentEvent type: llm_output
  tool_call / function_call -> AgentEvent type: tool_call
  tool_response / mcp_response -> AgentEvent type: tool_response
  agent_behavior            -> AgentEvent type: agent_behavior
  multi_agent               -> AgentEvent type: multi_agent_message
```

ATR matches are merged into the `DetectionResult` alongside Sigma and YARA matches,
flowing through the same Analyze -> Respond -> Report pipeline.

## Key Files

```
src/
  guard-engine.ts          # Main pipeline orchestrator
  engines/
    atr-engine.ts          # ATR engine wrapper (SecurityEvent -> AgentEvent)
  agent/
    detect-agent.ts        # Stage 1: Sigma rule matching
    analyze-agent.ts       # Stage 2: AI analysis
    respond-agent.ts       # Stage 3: Response execution
    report-agent.ts        # Stage 4: Logging + anonymization
  monitors/
    ebpf-monitor.ts        # eBPF-based system call monitoring
    dpi-monitor.ts         # Deep packet inspection
    memory-scanner.ts      # Memory scanning for injected code
  threat-cloud/
    index.ts               # Threat Cloud client (upload + fetch)
  cli/
    index.ts               # CLI entry point
```
