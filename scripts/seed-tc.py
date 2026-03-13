#!/usr/bin/env python3
"""Seed rules from local config/ to tc.panguard.ai via batch API."""

import json
import os
import sys
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

TC = "https://tc.panguard.ai"
BATCH_SIZE = 100  # rules per request
ROOT = Path(__file__).resolve().parent.parent


def post_batch(rules: list[dict]) -> int:
    """POST a batch of rules, return count uploaded."""
    body = json.dumps({"rules": rules}).encode("utf-8")
    req = urllib.request.Request(
        f"{TC}/api/rules",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
            return result.get("data", {}).get("count", 0)
    except Exception as e:
        print(f"    ERROR: {e}")
        return 0


def collect_and_seed(source: str, directory: Path, extensions: set[str]) -> int:
    """Collect rule files and seed them in batches."""
    files = []
    for ext in extensions:
        files.extend(directory.rglob(f"*.{ext}"))
    files.sort()

    print(f"  Found {len(files)} files")
    if not files:
        return 0

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    batch: list[dict] = []
    total = 0

    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        rel = f.relative_to(directory)
        rule_id = f"{source}:{str(rel).replace('/', ':')}"

        batch.append({
            "ruleId": rule_id,
            "ruleContent": content,
            "source": source,
            "publishedAt": now,
        })

        if len(batch) >= BATCH_SIZE:
            count = post_batch(batch)
            total += count
            print(f"    Uploaded {total} / {len(files)}")
            batch = []

    if batch:
        count = post_batch(batch)
        total += count
        print(f"    Uploaded {total} / {len(files)}")

    return total


def main():
    print(f"Seeding rules to {TC}")
    print()

    grand_total = 0

    # Sigma
    sigma_dir = ROOT / "config" / "sigma-rules"
    if sigma_dir.exists():
        print("=== Sigma Rules ===")
        n = collect_and_seed("sigma", sigma_dir, {"yml", "yaml"})
        grand_total += n
        print()

    # YARA
    yara_dir = ROOT / "config" / "yara-rules"
    if yara_dir.exists():
        print("=== YARA Rules ===")
        n = collect_and_seed("yara", yara_dir, {"yar", "yara"})
        grand_total += n
        print()

    # ATR
    atr_dir = ROOT / "packages" / "atr" / "rules"
    if atr_dir.exists():
        print("=== ATR Rules ===")
        n = collect_and_seed("atr", atr_dir, {"yaml", "yml"})
        grand_total += n
        print()

    print("=========================================")
    print(f"  Total seeded: {grand_total} rules")
    print("=========================================")

    # Verify
    print()
    print("Verifying...")
    try:
        with urllib.request.urlopen(f"{TC}/api/stats", timeout=10) as resp:
            stats = json.loads(resp.read())
            data = stats.get("data", {})
            print(f"  Total rules in DB: {data.get('totalRules', '?')}")
            print(f"  Total threats: {data.get('totalThreats', '?')}")
            ps = data.get("proposalStats", {})
            print(f"  Proposals: {ps.get('total', '?')} (confirmed: {ps.get('confirmed', '?')})")
    except Exception as e:
        print(f"  Verify failed: {e}")


if __name__ == "__main__":
    main()
