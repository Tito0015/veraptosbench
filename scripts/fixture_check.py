#!/usr/bin/env python3
"""Harness positive controls: scanners must fire on known fixtures (not held-out H2)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULE = ROOT / "benchmarks" / "veraptos_rules" / "web2_invariant.yml"
FIXTURE = ROOT / "benchmarks" / "dev_fixtures" / "untrusted_external.py"


def scanner() -> str:
    import shutil

    if shutil.which("opengrep"):
        return "opengrep"
    if shutil.which("semgrep"):
        return "semgrep"
    raise SystemExit("opengrep or semgrep required for fixture check")


def main() -> None:
    if not RULE.is_file() or not FIXTURE.is_file():
        raise SystemExit("missing rule or fixture")
    binary = scanner()
    cmd = [binary, "--json", "--config", str(RULE.resolve()), str(FIXTURE)]
    if binary == "semgrep":
        cmd.insert(1, "--metrics=off")
    else:
        cmd.append("--disable-version-check")
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        raise SystemExit(f"fixture scan parse failed: {(proc.stderr or proc.stdout)[:400]}")
    results = data.get("results") or []
    if not results:
        raise SystemExit("fixture check failed: sink-map rule did not fire on dev_fixtures/untrusted_external.py")
    print(f"fixture check ok ({binary}, {len(results)} finding(s))")


if __name__ == "__main__":
    main()
    sys.exit(0)
