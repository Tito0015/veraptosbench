#!/usr/bin/env python3
"""Harness positive controls: scanners must fire on known fixtures (not held-out H2)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULE = ROOT / "benchmarks" / "veraptos_rules" / "web2_invariant.yml"
PY_FIXTURE = ROOT / "benchmarks" / "dev_fixtures" / "untrusted_external.py"
SOL_FIXTURE = ROOT / "benchmarks" / "dev_fixtures" / "reentrancy_harness.sol"
SLITHER_DETECT = "reentrancy-eth,reentrancy-no-eth"


def scanner() -> str:
    if shutil.which("opengrep"):
        return "opengrep"
    if shutil.which("semgrep"):
        return "semgrep"
    raise SystemExit("opengrep or semgrep required for fixture check")


def check_opengrep_sinkmap() -> None:
    if not RULE.is_file() or not PY_FIXTURE.is_file():
        raise SystemExit("missing rule or Python fixture")
    binary = scanner()
    cmd = [binary, "--json", "--config", str(RULE.resolve()), str(PY_FIXTURE)]
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
        raise SystemExit(
            "fixture check failed: sink-map rule did not fire on dev_fixtures/untrusted_external.py"
        )
    print(f"opengrep sink-map ok ({binary}, {len(results)} finding(s))")


def slither_findings(payload: str) -> list[dict]:
    try:
        data = json.loads(payload or "{}")
    except json.JSONDecodeError:
        return []
    if data.get("success") is False:
        return []
    out = []
    for det in (data.get("results") or {}).get("detectors") or []:
        check = (det.get("check") or "").lower()
        if "reentranc" in check:
            out.append(det)
    return out


def check_stock_slither_reentrancy() -> None:
    if not SOL_FIXTURE.is_file():
        raise SystemExit("missing Solidity fixture")
    if shutil.which("slither") is None:
        raise SystemExit("slither required for fixture check")
    json_path = SOL_FIXTURE.parent / ".slither_fixture_out.json"
    cmd = [
        "slither",
        str(SOL_FIXTURE.resolve()),
        "--detect",
        SLITHER_DETECT,
        "--json",
        str(json_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    payload = json_path.read_text(encoding="utf-8", errors="replace") if json_path.is_file() else ""
    json_path.unlink(missing_ok=True)
    hits = slither_findings(payload)
    if not hits:
        hint = (proc.stderr or proc.stdout or "no reentrancy detectors in JSON")[:400]
        raise SystemExit(
            "fixture check failed: stock Slither reentrancy did not fire on "
            f"dev_fixtures/reentrancy_harness.sol ({hint})"
        )
    print(f"stock Slither reentrancy ok ({len(hits)} detector hit(s))")


def main() -> None:
    check_opengrep_sinkmap()
    check_stock_slither_reentrancy()
    print("fixture checks ok (harness only, not held-out H2)")


if __name__ == "__main__":
    main()
