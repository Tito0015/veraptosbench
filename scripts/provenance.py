#!/usr/bin/env python3
"""Write PROVENANCE.json for the held-out benchmark snapshot."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREREG = ROOT / "PREREG.md"
HELD = ROOT / "data" / "held_out_pairs.csv"
CARGO = ROOT / "veraptos_static" / "Cargo.toml"
GLIDER = ROOT / "benchmarks" / "determinism" / "run_1.glider.py"
RULE_DIR = ROOT / "benchmarks" / "veraptos_rules"
OUT = ROOT / "PROVENANCE.json"
HASH_RE = re.compile(r"(?m)^`?HELD_OUT_DATASET_SHA256 = ([0-9a-f]{64})`?\s*$")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compiler_version() -> str:
    text = CARGO.read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit(f"no version in {CARGO}")


def git_head() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def rule_hashes() -> dict[str, str]:
    if not RULE_DIR.is_dir():
        return {}
    hashes = {}
    for path in sorted(RULE_DIR.rglob("*")):
        if path.is_file():
            hashes[str(path.relative_to(ROOT)).replace("\\", "/")] = sha256(path)
    return hashes


def main() -> None:
    match = HASH_RE.search(PREREG.read_text(encoding="utf-8"))
    if not match:
        raise SystemExit("HELD_OUT_DATASET_SHA256 is missing from PREREG.md")
    registered = match.group(1)
    actual = sha256(HELD)
    if actual != registered:
        raise SystemExit(f"held-out hash mismatch: file {actual} prereg {registered}")
    payload = {
        "compiler_package": "veraptos_static",
        "compiler_version": compiler_version(),
        "compiler_git": git_head(),
        "compiler_usage": [
            "veraptos_static_cli --scan <dir> --severity-threshold <f>",
            "veraptos_static_cli --source <path> --export-glider",
            "veraptos_static_cli --source <path> --export-semgrep",
            "veraptos_static_cli --export-semgrep-python",
        ],
        "native_rule_exports": ["glider", "semgrep"],
        "glider_rule_sha256": sha256(GLIDER),
        "veraptos_rules_sha256": rule_hashes(),
        "HELD_OUT_DATASET_SHA256": registered,
    }
    OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
