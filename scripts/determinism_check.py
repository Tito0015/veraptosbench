#!/usr/bin/env python3
"""Offline H1 check against frozen Glider exports (no Veraptos compiler in-tree).

Three recorded runs must be byte-identical and match PROVENANCE glider_rule_sha256.
The compiler invocation that produced these artifacts is documented in PROVENANCE.json.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "benchmarks" / "determinism"
PROVENANCE = ROOT / "PROVENANCE.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    if not PROVENANCE.is_file():
        raise SystemExit(f"missing {PROVENANCE}")
    expected = json.loads(PROVENANCE.read_text(encoding="utf-8")).get("glider_rule_sha256")
    if not expected:
        raise SystemExit("PROVENANCE missing glider_rule_sha256")
    hashes: list[str] = []
    for index in range(1, 4):
        path = OUT_DIR / f"run_{index}.glider.py"
        if not path.is_file():
            raise SystemExit(f"missing frozen export {path}")
        value = digest(path)
        hashes.append(value)
        print(f"run_{index} {value}")
    if len(set(hashes)) != 1:
        raise SystemExit("determinism failed: hashes differ")
    if hashes[0] != expected:
        raise SystemExit(f"determinism failed: frozen {hashes[0]} != provenance {expected}")
    print("determinism ok")


if __name__ == "__main__":
    main()
    sys.exit(0)
