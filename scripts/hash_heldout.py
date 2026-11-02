#!/usr/bin/env python3
"""Hash data/held_out_pairs.csv and compare or lock it in PREREG.md.

--check compares only. --write replaces the active HELD_OUT_DATASET_SHA256
line, and only when the v2 size gate passes. The V1_ line is never edited.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELD = ROOT / "data" / "held_out_pairs.csv"
ORACLE = ROOT / "data" / "held_out_oracle.csv"
PREREG = ROOT / "PREREG.md"
ACTIVE_RE = re.compile(r"(?m)^`?HELD_OUT_DATASET_SHA256 = ([0-9a-f]{64}|<TBD>)`?\s*$")
ORACLE_RE = re.compile(r"(?m)^`?HELD_OUT_ORACLE_SHA256 = ([0-9a-f]{64}|<TBD>)`?\s*$")
GATE = {"web2_mcp": 20, "web3_toctou_cei": 20}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def active_hash(text: str) -> str:
    found = ACTIVE_RE.findall(text)
    if not found:
        raise SystemExit(f"active HELD_OUT_DATASET_SHA256 line missing in {PREREG}")
    return found[-1]


def counts(path: Path) -> Counter:
    with path.open(encoding="utf-8", newline="") as handle:
        return Counter(row["Category"] for row in csv.DictReader(handle))


def gate_ok(path: Path) -> bool:
    got = counts(path)
    return all(got[name] >= need for name, need in GATE.items())


def check() -> None:
    if not HELD.is_file():
        raise SystemExit(f"missing {HELD}")
    text = PREREG.read_text(encoding="utf-8")
    registered = active_hash(text)
    actual = digest(HELD)
    if registered == "<TBD>" or actual != registered:
        raise SystemExit(f"held-out hash mismatch: file {actual} prereg {registered}")
    print(actual)


def write_hash() -> None:
    if not HELD.is_file():
        raise SystemExit(f"missing {HELD}")
    if not gate_ok(HELD):
        got = dict(counts(HELD))
        raise SystemExit(f"gate: not freezing hash; counts={got} need={GATE}")
    text = PREREG.read_text(encoding="utf-8")
    if not ACTIVE_RE.search(text):
        raise SystemExit(f"active hash line missing in {PREREG}")
    actual = digest(HELD)
    new, n = ACTIVE_RE.subn(f"`HELD_OUT_DATASET_SHA256 = {actual}`", text, count=1)
    if n != 1:
        raise SystemExit("refused to rewrite more than the active hash line")
    PREREG.write_text(new, encoding="utf-8")
    print(actual)


def write_oracle() -> None:
    if not gate_ok(HELD):
        raise SystemExit("gate: not freezing oracle hash")
    if not ORACLE.is_file():
        raise SystemExit(f"missing {ORACLE}")
    text = PREREG.read_text(encoding="utf-8")
    if not ORACLE_RE.search(text):
        raise SystemExit("HELD_OUT_ORACLE_SHA256 line missing")
    actual = digest(ORACLE)
    new, n = ORACLE_RE.subn(f"`HELD_OUT_ORACLE_SHA256 = {actual}`", text, count=1)
    if n != 1:
        raise SystemExit("refused to rewrite more than the oracle hash line")
    PREREG.write_text(new, encoding="utf-8")
    print(actual)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--write-oracle", action="store_true")
    args = parser.parse_args()
    if args.check:
        check()
        return
    if args.write:
        write_hash()
        return
    if args.write_oracle:
        write_oracle()
        return
    raise SystemExit("pass --check, --write, or --write-oracle")


if __name__ == "__main__":
    main()
