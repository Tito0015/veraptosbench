#!/usr/bin/env python3
"""Build data/held_out_cwe.csv from GitHub Advisory API (does not alter held_out_pairs.csv)."""

from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELD = ROOT / "data" / "held_out_pairs.csv"
OUT = ROOT / "data" / "held_out_cwe.csv"

SINK_KW = re.compile(
    r"\b(requests|httpx|http client|redirect|transport|subprocess|fetch\(|urllib)\b",
    re.I,
)
REENT_KW = re.compile(r"\b(reentranc|checks.?effects.?interactions|cei\b|external call)\b", re.I)


def gh_advisory(ghsa: str) -> dict:
    proc = subprocess.run(
        ["gh", "api", f"/advisories/{ghsa}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if proc.returncode != 0:
        raise SystemExit(f"gh api failed for {ghsa}: {proc.stderr[:500]}")
    return json.loads(proc.stdout)


def cwe_ids(payload: dict) -> str:
    cwes = payload.get("cwes") or []
    ids = []
    for item in cwes:
        if isinstance(item, dict) and item.get("cwe_id"):
            ids.append(item["cwe_id"])
        elif isinstance(item, str):
            ids.append(item)
    return ";".join(ids) if ids else "unknown"


def main() -> None:
    if not HELD.is_file():
        raise SystemExit(f"missing {HELD}")
    rows = list(csv.DictReader(HELD.open(encoding="utf-8", newline="")))
    written = []
    for row in rows:
        ghsa = row["GHSA ID"]
        payload = gh_advisory(ghsa)
        text = f"{payload.get('summary') or ''} {payload.get('description') or ''} {row.get('Summary') or ''}"
        sink = "yes" if SINK_KW.search(text) else "no"
        reent = "yes" if REENT_KW.search(text) else "no"
        written.append(
            {
                "GHSA ID": ghsa,
                "CWE": cwe_ids(payload),
                "in_scope_sinkmap": sink,
                "in_scope_reentrancy": reent,
                "note": (payload.get("summary") or "")[:120],
            }
        )
        print(ghsa, written[-1]["CWE"], sink, reent, file=sys.stderr)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["GHSA ID", "CWE", "in_scope_sinkmap", "in_scope_reentrancy", "note"],
        )
        writer.writeheader()
        writer.writerows(written)
    print(f"wrote {OUT} rows={len(written)}")


if __name__ == "__main__":
    main()
