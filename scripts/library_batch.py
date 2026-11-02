#!/usr/bin/env python3
"""Score threat-library rules on frozen v1 held-out pairs (PREREG addendum 2026-11-02)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from pair_runner import (  # noqa: E402
    RELEASE,
    evaluate,
    load_oracle,
    load_rows,
)

DEFAULT_LIBRARY = Path(os.environ.get("VERAPTOS_THREAT_LIBRARY", r"D:\veraptos-threat-library"))
LIBRARY_SHA = "78b718d72bce1521593774c59b03c0e4edd7088e"

OPENGREP_RULES = (
    ("graphql-ssrf", "web2-opengrep/01-graphql-ssrf/graphql-ssrf.yaml", "web2_mcp"),
    ("dom-xss-postmessage", "web2-opengrep/02-dom-xss-postmessage/dom-xss-postmessage.yaml", "web2_mcp"),
    (
        "mass-assignment-fastapi",
        "web2-opengrep/03-mass-assignment-fastapi/mass-assignment-fastapi.yaml",
        "web2_mcp",
    ),
    ("express-auth-bypass", "web2-opengrep/04-express-auth-bypass/express-auth-bypass.yaml", "web2_mcp"),
    ("jwt-none-alg-go", "web2-opengrep/05-jwt-none-alg-go/jwt-none-alg-go.yaml", "web2_mcp"),
)

SLITHER_RULES = (
    ("veraptos-truster-arbitrary-call", "veraptos-truster-arbitrary-call", "web3_toctou_cei"),
    ("veraptos-side-entrance-state-hijack", "veraptos-side-entrance-state-hijack", "web3_toctou_cei"),
    (
        "veraptos-rewarder-snapshot-manipulation",
        "veraptos-rewarder-snapshot-manipulation",
        "web3_toctou_cei",
    ),
    ("veraptos-puppet-spot-oracle", "veraptos-puppet-spot-oracle", "web3_toctou_cei"),
    ("veraptos-selfie-governance-snapshot", "veraptos-selfie-governance-snapshot", "web3_toctou_cei"),
)


def slither_env(library_root: Path) -> dict[str, str]:
    pkg = library_root / "web3-slither-dvd"
    env = os.environ.copy()
    prefix = str(pkg.resolve())
    env["PYTHONPATH"] = prefix + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return env


def out_path(engine: str, rule_id: str, pair: str, side: str) -> Path:
    safe = rule_id.replace("/", "_")
    return RELEASE / f"library_{engine}_{safe}_{pair}_{side}.json"


def run_rule(
    rows: list[dict],
    oracle: dict,
    library_root: Path,
    engine: str,
    rule_id: str,
    category: str,
    rule_path: Path | None,
    slither_detect: str | None,
    offline: bool,
) -> None:
    selected = [row for row in rows if row["Category"] == category]
    env = slither_env(library_root) if engine == "slither" else None
    target = "semgrep" if engine == "opengrep" else "slither"
    for row in selected:
        for side in ("pre", "post"):
            payload = evaluate(
                row,
                target,
                side,
                rule_path,
                oracle.get(row["GHSA ID"]),
                "",
                offline,
                False,
                None,
                None,
                slither_detect=slither_detect,
                slither_env=env,
            )
            payload["target"] = f"library_{engine}"
            payload["library_rule_id"] = rule_id
            payload["library_repo"] = "https://github.com/Tito0015/veraptos-threat-library"
            payload["library_git_sha"] = LIBRARY_SHA
            payload["estimand"] = "out_of_class_v1"
            path = out_path(engine, rule_id, row["GHSA ID"], side)
            path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            print(f"{path.name} outcome={payload['outcome']} tp={payload['tp']}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library-root", type=Path, default=DEFAULT_LIBRARY)
    parser.add_argument("--csv", type=Path, default=ROOT / "data" / "held_out_pairs.csv")
    parser.add_argument("--oracle", type=Path, default=ROOT / "data" / "held_out_oracle.csv")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--opengrep-only", action="store_true")
    parser.add_argument("--slither-only", action="store_true")
    parser.add_argument("--only", help="Run one library rule id (e.g. jwt-none-alg-go)")
    args = parser.parse_args()
    og_bin = Path.home() / ".opengrep" / "bin"
    if og_bin.is_dir():
        os.environ["PATH"] = str(og_bin) + os.pathsep + os.environ.get("PATH", "")
    library_root = args.library_root.resolve()
    if not library_root.is_dir():
        raise SystemExit(f"missing library root {library_root}")
    rows = load_rows(args.csv)
    oracle = load_oracle(args.oracle if args.oracle.is_file() else None)
    RELEASE.mkdir(parents=True, exist_ok=True)
    if not args.slither_only:
        for rule_id, rel, category in OPENGREP_RULES:
            if args.only and rule_id != args.only:
                continue
            rule_path = (library_root / rel).resolve()
            if not rule_path.is_file():
                raise SystemExit(f"missing opengrep rule {rule_path}")
            run_rule(rows, oracle, library_root, "opengrep", rule_id, category, rule_path, None, args.offline)
    if not args.opengrep_only:
        for rule_id, detect, category in SLITHER_RULES:
            if args.only and rule_id != args.only:
                continue
            run_rule(rows, oracle, library_root, "slither", rule_id, category, None, detect, args.offline)
    print("library batch done", file=sys.stderr)


if __name__ == "__main__":
    main()
