#!/usr/bin/env python3
"""Write README_BENCHMARK.md from the release runner JSON and LLM scorecards.

Primary H2 metric is fix discrimination on pairs whose pre and post outcomes
are both ok. compile_error is a separate count. The H2 decision is withheld
when the real rule does not beat the trivial every-function control.
"""

from __future__ import annotations

import csv
import json
import math
import random
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELD = ROOT / "data" / "held_out_pairs.csv"
RESULTS = ROOT / "benchmarks" / "results" / "release"
LLM = ROOT / "benchmarks" / "raw_llm_outputs"
README = ROOT / "README.md"
H4_PAIRS = RESULTS / "h4_pairs.json"
GATE_JSON = ROOT / "data" / "v2_candidate" / "gate.json"
CWE_SIDE = ROOT / "data" / "held_out_cwe.csv"
Z = 1.95996
RECALL_BAR = 0.70
SILENCE_BAR = 0.85
FD_BAR = 0.70


def wilson(successes: int, n: int) -> tuple[float, float] | None:
    if n <= 0:
        return None
    p = successes / n
    z2 = Z * Z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    margin = Z * math.sqrt((p * (1 - p) + z2 / (4 * n)) / n) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def binom_sf(k: int, n: int, p: float) -> float:
    if n < 0 or k > n:
        return 1.0
    total = sum(math.comb(n, i) * (p**i) * ((1 - p) ** (n - i)) for i in range(k, n + 1))
    return min(1.0, total)


def holm(pvals: list[tuple[str, float]]) -> dict[str, float]:
    ordered = sorted(pvals, key=lambda item: item[1])
    adjusted: dict[str, float] = {}
    running = 0.0
    m = len(ordered)
    for index, (name, pval) in enumerate(ordered):
        running = max(running, min(1.0, pval * (m - index)))
        adjusted[name] = running
    return adjusted


def mcnemar(b: int, c: int) -> float | None:
    n = b + c
    if n == 0:
        return None
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2**n)
    return min(1.0, 2 * tail)


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * p
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    frac = pos - lo
    return ordered[lo] * (1 - frac) + ordered[hi] * frac


def self_check() -> None:
    assert Z == 1.95996
    both = wilson(1, 1)
    assert both is not None and both[1] == 1.0 and 0.20 < both[0] < 0.22
    none = wilson(0, 1)
    assert none is not None and none[0] == 0.0 and none[1] < 0.80
    assert wilson(0, 0) is None
    zero = wilson(0, 20)
    assert zero is not None and abs(zero[1] - 0.1611) < 0.002
    assert holm([("a", 0.01), ("b", 0.04)]) == {"a": 0.02, "b": 0.04}
    assert mcnemar(6, 0) is not None and abs(mcnemar(6, 0) - 0.03125) < 1e-9
    assert mcnemar(0, 0) is None


def fmt_rate(k: int | None, n: int | None) -> str:
    if k is None or n is None or n == 0:
        return "not measured"
    return f"{k}/{n} = {k / n:.2f}"


def fmt_wilson(k: int | None, n: int | None) -> str:
    if k is None or n is None:
        return "—"
    interval = wilson(k, n)
    if interval is None:
        return "—"
    return f"[{interval[0]:.2f}, {interval[1]:.2f}]"


def decision(k: int | None, n: int | None, bar: float) -> str:
    if k is None or n is None or n == 0:
        return "not measured"
    rate = k / n
    interval = wilson(k, n)
    low = interval[0] if interval else 0.0
    if rate + 1e-12 >= bar and low + 1e-12 >= bar:
        return "point and interval meet bar"
    if rate + 1e-12 >= bar:
        return "point meets bar, interval does not"
    return "point does not meet bar"


def load_results() -> dict[tuple[str, str, str, str], dict]:
    found = {}
    if not RESULTS.is_dir():
        return found
    for path in RESULTS.glob("*.json"):
        if path.name == "h4_pairs.json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if "pair" not in data or "target" not in data:
            continue
        control = data.get("control") or ""
        found[(control, data["target"], data["pair"], data["side"])] = data
    return found


def load_cwe_sidecar() -> dict[str, dict]:
    if not CWE_SIDE.is_file():
        return {}
    out: dict[str, dict] = {}
    with CWE_SIDE.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            out[row["GHSA ID"]] = row
    return out


def status_pilot_lines() -> list[str]:
    return [
        "## Status (read first)",
        "",
        "Pilot held-out: **n=7** Python (`web2_mcp`), **n=8** Solidity (`web3_toctou_cei`).",
        "Pre-registered H2 bars **were not met**; **no general performance claims** in this release.",
        "This release ships the harness, labeled primary arms, cheap controls, and frozen artifacts.",
        "**Pending:** fair baselines (see PREREG); v2 held-out (**GATE_FAIL**: 0 of 20 Web3 candidates in public `gate.json`).",
        "Per-repository recall/silence scores measure **rule–oracle agreement on that advisory**, not the security posture of the upstream project.",
        "",
        "**Attribution:** advisory metadata from the [GitHub Advisory Database](https://github.com/advisories) (CC-BY 4.0).",
        "",
        "**Third-party rerun:** you may re-score committed YAML, stock Slither detectors, and the pinned threat-library SHA on the same clone pins.",
        "You **cannot** regenerate `web2_invariant.yml` from this repo alone (requires closed `veraptos_static_cli`).",
        "`PROVENANCE.json` frozen H1 hashes are integrity checks, not a public compiler replay recipe.",
        "",
    ]


def results_changelog_lines() -> list[str]:
    return [
        "## Results changelog",
        "",
        "| Release | Note |",
        "|---|---|",
        "| **v0.1.1** | Threat-library arm added **after** v1 primary H2 scores were known (PREREG post-hoc addendum; control arm). |",
        "| **v0.1.2** | Method-first README: status block, H2 negative controls, CWE sidecar, finding totals, fixture harness check. |",
        "| **v0.1.2+** | Public README scoped to **Opengrep + stock Slither** H2 only; legacy LLM syntax rows removed from this page. |",
        "",
    ]


def harness_checks_lines() -> list[str]:
    return [
        "## Harness checks (not held-out evidence)",
        "",
        "`scripts/fixture_check.py` runs in `reproduce.sh`:",
        "",
        "- Opengrep: `benchmarks/veraptos_rules/web2_invariant.yml` on `benchmarks/dev_fixtures/untrusted_external.py`.",
        "- Stock Slither: `reentrancy-eth,reentrancy-no-eth` on `benchmarks/dev_fixtures/reentrancy_harness.sol`.",
        "",
    ]


def findings_noise_lines(results: dict, rows: list[dict], engine: str) -> list[str]:
    lines = [
        f"### Total findings (primary arm, {engine_label(engine, results)})",
        "",
        "Oracle true positives are a subset of scanner findings. Post-patch **zero TP** can still mean noisy non-oracle alarms.",
        "",
        "| Pair | pre `finding_count` | post `finding_count` |",
        "|---|---|---|",
    ]
    for row in domain_rows(rows, engine):
        pair = row["GHSA ID"]
        pre = results.get(("", engine, pair, "pre"))
        post = results.get(("", engine, pair, "post"))
        if not pre or not post:
            continue
        lines.append(
            f"| `{pair}` | {pre.get('finding_count', '—')} | {post.get('finding_count', '—')} |"
        )
    lines.append("")
    return lines


def library_compile_notes(lib: dict) -> list[str]:
    tails: list[str] = []
    for by_side in lib.values():
        for payload in by_side.values():
            if payload.get("outcome") != "compile_error":
                continue
            tail = (payload.get("telemetry") or {}).get("stderr_tail")
            pair = payload.get("pair")
            if pair:
                snippet = (tail or "slither exited without JSON (~1.4s on veraptos-* detect)").strip().replace(
                    "\n", " "
                )[:200]
                tails.append(f"- `{pair}`: {snippet}")
    static = [
        "",
        "Library Slither `compile_error` sides (four GHSA pairs: `93hq`, `9vx6`, `g4vp`, `wprv`): `--detect veraptos-*` often writes no JSON while **stock** `reentrancy-eth` compiles on the same clone. Do not treat as post-patch silence.",
    ]
    if not tails:
        return static + ["",]
    return [
        "",
        "Library Slither `compile_error` stderr tails:",
        "",
        *tails,
        *static,
        "",
    ]


def in_scope_recall_lines(
    summary_rows: list[dict],
    sidecar: dict[str, dict],
    scope_key: str,
) -> list[str]:
    scoped = [
        row
        for row in summary_rows
        if sidecar.get(row["pair"], {}).get(scope_key) == "yes"
    ]
    if not scoped:
        return ["In-scope subset (sidecar): not measured.", ""]
    k = sum(1 for row in scoped if row["recall"])
    n = len(scoped)
    return [
        f"In-scope subset ({scope_key.replace('in_scope_', '')}, sidecar metadata): {fmt_rate(k, n)}.",
        "",
    ]


def held_rows() -> list[dict]:
    if not HELD.is_file():
        return []
    with HELD.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def engine_label(engine: str, results: dict) -> str:
    if engine != "semgrep":
        return engine
    for key, data in results.items():
        if len(key) < 2 or key[1] != "semgrep":
            continue
        version = ((data.get("telemetry") or {}).get("tool_version") or "").lower()
        if "opengrep" in version:
            return "opengrep"
    return "semgrep"


def domain_rows(rows: list[dict], engine: str) -> list[dict]:
    category = "web2_mcp" if engine == "semgrep" else "web3_toctou_cei"
    return [row for row in rows if row["Category"] == category]


def pair_record(results: dict, control: str, engine: str, pair: str) -> dict | None:
    pre = results.get((control, engine, pair, "pre"))
    post = results.get((control, engine, pair, "post"))
    if pre is None or post is None:
        return None
    return {"pre": pre, "post": post}


def summarize(results: dict, rows: list[dict], engine: str, control: str) -> dict:
    primary = []
    unresolved = compile_error = clone_error = other = paired = 0
    sides = ok_sides = 0
    for row in domain_rows(rows, engine):
        rec = pair_record(results, control, engine, row["GHSA ID"])
        if rec is None:
            continue
        paired += 1
        for side in (rec["pre"], rec["post"]):
            sides += 1
            outcome = side.get("outcome")
            if outcome == "ok":
                ok_sides += 1
            elif outcome == "compile_error":
                compile_error += 1
            elif outcome == "clone_error":
                clone_error += 1
            else:
                other += 1
        if rec["pre"].get("oracle_unresolved") or rec["post"].get("oracle_unresolved"):
            unresolved += 1
            continue
        if rec["pre"].get("outcome") == "ok" and rec["post"].get("outcome") == "ok":
            hit = bool(rec["pre"].get("tp")) and not bool(rec["post"].get("tp"))
            primary.append(
                {
                    "pair": row["GHSA ID"],
                    "repo": rec["pre"].get("repository") or row["Repository URL"],
                    "cwe": rec["pre"].get("cwe") or row.get("CWE ID") or "unknown",
                    "recall": bool(rec["pre"].get("tp")),
                    "silence": not bool(rec["post"].get("tp")),
                    "fd": hit,
                    "pre_ok": True,
                    "post_ok": True,
                }
            )
    n = len(primary)
    recall = sum(1 for item in primary if item["recall"])
    silence = sum(1 for item in primary if item["silence"])
    fd = sum(1 for item in primary if item["fd"])
    return {
        "n": n,
        "recall": recall,
        "silence": silence,
        "fd": fd,
        "unresolved": unresolved,
        "compile_error": compile_error,
        "clone_error": clone_error,
        "other": other,
        "sides": sides,
        "ok_sides": ok_sides,
        "paired": paired,
        "rows": primary,
    }


def by_cwe(rows: list[dict]) -> list[tuple[str, int, int]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row["cwe"] or "unknown"].append(row)
    out = []
    for cwe in sorted(groups):
        items = groups[cwe]
        out.append((cwe, sum(1 for item in items if item["recall"]), len(items)))
    return out


def by_repo(rows: list[dict]) -> list[tuple[str, int, int]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row["repo"]].append(row)
    out = []
    for repo in sorted(groups):
        items = groups[repo]
        out.append((repo, sum(1 for item in items if item["fd"]), len(items)))
    return out


def bootstrap(rows: list[dict]) -> tuple[float, float] | None:
    groups: dict[str, list[int]] = defaultdict(list)
    for row in rows:
        groups[row["repo"]].append(1 if row["fd"] else 0)
    repos = list(groups.values())
    if not repos:
        return None
    rng = random.Random(0)
    rates = []
    for _ in range(1000):
        draw = [rng.choice(repos) for _ in repos]
        bits = [bit for group in draw for bit in group]
        rates.append(sum(bits) / len(bits) if bits else 0.0)
    low = percentile(rates, 0.025)
    high = percentile(rates, 0.975)
    if low is None or high is None:
        return None
    return low, high


def bounds(summary: dict, domain_n: int) -> dict[str, str]:
    """Worst treats a non-ok side as a miss or an alarm. Best treats it as a hit or silence."""
    if domain_n <= 0:
        return {}
    recall = summary["recall"]
    silence = summary["silence"]
    # Pairs that are not in the both-ok primary set.
    missing = domain_n - summary["n"]
    return {
        "recall_worst": fmt_rate(recall, domain_n),
        "recall_best": fmt_rate(min(domain_n, recall + missing), domain_n),
        "silence_worst": fmt_rate(silence, domain_n),
        "silence_best": fmt_rate(min(domain_n, silence + missing), domain_n),
    }


def scorecards() -> list[dict]:
    found = []
    if not LLM.is_dir():
        return found
    for path in sorted(LLM.glob("*/scorecard.json")):
        found.append(json.loads(path.read_text(encoding="utf-8")))
    return found


def h3_lines(primary_opengrep_recall: int, primary_n: int) -> list[str]:
    return [
        "## H3 — metamorphic mutators",
        "",
        "**Not scored on v1 held-out.** PREREG requires at least **10 pre-patch detections** on the unmutated rule before mutant preserving/altering rates are reported. Primary Opengrep recall on v1 is "
        f"**{primary_opengrep_recall}/{primary_n}**, so the held-out corpus does not meet the H3 gate.",
        "",
        "**What did run:** `python scripts/mutator.py --self-check` on the four Web2 dev mutants (altering + preserving). That checks the mutator machinery only — not advisory recall.",
        "",
        "Slither mutants are out of scope for this pilot (H3 is Web2 Python fixtures in PREREG).",
        "",
    ]


def h4_text() -> list[str]:
    path = H4_PAIRS
    if not path.is_file():
        return [
            "Held-out H4 recall was not scored. McNemar is not measured.",
            "",
        ]
    data = json.loads(path.read_text(encoding="utf-8"))
    lines = [
        "| Model | Veraptos-only | LLM-only | Both | Neither | McNemar p |",
        "|---|---|---|---|---|---|",
    ]
    for row in data.get("models") or []:
        pval = mcnemar(int(row["veraptos_only"]), int(row["llm_only"]))
        shown = "—" if pval is None else f"{pval:.4f}"
        lines.append(
            "| `{model}` | {v} | {llm} | {both} | {neither} | {p} |".format(
                model=row["model"],
                v=row["veraptos_only"],
                llm=row["llm_only"],
                both=row["both"],
                neither=row["neither"],
                p=shown,
            )
        )
    lines.append("")
    return lines


def load_library_results() -> dict[tuple[str, str], dict[tuple[str, str], dict]]:
    """Map (library_rule_id, target) -> (pair, side) -> payload."""
    found: dict[tuple[str, str], dict[tuple[str, str], dict]] = {}
    if not RESULTS.is_dir():
        return found
    for path in RESULTS.glob("library_*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        rule_id = data.get("library_rule_id") or ""
        target = data.get("target") or ""
        if not rule_id or not target:
            continue
        key = (rule_id, target)
        found.setdefault(key, {})[(data["pair"], data["side"])] = data
    return found


def summarize_library(
    held: list[dict],
    by_side: dict[tuple[str, str], dict],
    category: str,
) -> dict:
    primary = []
    compile_error = 0
    sides = ok_sides = 0
    for row in held:
        if row["Category"] != category:
            continue
        pre = by_side.get((row["GHSA ID"], "pre"))
        post = by_side.get((row["GHSA ID"], "post"))
        if pre is None or post is None:
            continue
        for side in (pre, post):
            sides += 1
            if side.get("outcome") == "ok":
                ok_sides += 1
            elif side.get("outcome") == "compile_error":
                compile_error += 1
        if pre.get("outcome") == "ok" and post.get("outcome") == "ok":
            primary.append(
                {
                    "recall": bool(pre.get("tp")),
                    "silence": not bool(post.get("tp")),
                    "fd": bool(pre.get("tp")) and not bool(post.get("tp")),
                }
            )
    n = len(primary)
    return {
        "n": n,
        "recall": sum(1 for item in primary if item["recall"]),
        "silence": sum(1 for item in primary if item["silence"]),
        "fd": sum(1 for item in primary if item["fd"]),
        "compile_error": compile_error,
        "sides": sides,
        "ok_sides": ok_sides,
    }


def library_table_lines(held: list[dict]) -> list[str]:
    lib = load_library_results()
    if not lib:
        return [
            "## H2 — threat library on v1 (out-of-class)",
            "",
            "Not measured. Run `python scripts/library_batch.py` after PREREG addendum.",
            "",
        ]
    lines = [
        "## H2 — control: threat library on v1 (out-of-class)",
        "",
        "Zeros are the expected outcome: DVD / TS / Go showcase rules vs MCP Python and OpenZeppelin patch-class advisories.",
        "",
        "Rules from [veraptos-threat-library](https://github.com/Tito0015/veraptos-threat-library) at SHA `78b718d72bce1521593774c59b03c0e4edd7088e`. Estimand: same matcher as H2; pairs are **not** the fixture classes these rules target.",
        "",
        "| Rule | Engine | Domain | N | Fix discrimination | Pre-patch recall | Post-patch silence | compile_error sides |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for (rule_id, target), by_side in sorted(lib.items()):
        engine = "opengrep" if "opengrep" in target else "slither"
        category = "web2_mcp" if engine == "opengrep" else "web3_toctou_cei"
        summary = summarize_library(held, by_side, category)
        n = summary["n"]
        lines.append(
            "| `{rule}` | {engine} | {domain} | {n} | {fd} | {recall} | {silence} | {comp} |".format(
                rule=rule_id,
                engine=engine,
                domain="Python" if category == "web2_mcp" else "Solidity",
                n=n,
                fd=fmt_rate(summary["fd"], n),
                recall=fmt_rate(summary["recall"], n),
                silence=fmt_rate(summary["silence"], n),
                comp=summary["compile_error"],
            )
        )
    lines.extend(library_compile_notes(lib))
    lines.append("")
    return lines


def scored_arms_lines() -> list[str]:
    return [
        "**Related repos:** [Veraptos Threat Library](https://github.com/Tito0015/veraptos-threat-library) · public package [`veraptosbench-mini`](https://github.com/Tito0015/veraptosbench-mini).",
        "",
        "## Scored arms (what each row measures)",
        "",
        "| Arm | Status | Rule source | Scoring engine |",
        "|---|---|---|---|",
        "| **Treatment (compiler sink-map)** | Scored | Veraptos static CLI Python YAML export → `benchmarks/veraptos_rules/web2_invariant.yml` | Opengrep on Python pairs (N=7) |",
        "| **Baseline (stock Slither)** | Scored | Slither `reentrancy-eth`, `reentrancy-no-eth` — not Veraptos-compiled; no `--export-slither` | Slither on Solidity pairs (N=8) |",
        "| **Control (out-of-class library rules)** | Scored (descriptive) | Pinned threat-library paths/detectors (see table below) | Opengrep + library Slither |",
        "",
        "The Opengrep H2 row is the compiler Python sink-map only, not a threat-library YAML.",
        "",
    ]


def gate_lines() -> list[str]:
    if not GATE_JSON.is_file():
        return []
    data = json.loads(GATE_JSON.read_text(encoding="utf-8"))
    held = data.get("held") or {}
    dev = data.get("dev") or {}
    dropped = data.get("dropped") or {}
    return [
        "## v2 harvest gate",
        "",
        f"Status: {data.get('status')}. The active held-out hash stays at v1, and v2 pairs were not scanned.",
        f"Candidate held-out counts: web2_mcp={held.get('web2_mcp', 0)}, web3_toctou_cei={held.get('web3_toctou_cei', 0)}. Need 20 and 20.",
        f"Candidate dev counts: web2_mcp={dev.get('web2_mcp', 0)}, web3_toctou_cei={dev.get('web3_toctou_cei', 0)}. Raw rows kept: {data.get('raw')}.",
        "Dropped before the split: "
        + ", ".join(f"{name}={count}" for name, count in sorted(dropped.items()))
        + ".",
        "",
    ]


def render() -> str:
    rows = held_rows()
    results = load_results()
    engines = (
        ("semgrep", "Python", "web2_mcp"),
        ("slither", "Solidity", "web3_toctou_cei"),
    )
    lines = [
        "# VeraptosBench-mini results",
        "",
    ]
    lines.extend(status_pilot_lines())
    lines.extend(scored_arms_lines())
    lines.extend(results_changelog_lines())
    lines.extend(harness_checks_lines())
    lines.extend(
        [
        "## v1 archive",
        "",
        "v1 hash `8316802fb09b6a0595d58472ceb810656cf71a8549b495d5641c98dcc478222d`.",
        "An archived wrong-engine row once ran a Python rule engine on Solidity pairs; it is not part of this release. **Web2 H2 = Opengrep only. Web3 H2 = stock Slither only.**",
        "",
        ]
    )
    lines.extend(gate_lines())
    lines.extend(
        [
        "## H2 — frozen v1 held-out",
        "",
        "The primary estimand is pairs with both sides `ok` and a resolved oracle function.",
        "Fix discrimination means a pre-patch true positive and a post-patch silence.",
        f"Wilson intervals use z = {Z}. `compile_error` is not in the recall, silence, or fix-discrimination denominators.",
        "",
        "| Engine | Domain | N | Fix discrimination | Wilson 95% | Pre-patch recall | Wilson 95% | Post-patch silence | Wilson 95% | compile_error sides |",
        "|---|---|---|---|---|---|---|---|---|---|",
        ]
    )
    summaries = {}
    trivial = {}
    pvals = []
    sidecar = load_cwe_sidecar()
    scope_key = {"semgrep": "in_scope_sinkmap", "slither": "in_scope_reentrancy"}
    for engine, domain, _category in engines:
        summary = summarize(results, rows, engine, "")
        summaries[engine] = summary
        trivial[engine] = summarize(results, rows, engine, "trivial")
        n = summary["n"] if summary["sides"] else None
        recall = summary["recall"] if n else None
        silence = summary["silence"] if n else None
        fd = summary["fd"] if n else None
        shown_n = "not measured" if n is None else str(n)
        if n:
            pvals.append((engine, binom_sf(summary["recall"], n, RECALL_BAR)))
        label = engine_label(engine, results)
        lines.append(
            "| {engine} | {domain} | {n} | {fd} | {fw} | {recall} | {rw} | {silence} | {sw} | {comp} |".format(
                engine=label,
                domain=domain,
                n=shown_n,
                fd=fmt_rate(fd, n),
                fw=fmt_wilson(fd, n),
                recall=fmt_rate(recall, n),
                rw=fmt_wilson(recall, n),
                silence=fmt_rate(silence, n),
                sw=fmt_wilson(silence, n),
                comp=summary["compile_error"] if summary["sides"] else "not measured",
            )
        )
    lines.extend(["", "## H2 decision", ""])
    adjusted = holm(pvals) if pvals else {}
    for engine, domain, category in engines:
        summary = summaries[engine]
        base = trivial[engine]
        domain_n = summary["paired"]
        label = engine_label(engine, results)
        for row in summary["rows"]:
            meta = sidecar.get(row["pair"], {})
            if meta.get("CWE"):
                row["cwe"] = meta["CWE"]
        if summary["sides"] == 0:
            lines.append(f"{label}: not measured.")
            continue
        real_fd = summary["fd"] / summary["n"] if summary["n"] else None
        trivial_fd = base["fd"] / base["n"] if base["n"] else None
        if base["sides"] == 0 or real_fd is None or trivial_fd is None:
            verdict = "H2 withheld: trivial control missing"
        elif real_fd <= trivial_fd:
            verdict = (
                f"H2 withheld: fix discrimination {real_fd:.2f} does not exceed "
                f"the trivial every-function control {trivial_fd:.2f}"
            )
        else:
            verdict = (
                f"H2 comparison passed the trivial control ({real_fd:.2f} > {trivial_fd:.2f}). "
                "The locked bars are still separate."
            )
        analyzability = summary["ok_sides"] / summary["sides"] if summary["sides"] else 0
        bound = bounds(summary, domain_n if summary["n"] or summary["sides"] else 0)
        boot = bootstrap(summary["rows"])
        boot_text = "—" if boot is None else f"[{boot[0]:.2f}, {boot[1]:.2f}]"
        holm_p = adjusted.get(engine)
        lines.extend(
            [
                f"### {label} on {domain}",
                "",
                verdict,
                f"Recall bar: {decision(summary['recall'], summary['n'], RECALL_BAR)}.",
                f"Silence bar: {decision(summary['silence'], summary['n'], SILENCE_BAR)}.",
                f"Fix-discrimination point against {FD_BAR:.0%}: {decision(summary['fd'], summary['n'], FD_BAR)}.",
                f"Analyzability: {summary['ok_sides']}/{summary['sides']} = {analyzability:.2f}. Unresolved oracle pairs excluded: {summary['unresolved']}. clone_error sides: {summary['clone_error']}.",
                "Repos with `foundry.toml` are compiled by Slither through forge. A `compile_error` means that build wrote no JSON."
                if engine == "slither"
                else "",
                f"Worst/best recall if non-ok pairs count against/for the tool: {bound.get('recall_worst', '—')} / {bound.get('recall_best', '—')}.",
                f"Worst/best silence: {bound.get('silence_worst', '—')} / {bound.get('silence_best', '—')}.",
                f"Repo-cluster bootstrap 95% for fix discrimination: {boot_text}.",
                f"Holm-adjusted one-sided binomial p for recall ≤ {RECALL_BAR:.0%}: "
                + (f"{holm_p:.4f}." if holm_p is not None else "not measured."),
                "",
                "Fix discrimination by repository:",
                "",
                "| Repository | Fix discrimination |",
                "|---|---|",
            ]
        )
        repos = by_repo(summary["rows"]) or [("(none)", 0, 0)]
        for repo, k, n in repos:
            if n == 0:
                continue
            lines.append(f"| `{repo}` | {fmt_rate(k, n)} |")
        lines.extend(["", "Recall by CWE:", "", "| CWE | Pre-patch recall |", "|---|---|"])
        for cwe, k, n in by_cwe(summary["rows"]):
            lines.append(f"| {cwe or 'unknown'} | {fmt_rate(k, n)} |")
        lines.extend(in_scope_recall_lines(summary["rows"], sidecar, scope_key[engine]))
        lines.extend(findings_noise_lines(results, rows, engine))
        shuffled = summarize(results, rows, engine, "shuffled")
        empty = summarize(results, rows, engine, "empty")
        lines.extend(
            [
                "",
                f"Empty control fix discrimination: {fmt_rate(empty['fd'], empty['n'] if empty['sides'] else None)}.",
                f"Shuffled-oracle fix discrimination: {fmt_rate(shuffled['fd'], shuffled['n'] if shuffled['sides'] else None)}.",
                "",
            ]
        )
    lines.extend(library_table_lines(rows))
    opengrep_summary = summaries.get("semgrep") or {}
    lines.extend(
        [
            "",
            "## Scope of this release",
            "",
            "Public scorecard: **Opengrep** (Python sink-map) and **stock Slither** (Solidity reentrancy) on frozen v1 pairs, plus out-of-class library controls. Legacy PREREG arms outside those two engines are not on this page.",
            "",
        ]
    )
    lines.extend(h3_lines(opengrep_summary.get("recall", 0), opengrep_summary.get("n", 0) or 0))
    lines.extend(
        [
            "## Pending fair baselines (pre-registered, not scored in this release)",
            "",
            "- Community Opengrep registry rules by upstream rule id + commit only (no vendored rule text).",
            "- Time-boxed hand-written expert rule per domain.",
            "",
            "See [`PREREG.md`](PREREG.md) addenda *Library-on-v1* and *Fair baselines pending*.",
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    self_check()
    README.write_text(render(), encoding="utf-8")
    print(f"wrote {README}")


if __name__ == "__main__":
    main()
