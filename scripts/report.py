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
README = ROOT / "README_BENCHMARK.md"
H4_PAIRS = RESULTS / "h4_pairs.json"
GATE_JSON = ROOT / "data" / "v2_candidate" / "gate.json"
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
        "## v1 archive",
        "",
        "v1 hash `8316802fb09b6a0595d58472ceb810656cf71a8549b495d5641c98dcc478222d`.",
        "An earlier Semgrep run on these 8 Solidity pairs scored recall 0/8 = 0.00 [0.00, 0.32] and silence 8/8 = 1.00 [0.68, 1.00]. That row is not the Web3 measurement. Semgrep is Web2 Python only. Web3 is the Slither row.",
        "",
    ]
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
    lines.extend(
        [
            "",
            "## In Progress / Compiler Roadmap",
            "",
            "CodeQL export is not implemented. The Slither row is Slither's built-in `reentrancy-eth` and `reentrancy-no-eth` detectors, not a Veraptos-compiled rule. There is no `--export-slither`.",
            "",
            "## H3",
            "",
            "Not scored on the corpus in this release. The mutator self-check covers the four mutants. H3 is inconclusive unless an unmutated rule has at least 10 pre-patch detections.",
            "",
            "## H4 — syntax, pack, and repair",
            "",
            "pass@1 is the first sample. pass@3 allows two repairs that see the validator error. API errors are separate from syntax failures. A missing qlpack is recorded even when compile uses the supplied scaffold.",
            "",
            "| Model | Semgrep pass@1 | Semgrep pass@3 | CodeQL pass@1 | CodeQL pass@3 | API errors | Missing qlpack | Hallucinated imports | semgrep --test |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
    )
    cards = scorecards()
    if not cards:
        lines.append("| — | not measured | not measured | not measured | not measured | — | — | — | — |")
    for card in cards:
        sem = card["pass_at_1"]["semgrep"]
        sem3 = card["pass_at_3"]["semgrep"]
        ql = card["pass_at_1"]["codeql"]
        ql3 = card["pass_at_3"]["codeql"]
        runs = card["runs"]
        lines.append(
            "| `{model}` | {s}/{n} | {s3}/{n} | {q}/{n} | {q3}/{n} | {api} | {pack} | {imp} | {semtest}/{valid} |".format(
                model=card["model"],
                s=sem,
                s3=sem3,
                q=ql,
                q3=ql3,
                n=runs,
                api=card.get("api_errors", 0),
                pack=card.get("missing_qlpack", 0),
                imp=card.get("hallucinated_imports", 0),
                semtest=card.get("semantic_semgrep_pass", 0),
                valid=card.get("semgrep_validated", sem),
            )
        )
    returned = []
    for card in cards:
        for model_id in card.get("returned_models") or []:
            returned.append(f"`{card['model']}` returned `{model_id}`")
    lines.extend(["", "Returned model ids: " + ("; ".join(returned) if returned else "not measured."), ""])
    lines.extend(["## H4 — paired held-out recall", ""])
    lines.extend(h4_text())
    return "\n".join(lines) + "\n"


def main() -> None:
    self_check()
    README.write_text(render(), encoding="utf-8")
    print(f"wrote {README}")


if __name__ == "__main__":
    main()
