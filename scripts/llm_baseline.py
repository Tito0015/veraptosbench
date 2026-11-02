#!/usr/bin/env python3
"""Ask two OpenRouter models for Python Semgrep and Python CodeQL rules.

The key is OPENROUTER_API_KEY from the environment or a local .env file.
It is never written into source, logs, or saved outputs.

Ten paraphrased prompts per model at temperature 0. pass@1 is the first
sample. pass@3 feeds the validator error back, up to three attempts.
CodeQL is compiled inside the repo's Python qlpack scaffold.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "benchmarks" / "raw_llm_outputs"
SCAFFOLD = ROOT / "benchmarks" / "native_rules" / "codeql"
FIXTURE = ROOT / "benchmarks" / "dev_fixtures" / "untrusted_external.py"
HELD = ROOT / "data" / "held_out_pairs.csv"
ORACLE = ROOT / "data" / "held_out_oracle.csv"
RELEASE = ROOT / "benchmarks" / "results" / "release"
MODELS = ("openai/gpt-4o-mini", "anthropic/claude-sonnet-5.5")
RUNS = 10
INVARIANT = (
    "State Mutation Following an External Untrusted Interaction. "
    "A public function performs an external call to untrusted input and then writes contract state. "
    "In Python the external call is requests, httpx, or subprocess, and the state write is an assignment that uses the response."
)
FEW_SHOT = (
    "Unrelated example, not the task. Do not copy this rule.\n"
    "```yaml\n"
    "rules:\n"
    "  - id: example.eval\n"
    "    languages: [python]\n"
    "    severity: ERROR\n"
    "    message: eval\n"
    "    pattern: eval(...)\n"
    "```\n"
    "```ql\n"
    "import python\n"
    "from Call c\n"
    "where c.getFunc().(Name).getId() = \"eval\"\n"
    "select c, \"eval\"\n"
    "```\n"
)
LEADS = (
    "Write the rules.",
    "Produce the rules from scratch.",
    "Author native scanner rules for the invariant.",
    "Draft the scanner queries for the invariant.",
    "Create one Semgrep rule and one CodeQL query.",
    "Translate the invariant into scanner rules.",
    "Give the scanner rules a reviewer could run.",
    "Emit the rules in the required fences.",
    "Write rules that flag the invariant.",
    "Prepare the two rules described below.",
)
FORMAT = (
    "Return exactly two fenced blocks and no other fences.\n"
    "1. a Python Semgrep rule in a yaml fence. languages must be [python].\n"
    "2. a Python CodeQL query in a ql fence. It must start with `import python` "
    "and must not import solidity.\n"
)
FENCE = re.compile(r"```([a-zA-Z0-9_+-]*)\s*\n(.*?)```", re.S)
IMPORT_RE = re.compile(r"(?m)^\s*import\s+([A-Za-z0-9_.]+)")
REAL_IMPORTS = {"python", "semmle", "codeql"}


def load_key() -> str:
    env_path = ROOT / ".env"
    if env_path.is_file():
        try:
            from dotenv import load_dotenv
        except ImportError:
            for line in env_path.read_text(encoding="utf-8").splitlines():
                if line.startswith("OPENROUTER_API_KEY="):
                    os.environ["OPENROUTER_API_KEY"] = (
                        line.split("=", 1)[1].strip().strip('"').strip("'")
                    )
        else:
            load_dotenv(env_path)
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise SystemExit("OPENROUTER_API_KEY is missing. Put it in .env or the environment.")
    return key


def redact(text: str, key: str) -> str:
    return text.replace(key, "[redacted]") if key else text


def prompt_for(index: int) -> str:
    lead = LEADS[index % len(LEADS)]
    return f"{FEW_SHOT}\n{lead}\nInvariant: {INVARIANT}\n{FORMAT}"


def extract(text: str, kind: str) -> str | None:
    want = {"semgrep": {"yaml", "yml"}, "codeql": {"ql", "codeql"}}[kind]
    for lang, body in FENCE.findall(text):
        if lang.lower() in want and body.strip():
            return body.strip() + "\n"
    return None


def rule_id(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip().lstrip("-").strip()
        if stripped.startswith("id:"):
            return stripped.split(":", 1)[1].strip().strip('"').strip("'")
    return None


def hallucinated_imports(ql: str) -> list[str]:
    bad = []
    for name in IMPORT_RE.findall(ql):
        if name.split(".")[0] not in REAL_IMPORTS:
            bad.append(name)
    return bad


def validate_semgrep(path: Path) -> tuple[bool, str]:
    proc = subprocess.run(
        ["semgrep", "--metrics=off", "--validate", "--config", str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    err = (proc.stderr or "") + (proc.stdout or "")
    return proc.returncode == 0, err


def validate_codeql(ql: str, work: Path) -> tuple[bool, str]:
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    for name in ("qlpack.yml", "codeql-pack.lock.yml"):
        src = SCAFFOLD / name
        if src.is_file():
            shutil.copyfile(src, work / name)
    (work / "query.ql").write_text(ql, encoding="utf-8")
    proc = subprocess.run(
        ["codeql", "query", "compile", "--additional-packs", str(work), str(work / "query.ql")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )
    err = (proc.stderr or "") + (proc.stdout or "")
    return proc.returncode == 0, err


def semantic_test(yml_path: Path) -> bool:
    text = yml_path.read_text(encoding="utf-8")
    rid = rule_id(text)
    if not rid or not FIXTURE.is_file():
        return False
    body = FIXTURE.read_text(encoding="utf-8")
    body = body.replace("# semgrep-sink", f"# ruleid: {rid}")
    body = body.replace("# semgrep-ok", f"# ok: {rid}")
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp)
        (dest / "rule.yml").write_text(text, encoding="utf-8")
        (dest / "untrusted_external.py").write_text(body, encoding="utf-8")
        proc = subprocess.run(
            ["semgrep", "--test", "--metrics=off", str(dest)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    return proc.returncode == 0


def slug(model: str) -> str:
    return model.replace("/", "__")


def one_run(client, model: str, index: int, folder: Path, key: str) -> dict:
    messages = [{"role": "user", "content": prompt_for(index - 1)}]
    record = {
        "semgrep_pass1": False,
        "codeql_pass1": False,
        "semgrep_pass3": False,
        "codeql_pass3": False,
        "api_error": False,
        "missing_qlpack": False,
        "hallucinated": False,
        "returned_model": "",
        "semgrep_path": "",
    }
    saw_body = False
    for attempt in range(1, 4):
        try:
            extra = {"reasoning": {"effort": "high"}} if "claude" in model else None
            reply = client.chat.completions.create(
                model=model,
                temperature=0.0,
                messages=messages,
                extra_body=extra,
            )
            text = reply.choices[0].message.content or ""
            returned = getattr(reply, "model", "") or ""
        except Exception as exc:
            (folder / f"run_{index}_try_{attempt}.txt").write_text(
                "API_ERROR\n" + redact(str(exc), key),
                encoding="utf-8",
            )
            if attempt == 3 and not saw_body:
                record["api_error"] = True
            messages.append(
                {
                    "role": "user",
                    "content": "The previous call failed before a rule was returned. Return the two fenced blocks.",
                }
            )
            continue
        saw_body = True
        record["returned_model"] = returned or record["returned_model"]
        (folder / f"run_{index}_try_{attempt}.txt").write_text(
            f"returned_model: {returned}\n{text}",
            encoding="utf-8",
        )
        if "qlpack.yml" not in text:
            record["missing_qlpack"] = True
        yml = extract(text, "semgrep")
        ql = extract(text, "codeql")
        sem_ok, sem_err = False, "missing yaml fence"
        ql_ok, ql_err = False, "missing ql fence"
        if yml:
            path = folder / f"run_{index}.yml"
            path.write_text(yml, encoding="utf-8")
            sem_ok, sem_err = validate_semgrep(path)
            if sem_ok and not record["semgrep_path"]:
                record["semgrep_path"] = str(path)
        if ql:
            bad = hallucinated_imports(ql)
            if bad:
                record["hallucinated"] = True
                (folder / f"run_{index}_imports.txt").write_text("\n".join(bad) + "\n", encoding="utf-8")
            (folder / f"run_{index}.ql").write_text(ql, encoding="utf-8")
            ql_ok, ql_err = validate_codeql(ql, folder / f"qlpack_run_{index}")
        if attempt == 1:
            record["semgrep_pass1"] = sem_ok
            record["codeql_pass1"] = ql_ok
        record["semgrep_pass3"] = record["semgrep_pass3"] or sem_ok
        record["codeql_pass3"] = record["codeql_pass3"] or ql_ok
        if sem_ok and ql_ok:
            break
        messages.append({"role": "assistant", "content": text})
        messages.append(
            {
                "role": "user",
                "content": "Validator errors:\n"
                + redact(f"Semgrep: {sem_err[:800]}\nCodeQL: {ql_err[:800]}", key)
                + "\nReturn the two fences again.",
            }
        )
    return record


def generate(models: tuple[str, ...]) -> None:
    key = load_key()
    from openai import OpenAI

    client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=key, timeout=120)
    print("model,semgrep_pass1,semgrep_pass3,codeql_pass1,codeql_pass3,api_errors")
    for model in models:
        folder = OUT / slug(model)
        folder.mkdir(parents=True, exist_ok=True)
        runs = [one_run(client, model, index, folder, key) for index in range(1, RUNS + 1)]
        validated = [run for run in runs if run["semgrep_path"]]
        semantic = sum(1 for run in validated if semantic_test(Path(run["semgrep_path"])))
        best = next((run["semgrep_path"] for run in runs if run["semgrep_pass1"]), "")
        if not best:
            best = next((run["semgrep_path"] for run in runs if run["semgrep_pass3"]), "")
        card = {
            "model": model,
            "runs": RUNS,
            "temperature": 0.0,
            "pass_at_1": {
                "semgrep": sum(1 for run in runs if run["semgrep_pass1"]),
                "codeql": sum(1 for run in runs if run["codeql_pass1"]),
            },
            "pass_at_3": {
                "semgrep": sum(1 for run in runs if run["semgrep_pass3"]),
                "codeql": sum(1 for run in runs if run["codeql_pass3"]),
            },
            "api_errors": sum(1 for run in runs if run["api_error"]),
            "missing_qlpack": sum(1 for run in runs if run["missing_qlpack"]),
            "hallucinated_imports": sum(1 for run in runs if run["hallucinated"]),
            "semantic_semgrep_pass": semantic,
            "semgrep_validated": len(validated),
            "best_semgrep": best,
            "returned_models": sorted({run["returned_model"] for run in runs if run["returned_model"]}),
        }
        (folder / "scorecard.json").write_text(json.dumps(card, indent=2) + "\n", encoding="utf-8")
        print(
            f"{model},{card['pass_at_1']['semgrep']},{card['pass_at_3']['semgrep']},"
            f"{card['pass_at_1']['codeql']},{card['pass_at_3']['codeql']},{card['api_errors']}"
        )


def gate_open() -> bool:
    if not HELD.is_file():
        return False
    import csv

    counts = {"web2_mcp": 0, "web3_toctou_cei": 0}
    with HELD.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["Category"] in counts:
                counts[row["Category"]] += 1
    return counts["web2_mcp"] >= 20 and counts["web3_toctou_cei"] >= 20


def score_heldout() -> None:
    if not gate_open():
        print("GATE: skip held-out LLM scoring")
        return
    sys.path.insert(0, str(ROOT / "scripts"))
    import pair_runner

    rows = [row for row in pair_runner.load_rows(HELD) if row["Category"] == "web2_mcp"]
    oracle = pair_runner.load_oracle(ORACLE)
    models = []
    for path in sorted(OUT.glob("*/scorecard.json")):
        card = json.loads(path.read_text(encoding="utf-8"))
        rule = card.get("best_semgrep") or ""
        if not rule or not Path(rule).is_file():
            continue
        veraptos_only = llm_only = both = neither = 0
        for row in rows:
            spec = oracle.get(row["GHSA ID"])
            if not spec or not (spec.get("Function") or "").strip():
                continue
            pre = pair_runner.evaluate(
                row, "semgrep", "pre", Path(rule), spec, "", False, False, None, None
            )
            veraptos_path = RELEASE / f"semgrep_{row['GHSA ID']}_pre.json"
            if not veraptos_path.is_file():
                continue
            veraptos = json.loads(veraptos_path.read_text(encoding="utf-8"))
            if pre.get("outcome") != "ok" or veraptos.get("outcome") != "ok":
                continue
            if veraptos.get("oracle_unresolved"):
                continue
            v_hit = bool(veraptos.get("tp"))
            l_hit = bool(pre.get("tp"))
            if v_hit and l_hit:
                both += 1
            elif v_hit:
                veraptos_only += 1
            elif l_hit:
                llm_only += 1
            else:
                neither += 1
        models.append(
            {
                "model": card["model"],
                "veraptos_only": veraptos_only,
                "llm_only": llm_only,
                "both": both,
                "neither": neither,
            }
        )
    RELEASE.mkdir(parents=True, exist_ok=True)
    (RELEASE / "h4_pairs.json").write_text(
        json.dumps({"models": models}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {RELEASE / 'h4_pairs.json'}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", choices=MODELS)
    parser.add_argument("--score-heldout", action="store_true")
    args = parser.parse_args()
    if args.score_heldout:
        score_heldout()
        return
    generate((args.model,) if args.model else MODELS)


if __name__ == "__main__":
    main()
