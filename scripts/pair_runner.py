#!/usr/bin/env python3
"""Run one scanner on one advisory pair side and score it.

Usage:
  python scripts/pair_runner.py --target semgrep|codeql|slither --pair GHSA-... --side pre|post
  python scripts/pair_runner.py --self-check
  python scripts/pair_runner.py --emit-oracle data/held_out_oracle.csv --csv data/held_out_pairs.csv
  python scripts/pair_runner.py --batch release --target semgrep --rule <yml> --csv data/held_out_pairs.csv --oracle data/held_out_oracle.csv

A hit is a true positive only under the locked rule. With an oracle row, the
finding must sit in the named function in the named file. Without one, the
finding must sit in a function that contains a changed line, else within 15
lines when no function bounds resolve. Test, mock, doc, and example hunks
are not part of the oracle.

ponytail: Solidity function bounds mask comments and strings, then brace-match.
Ceiling is nested assembly that uses braces as Yul syntax outside strings.
Upgrade path: solc AST source mappings.
ponytail: CodeQL language is python for web2 and solidity for web3. Ceiling is
mixed-language repos. Upgrade path: per-file language map.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV = ROOT / "data" / "dev_pairs.csv"
CLONES = ROOT / "benchmarks" / "clones"
CODEQL_DBS = ROOT / "benchmarks" / "codeql_dbs"
RELEASE = ROOT / "benchmarks" / "results" / "release"
NATIVE_SEMGREP = ROOT / "benchmarks" / "native_rules" / "semgrep.yml"
NATIVE_CODEQL = ROOT / "benchmarks" / "native_rules" / "codeql" / "Function.ql"
SLITHER_DETECT = "reentrancy-eth,reentrancy-no-eth"
BUFFER = 15
PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.I)
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
SOL_NAME_RE = re.compile(
    r"^\s*(?:function\s+(\w+)|constructor\s*\(|modifier\s+(\w+)|fallback\s*\(|receive\s*\()"
)
VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
EXCLUDE_DIRS = frozenset({"test", "tests", "mocks", "docs", "examples"})
MIRRORS = {
    "jlowin/fastmcp": "fastmcp",
    "prefecthq/fastmcp": "fastmcp",
    "openzeppelin/openzeppelin-contracts": "openzeppelin-contracts",
    "openzeppelin/openzeppelin-contracts-upgradeable": "openzeppelin-contracts",
}
SEMGREP_EXCLUDES = (
    "**/test/**",
    "**/tests/**",
    "**/mocks/**",
    "**/docs/**",
    "**/examples/**",
    "**/*.md",
)
_VERSIONS: dict[str, str] = {}


def self_check() -> None:
    hunks = parse_diff(
        "\n".join(
            [
                "diff --git a/a.py b/a.py",
                "--- a/a.py",
                "+++ b/a.py",
                "@@ -10,2 +10,3 @@",
                "-old",
                " unchanged",
                "+new",
                "+new2",
            ]
        )
    )
    assert hunks["pre"]["a.py"] == {10, 11}
    assert hunks["post"]["a.py"] == {10, 11, 12}
    renamed = parse_diff(
        "\n".join(
            [
                'diff --git "a/old name.py" "b/new name.py"',
                "rename from old name.py",
                "rename to new name.py",
                '--- "a/old name.py"',
                '+++ "b/new name.py"',
                "@@ -1 +1 @@",
                "-a",
                "+b",
            ]
        )
    )
    assert renamed["pre"]["old name.py"] == {1}
    assert renamed["post"]["new name.py"] == {1}
    assert "old name.py" not in renamed["post"]
    skipped = parse_diff(
        "\n".join(
            [
                "diff --git a/test/t.py b/test/t.py",
                "--- a/test/t.py",
                "+++ b/test/t.py",
                "@@ -1 +1 @@",
                "-a",
                "+b",
                "diff --git a/src/a.py b/src/a.py",
                "--- a/src/a.py",
                "+++ b/src/a.py",
                "@@ -4 +4 @@",
                "-a",
                "+b",
            ]
        )
    )
    assert skipped["excluded_hunks"] == 1
    assert "test/t.py" not in skipped["pre"]
    assert skipped["pre"]["src/a.py"] == {4}
    src = "def outer():\n    def inner():\n        return 1\n"
    boxes = [(start, end) for _name, start, end in python_functions(src)]
    assert enclosing(boxes, 3) == (2, 3)
    assert match_mode({1, 2, 3}, 2, [(2, 3)]) == "function"
    assert match_mode({10}, 12, []) == "buffer15"
    assert match_mode({1}, 50, [(1, 2)]) is None
    sol = 'function transfer() public { string memory s = "{"; x = 1; }\n'
    assert solidity_functions(sol) == [("transfer", 1, 1)]
    commented = "function transfer() public { // {\n x = 1;\n}\n"
    assert solidity_functions(commented) == [("transfer", 1, 3)]
    assert pick_solc("^0.8.0", ["0.7.6", "0.8.10", "0.8.20"]) == "0.8.20"
    assert pick_solc("0.8.10", ["0.8.10"]) == "0.8.10"
    assert pragma_is_installed("^0.8.20", ["0.8.10", "0.8.20", "0.8.28"])
    assert not pragma_is_installed("0.8.24", ["0.8.10", "0.8.20", "0.8.28"])
    assert not pragma_is_installed("^0.7.0", ["0.8.28"])
    assert repo_key("https://github.com/jlowin/fastmcp") == repo_key(
        "https://github.com/PrefectHQ/fastmcp"
    )
    assert pick_function(
        [("a.sol", "transfer", 3), ("a.sol", "balanceOf", 9)],
        "bug in transfer",
    ) == ("a.sol", "transfer")
    assert pick_function([("a.sol", "balanceOf", 9)], "no name here") is None
    assert pick_function([("a.sol", "get", 9)], "call get now") is None
    assert nearest_changed(12, {10, 20}) == 2
    print("self-check ok", file=sys.stderr)


def repo_key(url: str) -> str:
    match = re.search(r"github\.com/([^/]+)/([^/#]+)", url, re.I)
    if not match:
        return url.lower()
    slug = f"{match.group(1)}/{match.group(2)}".lower()
    return MIRRORS.get(slug, slug)


def pick_function(
    candidates: list[tuple[str, str, int]], text: str
) -> tuple[str, str] | None:
    mentioned = []
    for path, name, count in candidates:
        if len(name) < 4:
            continue
        if re.search(rf"\b{re.escape(name)}\b", text):
            mentioned.append((path, name, count))
    if not mentioned:
        return None
    path, name, _count = max(mentioned, key=lambda item: (item[2], item[1]))
    return path, name


def nearest_changed(line: int, changed: set[int]) -> int | None:
    if not changed:
        return None
    return min(abs(line - item) for item in changed)


def load_rows(csv_path: Path) -> list[dict]:
    with csv_path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def load_pair(csv_path: Path, pair_id: str) -> dict:
    for row in load_rows(csv_path):
        if row["GHSA ID"] == pair_id:
            return row
    raise SystemExit(f"pair not found: {pair_id} in {csv_path}")


def load_oracle(path: Path | None) -> dict[str, dict]:
    if path is None or not path.is_file():
        return {}
    found = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            found[row["GHSA ID"]] = row
    return found


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> subprocess.CompletedProcess:
    merged = os.environ.copy()
    merged["GIT_TERMINAL_PROMPT"] = "0"
    if env:
        merged.update(env)
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=merged,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )


def commit_present(dest: Path, sha: str) -> bool:
    if not (dest / ".git").exists():
        return False
    return run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=dest).returncode == 0


def clone_pair(row: dict, side: str, offline: bool = False) -> Path:
    pair_id = row["GHSA ID"]
    dest = CLONES / f"{pair_id}_{side}"
    sha = row["Vulnerable Commit SHA"] if side == "pre" else row["Fix Commit SHA"]
    dest.mkdir(parents=True, exist_ok=True)
    git_dir = dest / ".git"
    if not git_dir.exists():
        if offline:
            raise SystemExit(f"offline: clone missing for {pair_id} {side}")
        init = run(["git", "init"], cwd=dest)
        if init.returncode != 0:
            raise SystemExit(init.stderr[:800])
        run(["git", "remote", "add", "origin", row["Repository URL"]], cwd=dest)
    need = {row["Vulnerable Commit SHA"].lower(), row["Fix Commit SHA"].lower()}
    for needed in need:
        if commit_present(dest, needed):
            continue
        if offline:
            raise SystemExit(f"offline: commit {needed} not present for {pair_id}")
        fetched = run(["git", "fetch", "--depth", "1", "origin", needed], cwd=dest)
        if fetched.returncode != 0:
            raise SystemExit(f"clone fetch failed: {fetched.stderr[:800]}")
    head = run(["git", "rev-parse", "HEAD"], cwd=dest)
    have = head.stdout.strip().lower() if head.returncode == 0 else ""
    if have != sha.lower():
        checked = run(["git", "checkout", "--force", sha], cwd=dest)
        if checked.returncode != 0:
            raise SystemExit(f"checkout failed: {checked.stderr[:800]}")
    return dest


def diff_path(header: str) -> str | None:
    rest = header[4:].strip()
    if rest == "/dev/null":
        return None
    if len(rest) >= 2 and rest[0] == '"' and rest[-1] == '"':
        rest = bytes(rest[1:-1], "utf-8").decode("unicode_escape")
    if rest.startswith("a/") or rest.startswith("b/"):
        rest = rest[2:]
    return rest.replace("\\", "/")


def is_excluded(path: str | None) -> bool:
    if not path:
        return False
    norm = path.replace("\\", "/")
    if norm.lower().endswith(".md"):
        return True
    return any(part.lower() in EXCLUDE_DIRS for part in norm.split("/"))


def parse_diff(text: str) -> dict:
    pre: dict[str, set[int]] = {}
    post: dict[str, set[int]] = {}
    excluded = 0
    pre_path = None
    post_path = None
    for line in text.splitlines():
        if line.startswith("diff --git "):
            pre_path = None
            post_path = None
            continue
        if line.startswith("--- "):
            pre_path = diff_path(line)
            continue
        if line.startswith("+++ "):
            post_path = diff_path(line)
            continue
        match = HUNK_RE.match(line)
        if not match or (pre_path is None and post_path is None):
            continue
        if is_excluded(pre_path) or is_excluded(post_path):
            excluded += 1
            continue
        old_start, old_count, new_start, new_count = match.groups()
        old_n = int(old_count) if old_count is not None else 1
        new_n = int(new_count) if new_count is not None else 1
        old_s, new_s = int(old_start), int(new_start)
        if pre_path:
            if old_n == 0:
                pre.setdefault(pre_path, set()).add(old_s)
            else:
                pre.setdefault(pre_path, set()).update(range(old_s, old_s + old_n))
        if post_path:
            if new_n == 0:
                post.setdefault(post_path, set()).add(new_s)
            else:
                post.setdefault(post_path, set()).update(range(new_s, new_s + new_n))
    return {"pre": pre, "post": post, "excluded_hunks": excluded}


def rename_count(clone: Path, row: dict) -> int:
    proc = run(
        [
            "git",
            "diff",
            "-M",
            "--name-status",
            "-z",
            row["Vulnerable Commit SHA"],
            row["Fix Commit SHA"],
        ],
        cwd=clone,
    )
    if proc.returncode != 0:
        return 0
    return sum(1 for part in proc.stdout.split("\0") if part[:1] in {"R", "C"})


def changed_lines(clone: Path, row: dict, side: str) -> tuple[dict[str, set[int]], dict]:
    diff = run(
        [
            "git",
            "diff",
            "-M",
            "--unified=0",
            row["Vulnerable Commit SHA"],
            row["Fix Commit SHA"],
        ],
        cwd=clone,
    )
    if diff.returncode != 0:
        raise SystemExit(f"git diff failed: {diff.stderr[:800]}")
    parsed = parse_diff(diff.stdout)
    lines = parsed[side]
    stats = {
        "excluded_hunks": parsed["excluded_hunks"],
        "diff_files": len(lines),
        "diff_lines": sum(len(values) for values in lines.values()),
        "renames": rename_count(clone, row),
    }
    return lines, stats


def mask_solidity(src: str) -> str:
    out: list[str] = []
    i = 0
    n = len(src)
    while i < n:
        if src.startswith("//", i):
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if src.startswith("/*", i):
            out.extend("  ")
            i += 2
            while i < n and not src.startswith("*/", i):
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.extend("  ")
                i += 2
            continue
        if src[i] in {'"', "'"}:
            quote = src[i]
            out.append(" ")
            i += 1
            while i < n and src[i] != quote:
                if src[i] == "\\" and i + 1 < n:
                    out.append(" ")
                    out.append("\n" if src[i + 1] == "\n" else " ")
                    i += 2
                    continue
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
            continue
        out.append(src[i])
        i += 1
    return "".join(out)


def python_functions(src: str) -> list[tuple[str, int, int]]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    boxes = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            boxes.append((node.name, node.lineno, end))
    return boxes


def solidity_kind(line: str) -> str:
    head = line.lstrip()
    for name in ("constructor", "fallback", "receive"):
        if head.startswith(name):
            return name
    return ""


def solidity_functions(src: str) -> list[tuple[str, int, int]]:
    raw = src.splitlines()
    masked = mask_solidity(src).splitlines()
    if len(masked) < len(raw):
        masked.extend("" for _ in range(len(raw) - len(masked)))
    boxes: list[tuple[str, int, int]] = []
    i = 0
    while i < len(raw):
        found = SOL_NAME_RE.match(raw[i])
        if not found:
            i += 1
            continue
        name = found.group(1) or found.group(2) or solidity_kind(raw[i])
        start = i + 1
        joined = "\n".join(masked[i:])
        brace = joined.find("{")
        semi = joined.find(";")
        if brace < 0 or (semi >= 0 and semi < brace):
            i += 1
            continue
        depth = 0
        offset = 0
        for j, line in enumerate(masked[i:]):
            for char in line:
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        boxes.append((name, start, start + j))
                        offset = j + 1
                        break
            if offset:
                break
        i += max(offset, 1)
    return boxes


def enclosing(boxes: list[tuple[int, int]], line: int) -> tuple[int, int] | None:
    hits = [box for box in boxes if box[0] <= line <= box[1]]
    if not hits:
        return None
    return min(hits, key=lambda box: box[1] - box[0])


def named_functions(clone: Path, rel: str) -> list[tuple[str, int, int]]:
    path = clone / rel
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    if rel.endswith(".py"):
        return python_functions(text)
    if rel.endswith(".sol"):
        return solidity_functions(text)
    return []


def file_functions(clone: Path, rel: str) -> list[tuple[int, int]]:
    return [(start, end) for _name, start, end in named_functions(clone, rel)]


def match_mode(
    changed: set[int], line: int, boxes: list[tuple[int, int]]
) -> str | None:
    resolved = [enclosing(boxes, item) for item in changed]
    resolved = [box for box in resolved if box]
    if resolved:
        for box in resolved:
            if box[0] <= line <= box[1]:
                return "function"
        return None
    for item in changed:
        if abs(line - item) <= BUFFER:
            return "buffer15"
    return None


def rel_path(path: str, clone: Path) -> str:
    p = path.replace("\\", "/")
    root = str(clone).replace("\\", "/")
    if p.startswith(root):
        return p[len(root) :].lstrip("/")
    if p.startswith("file:"):
        p = p.split(":", 1)[-1]
    return p.lstrip("/")


def score_findings(
    findings: list[dict],
    clone: Path,
    changed: dict[str, set[int]],
    oracle: dict | None,
) -> list[dict]:
    scored = []
    oracle_file = (oracle or {}).get("File") or ""
    oracle_fn = (oracle or {}).get("Function") or ""
    for finding in findings:
        rel = rel_path(finding["file"], clone)
        finding = {**finding, "file": rel}
        lines = changed.get(rel) or set()
        finding["nearest_changed_line"] = nearest_changed(int(finding["line"]), lines)
        if oracle is not None:
            if not oracle_fn:
                finding["tp"] = False
                finding["match_mode"] = None
                scored.append(finding)
                continue
            if rel != oracle_file:
                finding["tp"] = False
                finding["match_mode"] = None
                scored.append(finding)
                continue
            named = [
                (start, end)
                for name, start, end in named_functions(clone, rel)
                if name == oracle_fn
            ]
            line = int(finding["line"])
            if named:
                mode = "function" if any(start <= line <= end for start, end in named) else None
            else:
                file_lines = changed.get(oracle_file) or set()
                mode = "buffer15" if any(abs(line - item) <= BUFFER for item in file_lines) else None
            finding["tp"] = mode is not None
            finding["match_mode"] = mode
            scored.append(finding)
            continue
        if not lines:
            finding["tp"] = False
            finding["match_mode"] = None
            scored.append(finding)
            continue
        mode = match_mode(lines, int(finding["line"]), file_functions(clone, rel))
        finding["tp"] = mode is not None
        finding["match_mode"] = mode
        scored.append(finding)
    return scored


def parse_semgrep(payload: str, clone: Path) -> tuple[list[dict], int]:
    data = json.loads(payload or "{}")
    out = []
    for result in data.get("results") or []:
        extra = result.get("extra") or {}
        out.append(
            {
                "file": rel_path(result.get("path") or "", clone),
                "line": (result.get("start") or {}).get("line") or 0,
                "rule_id": result.get("check_id") or "",
                "severity": extra.get("severity") or "",
                "message": extra.get("message") or "",
            }
        )
    errors = len(data.get("errors") or [])
    return out, errors


def parse_sarif(payload: str, clone: Path) -> list[dict]:
    data = json.loads(payload or "{}")
    out = []
    for run_item in data.get("runs") or []:
        for result in run_item.get("results") or []:
            loc = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
            uri = (loc.get("artifactLocation") or {}).get("uri") or ""
            line = (loc.get("region") or {}).get("startLine") or 0
            msg = result.get("message") or {}
            out.append(
                {
                    "file": rel_path(uri, clone),
                    "line": line,
                    "rule_id": result.get("ruleId") or "",
                    "severity": result.get("level") or "",
                    "message": msg.get("text") or "",
                }
            )
    return out


def parse_slither(payload: str, clone: Path) -> tuple[str, list[dict]]:
    try:
        data = json.loads(payload or "{}")
    except json.JSONDecodeError:
        return "compile_error", []
    if data.get("success") is False:
        return "compile_error", []
    out = []
    for det in (data.get("results") or {}).get("detectors") or []:
        for el in det.get("elements") or []:
            mapping = el.get("source_mapping") or {}
            lines = mapping.get("lines") or [0]
            out.append(
                {
                    "file": rel_path(
                        mapping.get("filename_relative")
                        or mapping.get("filename_short")
                        or "",
                        clone,
                    ),
                    "line": lines[0],
                    "rule_id": det.get("check") or slither_detect,
                    "severity": det.get("impact") or "",
                    "message": (det.get("description") or "").split("\n", 1)[0],
                }
            )
    return "ok", out


def pick_solc(spec: str, installed: list[str]) -> str | None:
    found = VERSION_RE.search(spec)
    if not found:
        return None
    want = tuple(int(x) for x in found.groups())
    parsed = []
    for ver in installed:
        match = VERSION_RE.fullmatch(ver.strip())
        if match:
            parsed.append((tuple(int(x) for x in match.groups()), ver.strip()))
    if not parsed:
        return None
    caret = spec.strip().startswith("^") or spec.strip().startswith(">=")
    exact = VERSION_RE.fullmatch(spec.strip())
    if exact:
        for nums, ver in parsed:
            if nums == want:
                return ver
        return None
    if caret:
        same_minor = [item for item in parsed if item[0][0] == want[0] and item[0] >= want]
        if same_minor:
            return max(same_minor)[1]
    ge = [item for item in parsed if item[0] >= want]
    return max(ge)[1] if ge else None


def pragma_is_installed(spec: str, installed: list[str]) -> bool:
    if "0.8" not in spec:
        return False
    return pick_solc(spec, installed) in set(installed)


def installed_solc() -> list[str]:
    proc = run(["solc-select", "versions"])
    versions = []
    for line in (proc.stdout or "").splitlines():
        match = VERSION_RE.search(line)
        if match:
            versions.append(".".join(match.groups()))
    return versions


def first_pragma(clone: Path, changed: dict[str, set[int]]) -> str | None:
    sol_files = [path for path in changed if path.endswith(".sol") and not is_excluded(path)]
    if not sol_files:
        sol_files = [
            path.relative_to(clone).as_posix()
            for path in clone.rglob("*.sol")
            if ".git" not in path.parts and not is_excluded(path.relative_to(clone).as_posix())
        ]
    for rel in sol_files:
        path = clone / rel
        if not path.is_file():
            continue
        match = PRAGMA_RE.search(path.read_text(encoding="utf-8", errors="replace"))
        if match:
            return match.group(1).strip()
    return None


def tool_version(cmd: str) -> str:
    if cmd not in _VERSIONS:
        proc = run([cmd, "--version"])
        line = (proc.stdout or proc.stderr or "unknown").splitlines()
        _VERSIONS[cmd] = (line[0] if line else "unknown")[:160]
    return _VERSIONS[cmd]


def sha256_file(path: Path | None) -> str:
    if path is None or not path.is_file():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def scanned_list(clone: Path) -> list[str]:
    found = []
    for path in clone.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        rel = path.relative_to(clone).as_posix()
        if is_excluded(rel):
            continue
        found.append(rel)
    return sorted(found)


def python_scanner() -> str:
    return "opengrep" if shutil.which("opengrep") else "semgrep"


def run_semgrep(clone: Path, rule: Path) -> tuple[str, list[dict], str, int]:
    binary = python_scanner()
    # Scan from the clone root. A path inside this repo makes Opengrep walk up
    # to the parent git root and die on unrelated junctions.
    cmd = [binary, "--json", "--config", str(rule.resolve()), "."]
    if binary == "semgrep":
        cmd.insert(1, "--metrics=off")
    else:
        cmd.append("--disable-version-check")
    for pattern in SEMGREP_EXCLUDES:
        cmd.extend(["--exclude", pattern])
    proc = run(cmd, cwd=clone)
    try:
        findings, errors = parse_semgrep(proc.stdout, clone)
    except json.JSONDecodeError:
        return "scan_error", [], (proc.stderr or proc.stdout or "")[:800], 0
    if proc.returncode not in (0, 1) and not findings:
        # ponytail: wrong-language / empty-target scans still parse; treat as silence.
        if errors == 0:
            return "ok", [], proc.stderr or "", errors
        return "scan_error", [], proc.stderr or "", errors
    return "ok", findings, proc.stderr or "", errors


def run_codeql(
    clone: Path, pair_id: str, side: str, language: str, rule: Path, keep_db: bool
) -> tuple[str, list[dict], str]:
    db = CODEQL_DBS / f"{pair_id}_{side}"
    db.parent.mkdir(parents=True, exist_ok=True)
    created = run(
        [
            "codeql",
            "database",
            "create",
            str(db),
            f"--language={language}",
            f"--source-root={clone}",
            "--overwrite",
        ]
    )
    if created.returncode != 0:
        return "scan_error", [], created.stderr or ""
    sarif = db.parent / f"{pair_id}_{side}.sarif"
    analyzed = run(
        [
            "codeql",
            "database",
            "analyze",
            str(db),
            str(rule),
            "--format=sarif-latest",
            f"--output={sarif}",
            "--threads=0",
        ]
    )
    payload = sarif.read_text(encoding="utf-8") if sarif.exists() else "{}"
    sarif.unlink(missing_ok=True)
    if not keep_db and db.exists():
        shutil.rmtree(db, ignore_errors=True)
    if analyzed.returncode != 0:
        return "scan_error", [], analyzed.stderr or ""
    return "ok", parse_sarif(payload, clone), analyzed.stderr or ""


def run_slither(
    clone: Path,
    changed: dict[str, set[int]],
    detect: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> tuple[str, list[dict], str, str]:
    slither_detect = detect or SLITHER_DETECT
    spec = first_pragma(clone, changed)
    env: dict[str, str] = dict(extra_env or {})
    solc_version = ""
    if spec:
        version = pick_solc(spec, installed_solc())
        if not version:
            return "compile_error", [], "", ""
        selected = run(["solc-select", "use", version])
        if selected.returncode != 0:
            return "compile_error", [], selected.stderr or "", version
        env["SOLC_VERSION"] = version
        solc_version = version
    json_path = clone / ".slither_out.json"
    # Foundry projects need forge remappings. solc mode rejects a directory and
    # still calls `forge config` when foundry.toml is present.
    if (clone / "foundry.toml").is_file():
        if shutil.which("forge") is None:
            return "compile_error", [], "forge is not on PATH", solc_version
        cmd = [
            "slither",
            ".",
            "--json",
            str(json_path),
            "--detect",
            slither_detect,
            "--compile-force-framework",
            "foundry",
        ]
        try:
            proc = run(cmd, cwd=clone, env=env or None)
            if not json_path.exists() or json_path.stat().st_size == 0:
                return "compile_error", [], proc.stderr or "", solc_version
            payload = json_path.read_text(encoding="utf-8", errors="replace")
        finally:
            json_path.unlink(missing_ok=True)
        outcome, findings = parse_slither(payload, clone)
        return outcome, findings, proc.stderr or "", solc_version
    # solc mode rejects a directory target, so each changed .sol file is compiled.
    targets = [
        rel
        for rel in changed
        if rel.endswith(".sol") and not is_excluded(rel) and (clone / rel).is_file()
    ]
    if not targets:
        return "compile_error", [], "no solidity file in the fix diff", solc_version
    json_path = clone / ".slither_out.json"
    findings: list[dict] = []
    errors: list[str] = []
    compiled = False
    for target in targets:
        cmd = [
            "slither",
            target,
            "--json",
            str(json_path),
            "--detect",
            slither_detect,
            "--compile-force-framework",
            "solc",
        ]
        try:
            proc = run(cmd, cwd=clone, env=env or None)
            if not json_path.exists() or json_path.stat().st_size == 0:
                errors.append((proc.stderr or "")[:500])
                continue
            payload = json_path.read_text(encoding="utf-8", errors="replace")
        finally:
            json_path.unlink(missing_ok=True)
        outcome, found = parse_slither(payload, clone)
        if outcome != "ok":
            errors.append((proc.stderr or "")[:500])
            continue
        compiled = True
        findings.extend(found)
    if not compiled:
        return "compile_error", [], "\n".join(errors), solc_version
    return "ok", findings, "", solc_version


def trivial_findings(clone: Path) -> list[dict]:
    out = []
    for rel in scanned_list(clone):
        if not (rel.endswith(".py") or rel.endswith(".sol")):
            continue
        for name, start, _end in named_functions(clone, rel):
            out.append(
                {
                    "file": rel,
                    "line": start,
                    "rule_id": "trivial.every-function",
                    "severity": "INFO",
                    "message": name,
                }
            )
    return out


def result_payload(
    row: dict,
    target: str,
    side: str,
    outcome: str,
    scored: list[dict],
    telemetry: dict,
    control: str,
    unresolved: bool,
) -> dict:
    return {
        "pair": row["GHSA ID"],
        "target": target,
        "side": side,
        "outcome": outcome,
        "control": control,
        "category": row.get("Category") or "",
        "repository": row.get("Repository URL") or "",
        "cwe": row.get("CWE ID") or "",
        "oracle_unresolved": unresolved,
        "findings": [
            {
                "file": item["file"],
                "line": item["line"],
                "rule_id": item["rule_id"],
                "severity": item["severity"],
                "message": item["message"],
                "nearest_changed_line": item.get("nearest_changed_line"),
            }
            for item in scored
        ],
        "matches": [
            {
                "file": item["file"],
                "line": item["line"],
                "rule_id": item["rule_id"],
                "match_mode": item["match_mode"],
            }
            for item in scored
            if item.get("tp")
        ],
        "tp": any(item.get("tp") for item in scored),
        "finding_count": len(scored),
        "tp_count": sum(1 for item in scored if item.get("tp")),
        "telemetry": telemetry,
    }


def evaluate(
    row: dict,
    target: str,
    side: str,
    rule: Path | None,
    oracle_row: dict | None,
    control: str,
    offline: bool,
    keep_db: bool,
    source_root: Path | None,
    donor: dict | None,
    slither_detect: str | None = None,
    slither_env: dict[str, str] | None = None,
) -> dict:
    started = time.perf_counter()
    clone = source_root if source_root else clone_pair(row, side, offline=offline)
    changed, stats = changed_lines(clone, row, side)
    score_changed = changed
    score_oracle = oracle_row
    if control == "shuffled":
        if donor is None:
            raise SystemExit(f"no donor pair for shuffled control {row['GHSA ID']}")
        score_changed, donor_stats = changed_lines(clone, donor, side)
        stats["shuffled_from"] = donor["GHSA ID"]
        stats["shuffled_diff_lines"] = donor_stats["diff_lines"]
        score_oracle = None
    unresolved = bool(oracle_row is not None and not (oracle_row.get("Function") or "").strip())
    language = "python" if row["Category"].startswith("web2") else "solidity"
    solc_version = ""
    semgrep_errors = 0
    stderr = ""
    if control == "empty":
        outcome, findings = "ok", []
    elif control == "trivial":
        outcome, findings = "ok", trivial_findings(clone)
    elif target == "semgrep":
        outcome, findings, stderr, semgrep_errors = run_semgrep(
            clone, rule if rule else NATIVE_SEMGREP
        )
    elif target == "codeql":
        outcome, findings, stderr = run_codeql(
            clone,
            row["GHSA ID"],
            side,
            language,
            rule if rule else NATIVE_CODEQL,
            keep_db,
        )
    else:
        outcome, findings, stderr, solc_version = run_slither(
            clone, changed, detect=slither_detect, extra_env=slither_env
        )
    scored = score_findings(findings, clone, score_changed, score_oracle) if outcome == "ok" else []
    files = scanned_list(clone)
    head = run(["git", "rev-parse", "HEAD"], cwd=clone)
    tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=clone)
    tool = {"semgrep": python_scanner(), "codeql": "codeql", "slither": "slither"}[target]
    version = tool_version(tool) if control not in {"empty", "trivial"} else control
    if target == "semgrep" and control not in {"empty", "trivial"}:
        version = f"{tool} {version}"
    telemetry = {
        "tool_version": version,
        "rule_sha256": sha256_file(rule) if rule and control not in {"empty", "trivial"} else control,
        "clone_head": head.stdout.strip(),
        "clone_tree": tree.stdout.strip(),
        "solc_version": solc_version,
        "scanned_files_sha256": hashlib.sha256("\n".join(files).encode()).hexdigest(),
        "scanned_file_count": len(files),
        "diff_files": stats["diff_files"],
        "diff_lines": stats["diff_lines"],
        "excluded_hunks": stats["excluded_hunks"],
        "renames": stats["renames"],
        "alarm_count": len(scored),
        "semgrep_errors": semgrep_errors,
        "runtime_seconds": round(time.perf_counter() - started, 3),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
    }
    if "shuffled_from" in stats:
        telemetry["shuffled_from"] = stats["shuffled_from"]
    return result_payload(row, target, side, outcome, scored, telemetry, control, unresolved)


def donor_for(rows: list[dict], row: dict) -> dict | None:
    same = [
        item
        for item in rows
        if item["GHSA ID"] != row["GHSA ID"]
        and repo_key(item["Repository URL"]) == repo_key(row["Repository URL"])
    ]
    if not same:
        same = [
            item
            for item in rows
            if item["GHSA ID"] != row["GHSA ID"] and item["Category"] == row["Category"]
        ]
    if not same:
        return None
    same.sort(key=lambda item: item["GHSA ID"])
    later = [item for item in same if item["GHSA ID"] > row["GHSA ID"]]
    return (later or same)[0]


def emit_oracle(csv_path: Path, out_path: Path, offline: bool) -> None:
    rows = load_rows(csv_path)
    written = []
    for row in rows:
        clone = clone_pair(row, "pre", offline=offline)
        changed, _stats = changed_lines(clone, row, "pre")
        candidates = []
        for rel, lines in changed.items():
            for name, start, end in named_functions(clone, rel):
                count = sum(1 for line in lines if start <= line <= end)
                if count:
                    candidates.append((rel, name, count))
        text = f"{row.get('Summary') or ''} {row.get('Description') or ''}"
        picked = pick_function(candidates, text)
        written.append(
            {
                "GHSA ID": row["GHSA ID"],
                "File": picked[0] if picked else "",
                "Function": picked[1] if picked else "",
                "CWE": row.get("CWE ID") or "",
            }
        )
        print(
            f"oracle {row['GHSA ID']} {written[-1]['File']} {written[-1]['Function']}",
            file=sys.stderr,
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["GHSA ID", "File", "Function", "CWE"])
        writer.writeheader()
        writer.writerows(written)
    print(f"wrote {out_path} rows={len(written)}")


def release_name(target: str, pair: str, side: str, control: str) -> Path:
    prefix = f"{control}_" if control else ""
    return RELEASE / f"{prefix}{target}_{pair}_{side}.json"


def batch_release(args: argparse.Namespace) -> None:
    rows = load_rows(Path(args.csv))
    want = "web2_mcp" if args.target == "semgrep" else "web3_toctou_cei"
    if args.target == "codeql":
        raise SystemExit("release batch does not score CodeQL")
    selected = [row for row in rows if row["Category"] == want]
    oracle = load_oracle(Path(args.oracle) if args.oracle else None)
    rule = Path(args.rule) if args.rule else None
    RELEASE.mkdir(parents=True, exist_ok=True)
    controls = ("", "empty", "trivial", "shuffled")
    for row in selected:
        donor = donor_for(selected, row)
        for side in ("pre", "post"):
            for control in controls:
                if control == "shuffled" and donor is None:
                    print(f"skip shuffled {row['GHSA ID']} {side}", file=sys.stderr)
                    continue
                try:
                    payload = evaluate(
                        row,
                        args.target,
                        side,
                        rule,
                        oracle.get(row["GHSA ID"]),
                        control,
                        args.offline,
                        args.keep_db,
                        Path(args.source_root).resolve() if args.source_root else None,
                        donor,
                    )
                except SystemExit as exc:
                    payload = {
                        "pair": row["GHSA ID"],
                        "target": args.target,
                        "side": side,
                        "outcome": "clone_error",
                        "control": control,
                        "category": row.get("Category") or "",
                        "repository": row.get("Repository URL") or "",
                        "cwe": row.get("CWE ID") or "",
                        "oracle_unresolved": False,
                        "error": str(exc),
                        "tp": False,
                        "finding_count": 0,
                        "tp_count": 0,
                        "findings": [],
                        "matches": [],
                        "telemetry": {},
                    }
                path = release_name(args.target, row["GHSA ID"], side, control)
                path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
                print(
                    f"{path.name} outcome={payload['outcome']} tp={payload['tp']}",
                    file=sys.stderr,
                )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["semgrep", "codeql", "slither"])
    parser.add_argument("--pair")
    parser.add_argument("--side", choices=["pre", "post"])
    parser.add_argument("--keep-db", action="store_true")
    parser.add_argument("--csv", default=str(DEFAULT_CSV))
    parser.add_argument("--rule")
    parser.add_argument("--source-root", help="scan this checkout instead of cloning")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--oracle")
    parser.add_argument("--control", choices=["empty", "trivial", "shuffled"], default="")
    parser.add_argument("--emit-oracle")
    parser.add_argument("--batch", choices=["release"])
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        self_check()
        return
    if args.emit_oracle:
        emit_oracle(Path(args.csv), Path(args.emit_oracle), args.offline)
        return
    if args.batch:
        if not args.target:
            raise SystemExit("--batch requires --target")
        batch_release(args)
        return
    if not (args.target and args.pair and args.side):
        raise SystemExit("need --target --pair --side, --emit-oracle, --batch, or --self-check")
    rows = load_rows(Path(args.csv))
    row = load_pair(Path(args.csv), args.pair)
    oracle = load_oracle(Path(args.oracle) if args.oracle else None).get(args.pair)
    donor = donor_for(rows, row) if args.control == "shuffled" else None
    payload = evaluate(
        row,
        args.target,
        args.side,
        Path(args.rule) if args.rule else None,
        oracle,
        args.control,
        args.offline,
        args.keep_db,
        Path(args.source_root).resolve() if args.source_root else None,
        donor,
    )
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
