#!/usr/bin/env python3
"""LibCST mutants for one Web2 Python fixture.

ponytail: Web3 Solidity mutation is deferred this sprint. Upgrade path: a
solc-ast or Slither mutator for .sol fixtures.

Four mutants, each applied to the original source:
  rename     scope-local validated_request -> validated_request_mut in _receive_loop
  wrap       move the first model_validate call into _mut_validate(*args, **kwargs)
  alias      import <sink module> as <sink module>_mut
  guard      replace model_validate(...) with its payload (the sink call is removed)

H3 is inconclusive unless the unmutated rule records at least MIN_BASELINE_DETECTIONS
pre-patch hits. A mutant that changes nothing is a failure, not a silent pass.
"""

from __future__ import annotations

import argparse
import py_compile
import shutil
import sys
import tempfile
from pathlib import Path

import libcst as cst
from libcst.metadata import MetadataWrapper, ParentNodeProvider, ScopeProvider

ROOT = Path(__file__).resolve().parents[1]
SINK_FN = "_receive_loop"
RENAME_OLD = "validated_request"
RENAME_NEW = "validated_request_mut"
HELPER = "_mut_validate"
MIN_BASELINE_DETECTIONS = 10


def self_check() -> None:
    src = (
        "import sinkmod\n"
        "import logging\n"
        "class S:\n"
        "    async def _receive_loop(self, **kwargs):\n"
        "        self.validated_request = 1\n"
        "        validated_request = await sinkmod.model_validate(message, strict=True)\n"
        "        logging.warning(validated_request, validated_request=1)\n"
        "        other = sinkmod.model_validate(message)\n"
        "def outer():\n"
        "    validated_request = 1\n"
    )
    renamed = apply_rename(src)
    wrapped = apply_wrap(src)
    aliased = apply_alias(src)
    guarded = apply_guard(src)
    for label, code in (
        ("rename", renamed),
        ("wrap", wrapped),
        ("alias", aliased),
        ("guard", guarded),
    ):
        compiles(code, label)
    assert "validated_request_mut" in renamed
    assert "self.validated_request = 1" in renamed
    assert "validated_request=1" in renamed
    assert "def outer():\n    validated_request = 1" in renamed
    assert "async def _mut_validate(*args, **kwargs):" in wrapped
    assert "return await sinkmod.model_validate(*args, **kwargs)" in wrapped
    assert "_mut_validate(message, strict=True)" in wrapped
    assert "import sinkmod as sinkmod_mut" in aliased
    assert "sinkmod_mut.model_validate" in aliased
    assert "import logging\n" in aliased
    assert "logging_mut" not in aliased
    assert "model_validate" not in guarded
    assert "sink_guard" not in guarded
    assert MIN_BASELINE_DETECTIONS == 10
    print("self-check ok", file=sys.stderr)


def compiles(src: str, label: str) -> None:
    path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(src)
            path = handle.name
        py_compile.compile(path, doraise=True)
    except py_compile.PyCompileError as exc:
        raise SystemExit(f"{label} does not compile: {exc}") from exc
    finally:
        if path:
            Path(path).unlink(missing_ok=True)


def in_sink(stack: list[bool]) -> bool:
    return bool(stack and stack[-1])


class _Scope(cst.CSTTransformer):
    def __init__(self) -> None:
        self.stack: list[bool] = []
        self.applied = 0

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        inside = in_sink(self.stack) or node.name.value == SINK_FN
        self.stack.append(inside)
        return True

    def leave_FunctionDef(
        self, original: cst.FunctionDef, updated: cst.FunctionDef
    ) -> cst.FunctionDef:
        self.stack.pop()
        return updated


class Rename(_Scope):
    METADATA_DEPENDENCIES = (ScopeProvider, ParentNodeProvider)

    def leave_Name(self, original: cst.Name, updated: cst.Name) -> cst.Name:
        if not in_sink(self.stack) or updated.value != RENAME_OLD:
            return updated
        parent = self.get_metadata(ParentNodeProvider, original, None)
        if isinstance(parent, cst.Attribute) and parent.attr is original:
            return updated
        if isinstance(parent, cst.Arg) and parent.keyword is original:
            return updated
        scope = self.get_metadata(ScopeProvider, original, None)
        if scope is None or RENAME_OLD not in scope:
            return updated
        self.applied += 1
        return updated.with_changes(value=RENAME_NEW)


class Wrap(_Scope):
    def __init__(self) -> None:
        super().__init__()
        self.helper: cst.FunctionDef | None = None

    def leave_SimpleStatementLine(
        self, original: cst.SimpleStatementLine, updated: cst.SimpleStatementLine
    ) -> cst.SimpleStatementLine:
        found = assign_call(updated)
        if self.helper is not None or not in_sink(self.stack) or found is None:
            return updated
        call, awaited = found
        func_src = cst.Module([]).code_for_node(call.func).strip()
        header = "async def" if awaited else "def"
        await_kw = "await " if awaited else ""
        self.helper = cst.parse_statement(
            f"{header} {HELPER}(*args, **kwargs):\n"
            f"    return {await_kw}{func_src}(*args, **kwargs)\n"
        )
        new_call = cst.Call(func=cst.Name(HELPER), args=list(call.args))
        value = cst.Await(new_call) if awaited else new_call
        assign = updated.body[0]
        assert isinstance(assign, cst.Assign)
        return updated.with_changes(body=[assign.with_changes(value=value)])

    def leave_FunctionDef(
        self, original: cst.FunctionDef, updated: cst.FunctionDef
    ) -> cst.FunctionDef:
        updated = super().leave_FunctionDef(original, updated)
        if original.name.value == SINK_FN and self.helper is not None:
            updated = updated.with_changes(
                body=updated.body.with_changes(body=(self.helper, *updated.body.body))
            )
            self.applied += 1
            self.helper = None
        return updated


class Alias(cst.CSTTransformer):
    def __init__(self, module: str) -> None:
        self.module = module
        self.applied = 0

    def leave_Import(self, original: cst.Import, updated: cst.Import) -> cst.Import:
        names = []
        for alias in original.names:
            if (
                isinstance(alias.name, cst.Name)
                and alias.name.value == self.module
                and alias.asname is None
            ):
                names.append(
                    alias.with_changes(asname=cst.AsName(cst.Name(self.module + "_mut")))
                )
                self.applied += 1
            else:
                names.append(alias)
        return updated.with_changes(names=names)

    def leave_Name(self, original: cst.Name, updated: cst.Name) -> cst.Name:
        parent_ok = updated.value == self.module
        if not parent_ok:
            return updated
        return updated.with_changes(value=self.module + "_mut")


class Guard(_Scope):
    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.BaseExpression:
        func = updated.func
        if (
            in_sink(self.stack)
            and isinstance(func, cst.Attribute)
            and func.attr.value == "model_validate"
            and updated.args
        ):
            self.applied += 1
            return updated.args[0].value
        return updated


def assign_call(stmt: cst.SimpleStatementLine) -> tuple[cst.Call, bool] | None:
    if len(stmt.body) != 1 or not isinstance(stmt.body[0], cst.Assign):
        return None
    value = stmt.body[0].value
    awaited = isinstance(value, cst.Await)
    if awaited:
        value = value.expression
    if (
        isinstance(value, cst.Call)
        and isinstance(value.func, cst.Attribute)
        and value.func.attr.value == "model_validate"
        and value.args
    ):
        return value, awaited
    return None


def sink_module(src: str) -> str | None:
    module = cst.parse_module(src)
    imported: set[str] = set()

    class Imports(cst.CSTVisitor):
        def visit_Import(self, node: cst.Import) -> bool:
            for alias in node.names:
                if isinstance(alias.name, cst.Name):
                    imported.add(alias.name.value)
            return False

    class Calls(cst.CSTVisitor):
        def __init__(self) -> None:
            self.roots: list[str] = []

        def visit_Call(self, node: cst.Call) -> bool:
            func = node.func
            if not (isinstance(func, cst.Attribute) and func.attr.value == "model_validate"):
                return True
            root = func.value
            while isinstance(root, cst.Attribute):
                root = root.value
            if isinstance(root, cst.Name):
                self.roots.append(root.value)
            return True

    module.visit(Imports())
    calls = Calls()
    module.visit(calls)
    for name in calls.roots:
        if name in imported:
            return name
    return None


def _code(src: str, transformer: cst.CSTTransformer) -> tuple[str, int]:
    wrapper = MetadataWrapper(cst.parse_module(src))
    updated = wrapper.visit(transformer)
    return updated.code, transformer.applied


def apply_rename(src: str) -> str:
    code, applied = _code(src, Rename())
    if applied <= 0:
        raise SystemExit("rename applied nothing")
    return code


def apply_wrap(src: str) -> str:
    code, applied = _code(src, Wrap())
    if applied <= 0:
        raise SystemExit("wrap applied nothing")
    return code


def apply_alias(src: str) -> str:
    module = sink_module(src)
    if not module:
        raise SystemExit("alias found no imported sink module")
    # Rebuild imports from the original tree, then rename uses. leave_Name would
    # also rewrite the import target, so the import pass uses original.names.
    code, applied = _code(src, Alias(module))
    if applied <= 0:
        raise SystemExit("alias applied nothing")
    return code


def apply_guard(src: str) -> str:
    code, applied = _code(src, Guard())
    if applied <= 0:
        raise SystemExit("guard applied nothing")
    return code


MUTATIONS = {
    "rename": apply_rename,
    "wrap": apply_wrap,
    "alias": apply_alias,
    "guard": apply_guard,
}


def snippet(src: str) -> str:
    lines = src.splitlines()
    keep = []
    for i, line in enumerate(lines, start=1):
        if any(
            token in line
            for token in (
                "def _receive_loop",
                "def _mut_validate",
                "async def _mut_validate",
                "model_validate",
                "validated_request",
                "import ",
            )
        ):
            start = max(1, i - 1)
            end = min(len(lines), i + 2)
            keep.append("\n".join(f"{n:4d}| {lines[n - 1]}" for n in range(start, end + 1)))
    seen: set[str] = set()
    out = []
    for block in keep:
        if block not in seen:
            seen.add(block)
            out.append(block)
    return "\n\n".join(out)


def write_mutants(clone: Path, out_root: Path) -> None:
    rel = Path("src/mcp/shared/session.py")
    original = (clone / rel).read_text(encoding="utf-8")
    print("===== before =====")
    print(snippet(original))
    for name, fn in MUTATIONS.items():
        dest = out_root / name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(clone, dest)
        mutated = fn(original)
        compiles(mutated, name)
        (dest / rel).write_text(mutated, encoding="utf-8", newline="\n")
        print(f"===== {name} =====")
        print(snippet(mutated))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--clone", type=Path)
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "benchmarks" / "mutants" / "GHSA-3qhf-m339-9g5v",
    )
    args = parser.parse_args()
    self_check()
    if args.self_check and args.clone is None:
        return
    if args.clone is None:
        raise SystemExit("need --clone or --self-check")
    write_mutants(args.clone, args.out)


if __name__ == "__main__":
    main()
