# VeraptosBench-mini — Pre-registration

Registered: 2026-11-01, before held-out selection and before any scanner scoring run.

This document locks the hypotheses, the scoring rule, and the acceptance bars. The bars below were locked by the reviewer on 2026-11-01, before `HELD_OUT_DATASET_SHA256` is written and before any scoring run. Changing them after seeing scores is a protocol violation.

Source plan: [`docs/VERAPTOS_BENCH_MASTER_PLAN.md`](docs/VERAPTOS_BENCH_MASTER_PLAN.md).

## Locked scoring rule

A hit is a true positive only when the reported file and line intersect the fix commit under this rule:

1. **Function bounding box (primary).** The reported line lies inside the function that contains a line changed by the fix commit.
2. **±15 line buffer (fallback).** Used only when the function bounds cannot be resolved. The reported line is within 15 lines of a changed line in that file.

Strict equality with a changed line is not the scoring rule. Patches often insert a guard above the sink. Each result records `match_mode` as `function` or `buffer15`.

Phase 3 checks the runner with one hardcoded native rule per engine (Semgrep, CodeQL CLI, Slither). Veraptos-compiled rules are scored in Phase 6, not Phase 3.

The metamorphic mutator (H3) applies only to Web2 Python fixtures in this sprint.

## Hypotheses

### H1 — Determinism

The Veraptos compiler is deterministic on a fixed input. Three invocations on the same input produce byte-identical artifacts. The acceptance check is equality of the three SHA-256 digests. Any mismatch fails H1.

### H2 — Fidelity

On the held-out pair list, each engine (Semgrep, CodeQL CLI, Slither) is measured separately:

- **Pre-patch recall:** fraction of vulnerable sides (`--side pre`) with at least one true positive under the locked scoring rule.
- **Post-patch silence:** fraction of fixed sides (`--side post`) with zero true positives under the same rule.

A compile failure (`compile_error`) is not a silent negative and is not counted as a true positive. It is reported as its own outcome.

### H3 — Metamorphic robustness (Web2 Python only)

For each Web2 fixture and its native rule:

- Semantics-preserving mutations still fire: variable renaming, helper-function wrapping, import aliasing.
- The semantics-altering mutation goes silent: an explicit `if` guard or sanitizer inserted before the sink.

Web3 fixtures are out of scope for this sprint.

### H4 — LLM baseline

A fixed prompt is sent five times per invariant at `temperature=0.0` through the OpenAI Python client with `base_url=https://openrouter.ai/api/v1`. The key is `OPENROUTER_API_KEY` from a local `.env` and is never written into this file or into source. Models: `openai/gpt-4o` and `anthropic/claude-3.5-sonnet`.

Recorded outcomes:

- Syntax-failure rate after `semgrep --validate` and `codeql query compile` on the raw outputs.
- Pre-patch recall of the syntax-valid outputs, using the same scoring rule as H2, compared with the Veraptos-authored rules from Phase 6.

Directional claim, registered before any API call: at temperature 0.0, both models have a higher syntax-failure rate and a lower pre-patch recall than the Veraptos-authored rules. The size of that gap is not registered here.

## Thresholds (locked 2026-11-01, before the held-out hash)

| Hypothesis | Metric | Bar |
|---|---|---|
| H1 | 3-run SHA-256 equality | 100% (all three equal) |
| H2 | Pre-patch recall, per engine | >= 70% |
| H2 | Post-patch silence, per engine | >= 85% |
| H3 | Preserving mutations that still fire | >= 90% of baseline pre-patch detections |
| H3 | Altering mutations that go silent | 100% (0% firing on guarded mutants) |
| H4 | Syntax-failure rate vs Veraptos | Veraptos: 0% \| LLM baseline: >= 20% |
| H4 | Pre-patch recall vs Veraptos | Veraptos recall >= LLM recall + 15% |

## Held-out dataset

`V1_HELD_OUT_DATASET_SHA256 = 8316802fb09b6a0595d58472ceb810656cf71a8549b495d5641c98dcc478222d`

`HELD_OUT_DATASET_SHA256 = 8316802fb09b6a0595d58472ceb810656cf71a8549b495d5641c98dcc478222d`

`HELD_OUT_ORACLE_SHA256 = <TBD>`

The active `HELD_OUT_DATASET_SHA256` line is v1 until a v2 file passes the size gate below. v1 results stay in the record. `scripts/hash_heldout.py --write` replaces only the active line, and only after that gate. The archive copy of the v1 CSVs is `data/v1/`.

## Amendment 2026-11-01 — v2 protocol, locked before any v2 score

v1 is not edited. v2 exists because the v1 split leaks and the v1 labels do not match the rule class. Evidence, recorded before the re-harvest: dev GHSA-rwrf fix `5ebdfed4` is held-out GHSA-84m7's vulnerable SHA; dev GHSA-xrc4 fix `8ea1fc87` is held-out GHSA-7grf's vulnerable SHA. Held-out Web2 is two FastMCP repos that are one project. Held-out Web3 is OpenZeppelin contracts plus its upgradeable mirror. The v1 Web3 Semgrep run was recall 0/8 and silence 8/8, which a never-firing rule can produce. Re-harvesting after that result is a forking path, so this amendment is the lock and v1 is kept.

Rules fixed before v2 scoring:

1. Each pair stores the advisory CWE. Recall is also reported per CWE.
2. The split is one connected component at a time. Pairs connect when they share a repository after mirror normalization, or when one pair's fix SHA is another pair's vulnerable SHA. Mirrors: `jlowin/fastmcp` with `PrefectHQ/fastmcp`; `openzeppelin-contracts` with `openzeppelin-contracts-upgradeable`. The whole component is dev or held-out.
3. A held-out component must have every advisory published after 2024-07-31. That is the later of the two v2 model cutoffs (gpt-4o-mini, October 2023; Claude 3.5 Haiku, July 2024). Any earlier member sends the whole component to dev.
4. Decision rule: the locked bars apply to the point estimate. The Wilson 95% interval uses z = 1.95996 and is reported beside the point. A point that clears a bar while the lower bound does not is reported as "point meets bar, interval does not". At N = 20 the lower bound of 20/20 is about 0.84, so the 85% silence bar cannot be cleared by the interval. That limit is registered here.
5. The primary estimand is pairs whose pre and post outcomes are both `ok`. `compile_error` is not in those denominators. Analyzability is ok sides / all sides, with a worst bound (`compile_error` as a miss or an alarm) and a best bound (`compile_error` as a hit or silence).
6. The primary H2 metric is fix discrimination: pre-patch true positive and post-patch silence. Recall and silence are secondary. Holm correction is applied across the engine rows' one-sided binomial tests of the 70% recall bar. H4 on the same pairs uses McNemar's exact test.
7. The oracle file is `data/held_out_oracle.csv` (GHSA ID, File, Function, CWE), hashed before any v2 scanner run. The function is a name of at least 4 characters that appears as a whole word in the advisory summary or description and that contains a changed line. If no such function exists, the pair is unresolved and is left out of the H2 denominators. Hunks under `test/`, `tests/`, `mocks/`, `docs/`, `examples/`, and `*.md` are excluded and counted. Diff parsing uses `git diff -M` and the `---` / `+++` paths, including renames.
8. Negative controls use the same matcher: an empty rule, a trivial every-function rule, and a shuffled oracle (another pair's diff in the same repository). The report does not call H2 a pass when the real rule's fix discrimination does not exceed the trivial rule.
9. H3 is inconclusive unless the unmutated rule has at least 10 pre-patch detections. The altering mutant removes the sink call. It does not insert the literal `sink_guard`. Preserving mutants are scope-aware rename, a wrap that keeps `*args`/`**kwargs` and `async`, and an alias of the sink's module.
10. H4 asks for the same invariant text the compiler exports, as Python Semgrep and Python CodeQL. The harness supplies one unrelated few-shot and the CodeQL qlpack scaffold. Ten paraphrased prompts per model at temperature 0.0. Models: `openai/gpt-4o-mini` and `anthropic/claude-3-5-haiku-20241022`. Report pass@1, pass@3 with the validator error fed back, missing qlpack, hallucinated imports, the returned model id, and `semgrep --test` on `benchmarks/dev_fixtures/`. API errors are not syntax failures.

## Addendum 2026-11-02 — Library-on-v1 (locked before library batch)

Frozen dataset: `HELD_OUT_DATASET_SHA256` unchanged (`8316802f…`). No edits to v1 pair labels or oracle ground truth.

**Repository:** `https://github.com/Tito0015/veraptos-threat-library` at git SHA `78b718d72bce1521593774c59b03c0e4edd7088e` (paths below relative to repo root; rules are **not** copied into the benchmark tree).

**Estimand:** For each library rule, run the same diff-intersection matcher as H2 on v1 held-out pairs. Pairs are **out-of-class** for these showcase rules (MCP Python advisories vs GraphQL/DOM/FastAPI rules; OpenZeppelin patch classes vs DVD flash-loan detectors). The primary read is descriptive recall/silence/fix-discrimination counts, not “DVD detector failed.”

**Arms (control = real rule only; no empty/trivial/shuffled in this batch):**

| Rule id | Engine | Path / detect |
|---|---|---|
| `graphql-ssrf` | Opengrep | `web2-opengrep/01-graphql-ssrf/graphql-ssrf.yaml` |
| `dom-xss-postmessage` | Opengrep | `web2-opengrep/02-dom-xss-postmessage/dom-xss-postmessage.yaml` |
| `mass-assignment-fastapi` | Opengrep | `web2-opengrep/03-mass-assignment-fastapi/mass-assignment-fastapi.yaml` |
| `express-auth-bypass` | Opengrep | `web2-opengrep/04-express-auth-bypass/express-auth-bypass.yaml` |
| `jwt-none-alg-go` | Opengrep | `web2-opengrep/05-jwt-none-alg-go/jwt-none-alg-go.yaml` |
| `veraptos-truster-arbitrary-call` | Slither | `--detect veraptos-truster-arbitrary-call` |
| `veraptos-side-entrance-state-hijack` | Slither | `--detect veraptos-side-entrance-state-hijack` |
| `veraptos-rewarder-snapshot-manipulation` | Slither | `--detect veraptos-rewarder-snapshot-manipulation` |
| `veraptos-puppet-spot-oracle` | Slither | `--detect veraptos-puppet-spot-oracle` |
| `veraptos-selfie-governance-snapshot` | Slither | `--detect veraptos-selfie-governance-snapshot` |

Web2 rules run on `web2_mcp` pairs only; Web3 detectors on `web3_toctou_cei` only. Wrong-language scans with zero findings count as `ok` / silence, not `scan_error`.

## Addendum 2026-11-02 — Fair baselines pending (not scored yet)

1. Community Opengrep/Semgrep rules by **registry id + upstream commit** only (no vendored rule text).
2. CodeQL default suites on public clones for these pairs.
3. LLM held-out **pair recall** (beyond H4 syntax pass@k).
4. Time-boxed hand-written expert rule per domain (author + time cap pre-registered).

v2 size gate: the active hash changes only when `data/held_out_pairs.csv` has at least 20 `web2_mcp` rows and 20 `web3_toctou_cei` rows. Otherwise the active hash stays at v1 and v2 is not scored. Pairs are not invented to fill the gate. Web3 harvest keeps a row only when the fix diff contains a `.sol` file, the advisory text matches reentrancy, checks-effects-interactions, access control, or a state write, and the pragma selects an installed 0.8 solc (`0.8.10`, `0.8.20`, `0.8.28`). Dropped rows are counted.
