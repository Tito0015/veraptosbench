# VeraptosBench-mini results

## v1 archive

v1 hash `8316802fb09b6a0595d58472ceb810656cf71a8549b495d5641c98dcc478222d`.
An earlier Semgrep run on these 8 Solidity pairs scored recall 0/8 = 0.00 [0.00, 0.32] and silence 8/8 = 1.00 [0.68, 1.00]. That row is not the Web3 measurement. Semgrep is Web2 Python only. Web3 is the Slither row.

## v2 harvest gate

Status: GATE_FAIL. The active held-out hash stays at v1, and v2 pairs were not scanned.
Candidate held-out counts: web2_mcp=12, web3_toctou_cei=0. Need 20 and 20.
Candidate dev counts: web2_mcp=35, web3_toctou_cei=1. Raw rows kept: 48.
Dropped before the split: compare_failed=2, keyword=17, no_fix_or_parent=11.

## H2 — frozen v1 held-out

The primary estimand is pairs with both sides `ok` and a resolved oracle function.
Fix discrimination means a pre-patch true positive and a post-patch silence.
Wilson intervals use z = 1.95996. `compile_error` is not in the recall, silence, or fix-discrimination denominators.

| Engine | Domain | N | Fix discrimination | Wilson 95% | Pre-patch recall | Wilson 95% | Post-patch silence | Wilson 95% | compile_error sides |
|---|---|---|---|---|---|---|---|---|---|
| opengrep | Python | 7 | 0/7 = 0.00 | [0.00, 0.35] | 1/7 = 0.14 | [0.03, 0.51] | 6/7 = 0.86 | [0.49, 0.97] | 0 |
| slither | Solidity | 8 | 0/8 = 0.00 | [0.00, 0.32] | 0/8 = 0.00 | [0.00, 0.32] | 8/8 = 1.00 | [0.68, 1.00] | 0 |

## H2 decision

### opengrep on Python

H2 withheld: trivial control missing
Recall bar: point does not meet bar.
Silence bar: point meets bar, interval does not.
Fix-discrimination point against 70%: point does not meet bar.
Analyzability: 14/14 = 1.00. Unresolved oracle pairs excluded: 0. clone_error sides: 0.

Worst/best recall if non-ok pairs count against/for the tool: 1/7 = 0.14 / 1/7 = 0.14.
Worst/best silence: 6/7 = 0.86 / 6/7 = 0.86.
Repo-cluster bootstrap 95% for fix discrimination: [0.00, 0.00].
Holm-adjusted one-sided binomial p for recall ≤ 70%: 1.0000.

Fix discrimination by repository:

| Repository | Fix discrimination |
|---|---|
| `https://github.com/PrefectHQ/fastmcp` | 0/1 = 0.00 |
| `https://github.com/jlowin/fastmcp` | 0/1 = 0.00 |
| `https://github.com/modelcontextprotocol/python-sdk` | 0/5 = 0.00 |

Recall by CWE:

| CWE | Pre-patch recall |
|---|---|
| unknown | 1/7 = 0.14 |

Empty control fix discrimination: not measured.
Shuffled-oracle fix discrimination: not measured.

### slither on Solidity

H2 withheld: trivial control missing
Recall bar: point does not meet bar.
Silence bar: point meets bar, interval does not.
Fix-discrimination point against 70%: point does not meet bar.
Analyzability: 16/16 = 1.00. Unresolved oracle pairs excluded: 0. clone_error sides: 0.
Repos with `foundry.toml` are compiled by Slither through forge. A `compile_error` means that build wrote no JSON.
Worst/best recall if non-ok pairs count against/for the tool: 0/8 = 0.00 / 0/8 = 0.00.
Worst/best silence: 8/8 = 1.00 / 8/8 = 1.00.
Repo-cluster bootstrap 95% for fix discrimination: [0.00, 0.00].
Holm-adjusted one-sided binomial p for recall ≤ 70%: 1.0000.

Fix discrimination by repository:

| Repository | Fix discrimination |
|---|---|
| `https://github.com/OpenZeppelin/openzeppelin-contracts` | 0/7 = 0.00 |
| `https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable` | 0/1 = 0.00 |

Recall by CWE:

| CWE | Pre-patch recall |
|---|---|
| unknown | 0/8 = 0.00 |

Empty control fix discrimination: not measured.
Shuffled-oracle fix discrimination: not measured.


## In Progress / Compiler Roadmap

CodeQL export is not implemented. The Slither row is Slither's built-in `reentrancy-eth` and `reentrancy-no-eth` detectors, not a Veraptos-compiled rule. There is no `--export-slither`.

## H3

Not scored on the corpus in this release. The mutator self-check covers the four mutants. H3 is inconclusive unless an unmutated rule has at least 10 pre-patch detections.

## H4 — syntax, pack, and repair

pass@1 is the first sample. pass@3 allows two repairs that see the validator error. API errors are separate from syntax failures. A missing qlpack is recorded even when compile uses the supplied scaffold.

| Model | Semgrep pass@1 | Semgrep pass@3 | CodeQL pass@1 | CodeQL pass@3 | API errors | Missing qlpack | Hallucinated imports | semgrep --test |
|---|---|---|---|---|---|---|---|---|
| `anthropic/claude-3-5-haiku-20241022` | 0/10 | 0/10 | 0/10 | 0/10 | 10 | 0 | 0 | 0/0 |
| `anthropic/claude-sonnet-5.5` | 9/10 | 10/10 | 9/10 | 10/10 | 0 | 10 | 0 | 10/10 |
| `openai/gpt-4o-mini` | 10/10 | 10/10 | 0/10 | 0/10 | 0 | 10 | 0 | 10/10 |

Returned model ids: `anthropic/claude-sonnet-5.5` returned `anthropic/claude-sonnet-5.5`; `openai/gpt-4o-mini` returned `openai/gpt-4o-mini`

## H4 — paired held-out recall

Held-out H4 recall was not scored. McNemar is not measured.

