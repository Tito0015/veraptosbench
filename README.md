# VeraptosBench-mini results

## Status (read first)

Pilot held-out: **n=7** Python (`web2_mcp`), **n=8** Solidity (`web3_toctou_cei`).
Pre-registered H2 bars **were not met**; **no general performance claims** in this release.
This release ships the harness, labeled primary arms, cheap controls, and frozen artifacts.
**Pending:** fair baselines (see PREREG); v2 held-out (**GATE_FAIL**: 0 of 20 Web3 candidates in public `gate.json`).
Per-repository recall/silence scores measure **rule–oracle agreement on that advisory**, not the security posture of the upstream project.

**Attribution:** advisory metadata from the [GitHub Advisory Database](https://github.com/advisories) (CC-BY 4.0).

**Third-party rerun:** you may re-score committed YAML, stock Slither detectors, and the pinned threat-library SHA on the same clone pins.
You **cannot** regenerate `web2_invariant.yml` from this repo alone (requires closed `veraptos_static_cli`).
`PROVENANCE.json` frozen H1 hashes are integrity checks, not a public compiler replay recipe.

**Related repos:** [Veraptos Threat Library](https://github.com/Tito0015/veraptos-threat-library) · public package [`veraptosbench-mini`](https://github.com/Tito0015/veraptosbench-mini).

## Scored arms (what each row measures)

| Arm | Status | Rule source | Scoring engine |
|---|---|---|---|
| **Treatment (compiler sink-map)** | Scored | Veraptos static CLI Python YAML export → `benchmarks/veraptos_rules/web2_invariant.yml` | Opengrep on Python pairs (N=7) |
| **Baseline (stock Slither)** | Scored | Slither `reentrancy-eth`, `reentrancy-no-eth` — not Veraptos-compiled; no `--export-slither` | Slither on Solidity pairs (N=8) |
| **Control (out-of-class library rules)** | Scored (descriptive) | Pinned threat-library paths/detectors (see table below) | Opengrep + library Slither |

The Opengrep H2 row is the compiler Python sink-map only, not a threat-library YAML.

## Results changelog

| Release | Note |
|---|---|
| **v0.1.1** | Threat-library arm added **after** v1 primary H2 scores were known (PREREG post-hoc addendum; control arm). |
| **v0.1.2** | Method-first README: status block, H2 negative controls, CWE sidecar, finding totals, fixture harness check. |
| **v0.1.2+** | Public README scoped to **Opengrep + stock Slither** H2 only; legacy LLM syntax rows removed from this page. |

## Harness checks (not held-out evidence)

`scripts/fixture_check.py` runs in `reproduce.sh`:

- Opengrep: `benchmarks/veraptos_rules/web2_invariant.yml` on `benchmarks/dev_fixtures/untrusted_external.py`.
- Stock Slither: `reentrancy-eth,reentrancy-no-eth` on `benchmarks/dev_fixtures/reentrancy_harness.sol`.

## v1 archive

v1 hash `8316802fb09b6a0595d58472ceb810656cf71a8549b495d5641c98dcc478222d`.
An archived wrong-engine row once ran a Python rule engine on Solidity pairs; it is not part of this release. **Web2 H2 = Opengrep only. Web3 H2 = stock Slither only.**

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
| CWE-200 | 1/1 = 1.00 |
| CWE-346;CWE-1385 | 0/1 = 0.00 |
| CWE-400;CWE-770;CWE-772 | 0/1 = 0.00 |
| CWE-639 | 0/1 = 0.00 |
| CWE-79 | 0/1 = 0.00 |
| CWE-862 | 0/1 = 0.00 |
| CWE-918 | 0/1 = 0.00 |
In-scope subset (sinkmap, sidecar metadata): 1/6 = 0.17.

### Total findings (primary arm, opengrep)

Oracle true positives are a subset of scanner findings. Post-patch **zero TP** can still mean noisy non-oracle alarms.

| Pair | pre `finding_count` | post `finding_count` |
|---|---|---|
| `GHSA-5h93-6whr-6q8j` | 267 | 319 |
| `GHSA-84m7-p3x7-pcfv` | 184 | 184 |
| `GHSA-hvrp-rf83-w775` | 182 | 182 |
| `GHSA-jpw9-pfvf-9f58` | 182 | 182 |
| `GHSA-mxxr-jv3v-6pgc` | 184 | 184 |
| `GHSA-vj7q-gjh5-988w` | 182 | 182 |
| `GHSA-vv7q-7jx5-f767` | 237 | 237 |


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
| CWE-116 | 0/1 = 0.00 |
| CWE-125 | 0/1 = 0.00 |
| CWE-20 | 0/1 = 0.00 |
| CWE-354 | 0/2 = 0.00 |
| CWE-400;CWE-770 | 0/1 = 0.00 |
| CWE-665 | 0/1 = 0.00 |
| CWE-669 | 0/1 = 0.00 |
In-scope subset (sidecar): not measured.

### Total findings (primary arm, slither)

Oracle true positives are a subset of scanner findings. Post-patch **zero TP** can still mean noisy non-oracle alarms.

| Pair | pre `finding_count` | post `finding_count` |
|---|---|---|
| `GHSA-4h98-2769-gh6h` | 0 | 0 |
| `GHSA-5vp3-v4hc-gx76` | 0 | 0 |
| `GHSA-7grf-83vw-6f5x` | 0 | 0 |
| `GHSA-93hq-5wgc-jc82` | 34 | 34 |
| `GHSA-9j3m-g383-29qr` | 0 | 0 |
| `GHSA-9vx6-7xxf-x967` | 34 | 34 |
| `GHSA-g4vp-m682-qqmp` | 41 | 41 |
| `GHSA-wprv-93r4-jj2p` | 34 | 34 |


Empty control fix discrimination: not measured.
Shuffled-oracle fix discrimination: not measured.

## H2 — control: threat library on v1 (out-of-class)

Zeros are the expected outcome: DVD / TS / Go showcase rules vs MCP Python and OpenZeppelin patch-class advisories.

Rules from [veraptos-threat-library](https://github.com/Tito0015/veraptos-threat-library) at SHA `78b718d72bce1521593774c59b03c0e4edd7088e`. Estimand: same matcher as H2; pairs are **not** the fixture classes these rules target.

| Rule | Engine | Domain | N | Fix discrimination | Pre-patch recall | Post-patch silence | compile_error sides |
|---|---|---|---|---|---|---|---|
| `dom-xss-postmessage` | opengrep | Python | 7 | 0/7 = 0.00 | 0/7 = 0.00 | 7/7 = 1.00 | 0 |
| `express-auth-bypass` | opengrep | Python | 7 | 0/7 = 0.00 | 0/7 = 0.00 | 7/7 = 1.00 | 0 |
| `graphql-ssrf` | opengrep | Python | 7 | 0/7 = 0.00 | 0/7 = 0.00 | 7/7 = 1.00 | 0 |
| `jwt-none-alg-go` | opengrep | Python | 7 | 0/7 = 0.00 | 0/7 = 0.00 | 7/7 = 1.00 | 0 |
| `mass-assignment-fastapi` | opengrep | Python | 7 | 0/7 = 0.00 | 0/7 = 0.00 | 7/7 = 1.00 | 0 |
| `veraptos-puppet-spot-oracle` | slither | Solidity | 4 | 0/4 = 0.00 | 0/4 = 0.00 | 4/4 = 1.00 | 8 |
| `veraptos-rewarder-snapshot-manipulation` | slither | Solidity | 4 | 0/4 = 0.00 | 0/4 = 0.00 | 4/4 = 1.00 | 8 |
| `veraptos-selfie-governance-snapshot` | slither | Solidity | 4 | 0/4 = 0.00 | 0/4 = 0.00 | 4/4 = 1.00 | 8 |
| `veraptos-side-entrance-state-hijack` | slither | Solidity | 4 | 0/4 = 0.00 | 0/4 = 0.00 | 4/4 = 1.00 | 8 |
| `veraptos-truster-arbitrary-call` | slither | Solidity | 4 | 0/4 = 0.00 | 0/4 = 0.00 | 4/4 = 1.00 | 8 |

Library Slither `compile_error` stderr tails:

- `GHSA-93hq-5wgc-jc82`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-93hq-5wgc-jc82`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-9vx6-7xxf-x967`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-9vx6-7xxf-x967`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-g4vp-m682-qqmp`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-g4vp-m682-qqmp`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-wprv-93r4-jj2p`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-wprv-93r4-jj2p`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-93hq-5wgc-jc82`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-93hq-5wgc-jc82`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-9vx6-7xxf-x967`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-9vx6-7xxf-x967`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-g4vp-m682-qqmp`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-g4vp-m682-qqmp`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-wprv-93r4-jj2p`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-wprv-93r4-jj2p`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-93hq-5wgc-jc82`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-93hq-5wgc-jc82`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-9vx6-7xxf-x967`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-9vx6-7xxf-x967`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-g4vp-m682-qqmp`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-g4vp-m682-qqmp`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-wprv-93r4-jj2p`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-wprv-93r4-jj2p`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-93hq-5wgc-jc82`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-93hq-5wgc-jc82`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-9vx6-7xxf-x967`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-9vx6-7xxf-x967`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-g4vp-m682-qqmp`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-g4vp-m682-qqmp`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-wprv-93r4-jj2p`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-wprv-93r4-jj2p`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-93hq-5wgc-jc82`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-93hq-5wgc-jc82`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-9vx6-7xxf-x967`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-9vx6-7xxf-x967`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-g4vp-m682-qqmp`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-g4vp-m682-qqmp`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-wprv-93r4-jj2p`: slither exited without JSON (~1.4s on veraptos-* detect)
- `GHSA-wprv-93r4-jj2p`: slither exited without JSON (~1.4s on veraptos-* detect)

Library Slither `compile_error` sides (four GHSA pairs: `93hq`, `9vx6`, `g4vp`, `wprv`): `--detect veraptos-*` often writes no JSON while **stock** `reentrancy-eth` compiles on the same clone. Do not treat as post-patch silence.



## Scope of this release

Public scorecard: **Opengrep** (Python sink-map) and **stock Slither** (Solidity reentrancy) on frozen v1 pairs, plus out-of-class library controls. Legacy PREREG arms outside those two engines are not on this page.

## H3 — metamorphic mutators

**Not scored on v1 held-out.** PREREG requires at least **10 pre-patch detections** on the unmutated rule before mutant preserving/altering rates are reported. Primary Opengrep recall on v1 is **1/7**, so the held-out corpus does not meet the H3 gate.

**What did run:** `python scripts/mutator.py --self-check` on the four Web2 dev mutants (altering + preserving). That checks the mutator machinery only — not advisory recall.

Slither mutants are out of scope for this pilot (H3 is Web2 Python fixtures in PREREG).

## Pending fair baselines (pre-registered, not scored in this release)

- Community Opengrep registry rules by upstream rule id + commit only (no vendored rule text).
- Time-boxed hand-written expert rule per domain.

See [`PREREG.md`](PREREG.md) addenda *Library-on-v1* and *Fair baselines pending*.

