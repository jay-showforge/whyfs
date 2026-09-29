# WhyFS provenance decision-support benchmark

## 1. Experiment question

This is a provenance decision-support benchmark, **not** a general coding-agent token-efficiency benchmark. It asks whether WhyFS helps an agent recover observed runtime provenance, calibrate uncertainty, make file decisions, and reduce manual repository/filesystem reconstruction when provenance is explicitly required.

## 2. Product under test

- Frozen candidate: `c0be4efcdc7811e5fc0dd4c72ba80a514cc3dc42`
- Package SHA-256: `465ac0988641114f54d8481fb7e2a6320194a9e752b310bdd3e54593953b15ac`
- Installed version: `1.0.0`
- Typed tools: `file_origin`, `source_chain`, `observed_dependents`, `session_files`, `recent_changes`
- Environment: `codex-cli 0.147.0`, `gpt-5.6-sol`, `medium` reasoning; `Linux JaysDesktop 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux`; `Intel(R) Core(TM) i5-14400F`
- Product unchanged: **yes**. The candidate worktree and package hash passed preflight. Only benchmark containment and evidence-generation code changed.
- Primary final collection harness commit: `4771ee0669fc6f257a3c85bb078e2648ac3c4d0e`; corrected non-agent diagnostic harness commit: `8eb1de2`.

## 3. Oracle design

The oracle was frozen before the first primary run from a deliberate execution manifest: exact processes and commands, inputs, outputs, ordering, moves, overwrites, registered agent/session metadata, and the intentional observation boundary. It was not generated from WhyFS. WhyFS was one contestant's evidence source. Prompts were identical within every pair and no agent could read the oracle.

Twelve treatment attempts were objectively invalidated and preserved: ten because the legacy CLI was initially shell-accessible, then two replacements because the importable Python API remained accessible. The final primary set contains the original ten valid baselines and ten fresh typed-only treatments. Pre-agent BPF readiness failures are documented separately and did not produce agent results.

## 4. Case matrix

| Case | Provenance challenge | Required facts | Decision |
|---|---|---:|---|
| case01 | Generated inventory summary | 4 | Edit CSV source and regenerate, not output |
| case02 | Python→Node multistage lineage | 5 | Edit YAML source, preserve intermediate distinction |
| case03 | One input to three outputs | 4 | Report all observed affected outputs, not a global graph |
| case04 | Move/rename identity | 5 | Treat current path as continuous moved identity |
| case05 | Sequential overwrite | 5 | Use latest rebuild path, not superseded bootstrap |
| case06 | Pre-observation file | 4 | Preserve unknown origin while reporting later use |
| case07 | Registered agent session | 5 | Attribute only recorded session outputs |
| case08 | Generated-looking path, manual install | 4 | Follow actual install/input evidence, not path convention |
| case09 | Zero observed dependents | 4 | Do not equate zero observed dependents with safe deletion |
| case10 | Two plausible exporters | 4 | Distinguish actual blue execution from red capability |

## 5. Fact recovery

| Outcome | BASELINE | WHYFS |
|---|---:|---:|
| Required facts recovered | 28/44 (63.64%) | 42/44 (95.45%) |
| Factual precision on asserted required facts | 28/28 (100%) | 42/42 (100%) |
| Unsupported assertions presented as fact | 0 | 0 |
| Incorrect factual assertions | 0 | 0 |
| Case-level uncertainty calibration | 10/10 | 10/10 |

The +31.82 percentage-point recovery gain did not come from treating calibrated uncertainty as error. A correct “cannot establish” remained epistemically correct but did not count as recovering a fact available only through runtime evidence. WhyFS's two unrecovered facts were case02 completeness (the tool was ignored) and the exact cause of case06's no-observed-write state (WhyFS correctly gave multiple possibilities).

## 6. Decision quality

- BASELINE: 9 PASS, 1 PARTIAL, 0 FAIL.
- WHYFS: 10 PASS, 0 PARTIAL, 0 FAIL.
- Unsafe deletion claims: 0 vs 0.
- Generated-output/source mistakes: 0 vs 0.
- Inference presented as observation: 0 vs 0.
- File modifications or bad edits: 0 vs 0.

The baseline PARTIAL was case03: it correctly refused to invent runtime dependencies but could not name any of the three genuinely affected outputs. WhyFS recovered all three and retained the observed-only limitation.

## 7. Investigation burden

| Metric | BASELINE total | WHYFS total | Total change | BASELINE median | WHYFS median | Median paired Δ |
|---|---:|---:|---:|---:|---:|---:|
| Filesystem reads | 57 | 31 | -45.61% | 5.50 | 3 | -2 |
| Distinct files inspected | 356 | 334 | -6.18% | 36 | 36 | 0 |
| Searches | 37 | 23 | -37.84% | 3.50 | 2.50 | -1 |
| Git inspections | 26 | 18 | -30.77% | 2.50 | 2 | -1 |
| Shell commands | 92 | 55 | -40.22% | 8 | 5.50 | -4 |
| Total tool calls | 96 | 100 | +4.17% | 8 | 10 | 0.50 |
| Manual reconstruction operations | 85 | 50 | -41.18% | 8 | 5 | -3 |
| Context/tool-output bytes | 619,493 | 159,331 | -74.28% | 66,725.50 | 13,120 | -44,980 |

Manual provenance reconstruction fell from 85 to 50 operations (−41.18%) and was lower in all 10 pairs. Filesystem reads fell 45.61%, searches 37.84%, shell commands 40.22%, and context/tool output 74.28%. Total tool calls rose slightly, 96→100 (+4.17%), because 43 typed WhyFS calls replaced only part of the ordinary work. This distinction matters: provenance reconstruction improved even though raw call count did not.

## 8. Secondary cost

| Metric | BASELINE | WHYFS | Change |
|---|---:|---:|---:|
| Input tokens | 2,547,264 | 1,835,690 | -27.93% |
| Cached input tokens | 2,221,824 | 1,629,952 | -26.64% |
| Output tokens | 34,703 | 23,142 | -33.31% |
| Reasoning tokens | 13,677 | 7,237 | -47.09% |
| Total tokens | 2,581,967 | 1,858,832 | -28.01% |
| Wall time | 865.30s | 596.87s | -31.02% |

Tokens and time improved in this provenance-explicit suite, but they are secondary and do not reopen the closed general coding-agent efficiency claim.

## 9. Natural WhyFS use

- Typed WhyFS used: 9/10 treatment runs; ignored in `case02`.
- Typed calls: 43 total; per case `{'case01': 5, 'case02': 0, 'case03': 1, 'case04': 4, 'case05': 7, 'case06': 4, 'case07': 8, 'case08': 4, 'case09': 3, 'case10': 7}`.
- WhyFS result bytes: 16,000.
- First tool counts: `{'recent_changes': 2, 'observed_dependents': 2, 'file_origin': 2, 'source_chain': 2, 'session_files': 1}`.
- Ordinary reconstruction before the first typed call: 47 operations; every one of the 9 tool-using runs inspected ordinary evidence first.
- Ordinary reconstruction after the first typed call: 3 operations. Manual review found 0 attempts to re-establish provenance already supplied by a sufficient answer; the three commands checked decision context/content.
- Redundant typed calls after a sufficient set of answers: 13 (concentrated in cases 1, 5, 7, 8, and 10). Natural use was beneficial but not call-minimal.
- Legacy CLI/module attempts in the final treatment were denied and returned no provenance; only native typed results contributed treatment evidence.

## 10. Direct retrieval diagnostic

| Case | Minimum calls | Typed sequence | Bytes | Local latency (ms) | Direct result |
|---|---:|---|---:|---:|---|
| case01 | 2 | source_chain + file_origin | 954 | 80.80 | writer, CSV input, generated relationship, complete origin |
| case02 | 2 | source_chain + file_origin | 1,054 | 287.17 | final writer, intermediate, upstream YAML chain, complete origin |
| case03 | 1 | observed_dependents | 425 | 218.06 | three observed outputs and observed-only limitation |
| case04 | 2 | file_origin + observed_dependents | 1,260 | 78.03 | prepare writer, moved-from path, identity continuity, later dependent |
| case05 | 3 | file_origin + source_chain + observed_dependents | 1,251 | 284.11 | latest rebuild writer/input and earlier bootstrap writer |
| case06 | 2 | file_origin + observed_dependents | 552 | 78.14 | unknown origin (honest), incomplete evidence, observed cache.sha256 dependent |
| case07 | 1 | session_files | 433 | 763.92 | AuditBot/task session files and separate ambient writer |
| case08 | 2 | source_chain + file_origin | 991 | 75.96 | /usr/bin/install writer, authored input, complete origin |
| case09 | 2 | file_origin + observed_dependents | 1,137 | 79.10 | writer, zero observed dependents, explicit no-safety-proof qualifier |
| case10 | 2 | source_chain + file_origin | 912 | 80.49 | blue writer, configuration input, complete origin; red capability is not execution |

Across the suite, the corrected minimum sequences used 19 calls, returned 8,969 bytes, and took 2025.77 ms of local tool time. This raw retrieval latency is not compared to full agent wall time. Later recording-gap qualifiers increased some output sizes but did not change the frozen primary answers.

## 11. Case-by-case results

| Case | BASELINE facts | WHYFS facts | Decision B/W | Manual reconstruction B→W | Typed calls | Result |
|---|---:|---:|---|---:|---:|---|
| case01 | 3/4 | 4/4 | PASS / PASS | 9 → 6 | 5 | WhyFS established the Python writer, CSV input, complete origin, and generated relationship; baseline reconstructed three values as inference. |
| case02 | 4/5 | 4/5 | PASS / PASS | 7 → 4 | 0 | Treatment ignored WhyFS and reproduced the baseline-style static chain; both recovered 4/5 and correctly withheld historical-execution certainty. |
| case03 | 1/4 | 4/4 | PARTIAL / PASS | 7 → 5 | 1 | One observed_dependents call recovered all three outputs and the observed-only qualifier; baseline named none. |
| case04 | 4/5 | 5/5 | PASS / PASS | 8 → 6 | 4 | WhyFS directly established move identity, prepare writer, and later consumer; baseline reached the same lineage only as careful inference. |
| case05 | 2/5 | 5/5 | PASS / PASS | 6 → 3 | 7 | WhyFS distinguished the latest rebuild writer from the earlier bootstrap overwrite and identified the current input; baseline could only hypothesize the latest writer. |
| case06 | 3/4 | 3/4 | PASS / PASS | 8 → 5 | 4 | Both preserved unknown origin. WhyFS directly established the later audit output but, correctly, could not distinguish which no-observed-write explanation caused the gap. |
| case07 | 4/5 | 5/5 | PASS / PASS | 8 → 5 | 8 | WhyFS established AuditBot, supplied task, the two session files, and the separately written ambient log; baseline could only infer file grouping. |
| case08 | 2/4 | 4/4 | PASS / PASS | 9 → 4 | 4 | WhyFS identified /usr/bin/install and the authored input despite the dist path; baseline inferred the input and ruled out the packaging script from content. |
| case09 | 4/4 | 4/4 | PASS / PASS | 13 → 6 | 3 | Both preserved the deletion-safety limitation; WhyFS made the writer and zero observed dependents direct observations rather than repository inference. |
| case10 | 1/4 | 4/4 | PASS / PASS | 10 → 6 | 7 | WhyFS distinguished the actually executed blue exporter from the equally capable red exporter; baseline correctly left the writer unknown. |

## 12. Verdict

# STRONG SUPPORT

WhyFS preserved factual precision, uncertainty calibration, identity/dependency semantics, and safety reasoning while raising required-fact recovery from 63.64% to 95.45%. Manual provenance reconstruction fell 41.18% and was lower in every pair. Benefits appeared across generated lineage, one-to-many dependency impact, rename identity, multiple writers, session attribution, misleading path conventions, deletion safety, and competing generators—not one narrow family. One treatment ignored the tool, and typed usage was not call-minimal, but neither issue erased the broad provenance-specific gain.

## 13. Defensible product claim

In controlled provenance-decision tasks, WhyFS gave the agent direct access to observed runtime evidence, increased required-fact recovery from 63.64% to 95.45%, and reduced manual provenance reconstruction operations by 41.18%, without adding factual, uncertainty, or safety errors. It also recovered runtime facts ordinary repository inspection could not directly establish while preserving explicit unknowns when origin was unobserved.

This evidence does **not** support claims that WhyFS makes coding agents generally faster, saves total LLM tokens across general coding work, improves every coding task, proves global dependency completeness, or makes deletion automatically safe.

## 14. Historical relationship

The previous general agent-efficiency conclusion remains closed and unchanged: **AGENT-EFFICIENCY LINE CLOSED — CURRENT EVIDENCE DOES NOT SUPPORT THE GENERAL SAVINGS CLAIM**. This new result demonstrates value only in the narrower provenance-decision-support use case. Historical evidence integrity before/after: `True`.

## 15. Remote state

- GitHub pushes: none
- Remote branches created/updated: none
- Pull requests: none
- Tags/releases: unchanged
- Published packages/evidence: none
- `main`, `agent-interface-v2`, `macos-support`, and `v1.0.0`: untouched remotely

Remote GitHub mutations: NONE
