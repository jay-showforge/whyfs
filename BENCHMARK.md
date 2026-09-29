# Benchmarks

This file has three parts:
- **the provenance decision-support benchmark**, including its claim boundary and public evidence;
- **the WhyFS 1.0 performance contract**, and the evidence behind it;
- **the historical v0.1 / v0.2 benchmarks**, kept as they were written (below).

Per-platform results are in [docs/PLATFORM_VALIDATION.md](docs/PLATFORM_VALIDATION.md).

## Provenance decision-support benchmark

**Verdict: STRONG SUPPORT**

This benchmark asks a provenance-specific question: when an agent actually needs provenance to
make a file decision, does access to WhyFS help it establish the correct observed facts more
completely and with less manual reconstruction than ordinary repository and filesystem
investigation?

In controlled provenance-decision tasks, WhyFS increased required-fact recovery from **63.64% to
95.45%** and reduced manual provenance reconstruction by **41.18%**, without adding factual,
uncertainty, or safety errors.

### What was tested

Ten fresh provenance-decision cases covered generated outputs, multi-stage lineage, one-to-many
dependents, rename identity, multiple writers, an observation gap, agent/session attribution, a
generated-looking but manually installed file, downstream safety, and competing plausible
generators.  Each case had a BASELINE run using ordinary coding tools and a WHYFS run with the
same prompt plus read-only typed provenance tools.

The hidden oracle was constructed before collection from the deliberately executed processes,
commands, inputs, outputs, moves, overwrites, session metadata, and observation boundary.  It was
independent of WhyFS; WhyFS was one contestant's evidence source, not the source of truth used for
scoring.  Correctly refusing to invent an unknowable fact was treated as calibrated uncertainty,
not as a factual error.

The treatment used frozen experimental candidate
`c0be4efcdc7811e5fc0dd4c72ba80a514cc3dc42`, package SHA-256
`465ac0988641114f54d8481fb7e2a6320194a9e752b310bdd3e54593953b15ac`, with the read-only tools
`file_origin`, `source_chain`, `observed_dependents`, `session_files`, and `recent_changes`.
Those native typed tools are **not** part of the released WhyFS 1.0.0 product, and publishing this
evidence does not make the experimental implementation a supported feature.

### Primary results

| Metric | BASELINE | WHYFS | Change |
|---|---:|---:|---:|
| Required-fact recovery | 28/44 (63.64%) | 42/44 (95.45%) | +31.82 percentage points |
| Factual precision | 28/28 (100%) | 42/42 (100%) | unchanged |
| Correct uncertainty calibration | 10/10 | 10/10 | unchanged |
| Decision quality | 9 PASS / 1 PARTIAL | 10 PASS | improved |
| Manual provenance reconstruction | 85 | 50 | -41.18% |
| Filesystem reads | 57 | 31 | -45.61% |
| Searches | 37 | 23 | -37.84% |
| Context/tool-output bytes | 619,493 | 159,331 | -74.28% |
| Unsafe or unsupported claims | 0 | 0 | unchanged |
| File modifications | 0 | 0 | unchanged |

Manual reconstruction was lower in all ten pairs.  Raw tool calls did not fall: they rose from 96
to 100 because 43 typed WhyFS calls replaced only part of the ordinary work.  The result is about
fact recovery, calibrated uncertainty, decision quality, and provenance reconstruction burden—not
a synthetic efficiency score.

### Secondary measurements

For these provenance-explicit tasks, total model tokens fell **28.01%** (2,581,967 to 1,858,832)
and wall time fell **31.02%** (865.30s to 596.87s).

These token and time results apply only to the provenance-explicit benchmark and must not be
interpreted as evidence that WhyFS generally reduces coding-agent cost or latency.

### Natural tool selection

Codex naturally selected the typed WhyFS provenance tools in 9 of 10 treatment runs.  It made 43
typed calls; one treatment run ignored WhyFS, and 13 calls were classified as redundant.  Every
tool-using run performed some ordinary reconstruction before its first WhyFS call.  After an agent
received sufficient typed provenance, however, none continued manually reconstructing that same
provenance.

### Claim boundary

The earlier general coding-agent investigation asked whether simply giving a coding agent WhyFS
makes arbitrary coding work generally cheaper or faster.  Its conclusion remains visible and
unchanged:

**AGENT-EFFICIENCY LINE CLOSED — CURRENT EVIDENCE DOES NOT SUPPORT THE GENERAL SAVINGS CLAIM**

The new result asks a narrower question and does not reopen that line.  It supports WhyFS as
decision support when provenance is explicitly required; it does not show that WhyFS improves
every coding task, generally saves tokens or time, proves a complete dependency graph, or makes a
file safe to delete.

- [Full benchmark report](results/provenance-decision-support/FINAL_REPORT.md)
- [Evidence guide and complete public bundle](results/provenance-decision-support/README.md)
- [Methodology](results/provenance-decision-support/METHODOLOGY.md)
- [Independent oracle](results/provenance-decision-support/ORACLE.json)
- [Paired summary](results/provenance-decision-support/PAIRED_SUMMARY.json)
- [Results CSV](results/provenance-decision-support/RESULTS.csv)
- [Evidence hashes](results/provenance-decision-support/EVIDENCE_MANIFEST.sha256)

## WhyFS 1.0 performance contract

### 1. The original criterion (the historical pre-1.0 gate)

`scripts/machine_perf.py` runs every workload through the installed service:
- 20 counterbalanced off/on pairs after 2 warm-up pairs;
- the reported number is the median of the per-pair overheads, with a bootstrap CI90.

Its rule for **every** workload is **total overhead < 5 %**, and that includes the process-spawn
stress workload:
- **Windows `native_exe_x300`:** a small program started 300 times in a `cmd` loop;
- **Linux `static_binary_x300`:** the same with a static binary.

This rule, and machine_perf itself, are unchanged.  It still runs in every validation, and
its result is always reported as **the historical pre-1.0 gate**.

### 2. The runs that failed it (nothing removed; every result)

Spawn ×300, median total overhead from machine_perf on the hosted native runners (20 pairs each):

| Run (commit) | Windows x64 | Windows ARM64 | Linux x86-64 | Linux ARM64 |
|---|---|---|---|---|
| 1, 36358319118 | +4.84 % | — | — | — |
| 2 | +5.22 % **fail** | — | — | — |
| 4 | +6.52 % **fail** | — | — | — |
| 5, 36370736605 (6321b45) | +6.57 % **fail** | +7.41 % **fail** | +3.81 % | +3.49 % |
| 6, 36374200705 (f2b9ca6) | +4.54 % (CI90 up to 5.91) | −0.76 % | +3.68 % | +4.24 % |
| release 36377152638 (b5562df) | **+5.16 % fail** | −0.25 % | +3.19 % | +3.63 % |
| 7, 36391350371 (ec52053, after the optimization) | +4.17 % (3.83..4.53) | −10.66 % | +4.00 % | +3.91 % |
| release candidate 36395424116 (37f7e7a = ec52053 product code) | **+6.48 % fail** (4.97..7.48) | −0.02 % | **+5.50 % fail** (3.58..6.74) | +3.35 % |

- **Identical code.**  The same product code measured +4.17 % and +6.48 % on Windows x64.
  Linux x86-64's collector code has not changed since graduation, and measured anywhere from
  +3.19 % to +5.50 %.
- **Earlier history.**  The v0.2 Linux graduation history below shows the same workload failing
  on WSL2 (+7.60 %, +7.92 %, +5.56 %) before its collector was rebuilt.
- **The dedicated desktop passes it.**  On the development desktop (i5-14400F, 10 cores / 16
  threads, Windows 11, Defender on, the exact release-candidate MSI), the original unchanged
  campaign passes every check: spawn ×300 −0.70 % (CI90 −1.67..+0.27), MSVC −0.35 %,
  Vite −0.54 % (`results/desktop-1.0.0/machine-perf/`).

### 3. The required kernel/provider cost alone measured above 5 %

`scripts/diag_service_cost.py` (Windows) and `scripts/diag_service_cost_linux.py` (Linux) run
machine_perf's unchanged spawn workload, pairing and timing against the installed service in
three configurations:
- **normal:** the product.
- **discard:** every event source enabled, records counted and dropped.  This is the observation
  (kernel/provider) floor.
- **no_write / no_store:** everything except persistence.

| Environment (runs) | Kernel floor (discard) | Total (normal) | WhyFS-controlled = normal − discard |
|---|---|---|---|
| Hosted Windows x64, 1 core / 2 threads (four sessions) | **+3.25, +3.75, +4.30, +5.90 %** | +3.52 to +4.60 % | before the optimization +1.35 pp; after +0.71, +0.79 pp (CI90 −1.49..+2.86) |
| Hosted Windows ARM64 | +1.21 % | +4.75 % | not measurable (CI90 −10.6..+18.2) |
| Hosted Linux x86-64 | +2.34 % (1.98..3.50) | +4.02 % | **+1.68 pp** (+0.52..+2.64) |
| Hosted Linux ARM64 | +2.46 % (1.35..3.04) | +5.13 % | **+2.67 pp** (+0.63..+4.10) |
| Dedicated desktop, Windows x64 (two sessions, opposite order) | +1.23, +1.25 % | +0.59, +1.48 % | −0.64 pp (−2.28..+1.07), +0.23 pp (−2.03..+2.48) |

The WhyFS-controlled share is the difference between two independent sets of 20 pairs.  Its
CI90 resamples both sets, so a single session resolves it only to about ±1–2 pp (±14 pp on the
Windows ARM64 runner).

On the hosted Windows x64 runner, the discard floor alone (+5.90 %) exceeded the whole budget.
The historical rule could not be met there reliably by any implementation that keeps these
events.

### 4. What reduced WhyFS's own share (commit ec52053)

Measured before changing anything (`docs/PLATFORM_VALIDATION.md` has the details):
- **Store writer.**  A 16 MB page cache and a 4,000-page checkpoint interval.  The writer's I/O
  operations fell by about a third, and each of those I/Os was also a kernel file event.
- **File identity.**  The ID captured at a file's first write is read without opening the file
  (`NtQueryInformationByName` on NTFS).  The identity is identical, including for symlinks.
- **Kernel-File consumer.**  A memo of raw paths already classified out of scope.

The Windows x64 WhyFS-controlled share went from about 1.35 pp to about 0.7 pp, and user-space
CPU during a measured run from 20 ms to 14 ms.  Process-record deferral was examined and
rejected by measurement: in this workload every process writes a labelled file, so every
process record is required provenance.

### 5. Why the floor is not lowered further

Per `copy.exe`, Windows generates about:
- 13 Create, 15 QueryInformation, 13 Cleanup and 14 Close Kernel-File events;
- 22 mapped-view and 22 unmap events.

Every one is used:
- **Create and Close:** the file-object table.
- **Cleanup:** delete-on-close.
- **QueryInformation:** learns a file's key before its first mapped view.
- **Read and Write:** the I/O evidence.
- **Mapped views:** the MSVC linker's reads and writes.

The provider manifest ties Cleanup, Close and QueryInformation to the broad FILEIO keyword, so
they cannot be enabled more narrowly.  The system logger cannot separate unmap from map.  Fewer
events would mean lost identity, lost I/O attribution or lost mapped-file evidence, and WhyFS
does not trade provenance for a benchmark.

### 6. The 1.0 contract

The contract was frozen **before** the authoritative release-candidate run.  The thresholds come
only from the calibration runs above.  The machine-readable part is
`scripts/spawn_stress_contract.json`.

**A. Real development workloads: release criterion, unchanged budget.**
Median total overhead **< 5 %** on:
- MSVC /MP8 (240 units) and Vite on Windows;
- `make -j8` and Vite on Linux.

Also required: idle collector CPU < 1 % of a core, zero event loss, and `why` / `label` CLI
median < 100 ms.  These come from the unchanged machine_perf campaign (`scripts/perf_contract.py`).

**B. Process-spawn stress ×300: mandatory stress and regression benchmark.**
Every validation reports, per platform:
- the baseline runtime;
- the total overhead: the historical rule, which is never hidden;
- the kernel/provider floor;
- the WhyFS-controlled share;
- all with CI90s and every raw pair;
- WhyFS CPU by process and thread, store I/O and event loss.

It **passes** when all of these hold:
1. zero event loss, in every session;
2. correctness under the stress: all 300 outputs labelled with the program that wrote them,
   observed completely, identity matching;
3. every event source enabled in the product configuration;
4. **WhyFS-controlled share:**
   - It must not be shown to exceed 3.0 percentage points: the lower bound of its CI90 must be
     ≤ 3.0 pp.
   - That is above every frozen-implementation estimate (−0.64 to +2.67 pp).  The test fails
     only on evidence, not on noise.
5. **WhyFS user-space CPU per stress iteration:**
   - It must be ≤ 1.5 × the frozen implementation's calibrated mean on that hosted platform:
     Windows x64 53.5 ms, Windows ARM64 86.2 ms, Linux x86-64 28.1 ms, Linux ARM64 21.9 ms.
   - This is the precise regression detector.
   - One calibration session per platform cannot separate changes below roughly 30–50 % from
     runner-to-runner variation: single iterations vary up to 1.39 × the mean.  Smaller changes
     are reported, not gated.

"Total < 5 %" is not the release criterion for this stress test, because:
- the required observation floor can by itself reach 5 % on constrained hardware;
- the WhyFS-controlled component is small;
- correctness requires those events.

The total is still reported every time, next to the floor.

**Linux spawn stress.**  WhyFS's own share there is measurably larger than on Windows:
+1.7 to +2.7 pp, mostly the store writer.  It is within the contract, but it is the first place
to look for future optimization.

### 7. The authoritative run under the contract: run 36449450012 (commit 80dabe3) -- **FAIL (contract A, Windows ARM64)**

The contract above was committed before this run (80dabe3).  One run, not repeated.
`results/release-1.0.0-final/`.

| Platform | A. real workloads < 5 % | B. spawn stress | Historical spawn rule (total < 5 %) |
|---|---|---|---|
| Windows x64 | **PASS**: MSVC +1.01 % (CI90 0.45..6.71), Vite +1.37 %; idle 0.0 %; CLI 68 / 71 ms; lost 0 | **PASS**: total −6.73 %, floor +2.74 %, WhyFS-controlled −9.46 pp (−21.14..+1.85: a noisy runner); CPU 49.8 ms ≤ 80.2 (merge 16.3, writer 19.3); 300/300; lost 0 | met (−0.07 %) |
| Windows ARM64 | **FAIL: MSVC +5.18 %** (CI90 1.44..12.36); Vite −0.13 %; idle 0.10 %; CLI 83 / 85 ms; lost 0 | **PASS**: total +4.72 %, floor +1.49 %, WhyFS-controlled +3.23 pp (−9.88..+15.36); CPU 84.6 ms ≤ 129.3; 300/300; lost 0 | met (+2.32 %) |
| Linux x86-64 | **PASS**: make -j8 +3.82 %, Vite +0.30 %; idle 0.11 %; CLI 27 / 29 ms; lost 0 | **PASS**: total +4.40 %, floor +2.60 %, WhyFS-controlled +1.81 pp (+0.43..+2.82); CPU 30.9 ms ≤ 42.1; 300/300; lost 0 | met (+4.37 %) |
| Linux ARM64 | **PASS**: make -j8 +2.37 %, Vite −0.06 %; idle 0.11 %; CLI 24 / 25 ms; lost 0 | **PASS**: total +3.62 %, floor +4.44 %, WhyFS-controlled −0.82 pp (−2.99..+0.87); CPU 23.1 ms ≤ 32.9; 300/300; lost 0 | **not met (+5.10 %)** |

Every functional gate passed on all four platforms in the same run:
- tests: Windows 108 + 108, Linux 246 + 246 per platform;
- MSI 32/32 and upgrade 16/16; `.deb` 24/24;
- product 47/47 and 48/48; outage 16/16 and 13/13;
- all corpora 79/79 with lost 0; secret 22/22;
- functional and graduation PASS; process decoding 0 mismatches.

**The failure.**  Windows ARM64 MSVC /MP8 measured **+5.18 %** against the part A criterion of
< 5 %.  Two facts from the raw data (`machine_perf.json`, every pair kept):
- **Identical code, earlier runs.**  The same product code (ec52053) measured +1.01 % and
  +0.72 % in the two previous runs.  Across all six hosted runs the figures were +2.40, +2.55,
  +3.96, +1.01, +0.72 and +5.18 %.
- **The runner itself is unstable.**
  - Its baseline (WhyFS off) moves between levels within a run: about 5.6, 6.5 and 7.3 s.
  - Single pairs therefore range from −14 % to +43 %.
  - The CI90 of the median spans 11 percentage points.
  - WhyFS's CPU during a build was 0.06–0.10 s of a 6–7 s build.

Contract A as frozen has no exception for a workload that cannot be measured precisely on its
runner.  Adding one after seeing this result would be changing the criterion to obtain a pass,
so this run is recorded as a failure.  Resolving it needs a decision:
- measure MSVC on dedicated ARM64 hardware;
- or state, before the next run, a measurability condition for part A (for example a maximum
  CI90 width) and how a workload that fails it is judged.

### 8. Measurability of real-workload results (frozen before the next authoritative run)

Section 7's +5.18 % stays a failure under the contract that was frozen for that run.  This
section adds what that contract lacked: a rule for when a measurement is precise enough to be
judged against the 5 % threshold.  It was derived **only from pre-existing measurements**:
- the 45 historical real-workload results in `results/` (8 hosted native runs × 4 platforms,
  plus the desktop campaigns);
- analysed by `scripts/measurability_calibration.py`, output in
  `results/measurability-calibration.json`.

It applies to every real workload on every platform.  The machine-readable form is
`scripts/real_workload_contract.json`, evaluated by `scripts/perf_contract.py`.

**What the history shows (CI90 width of the median paired overhead, 20 pairs):**

| Hosted workload | Measurements with CI90 width ≤ 5 pp | Widths (pp) | Notes |
|---|---|---|---|
| Windows x64 MSVC | 7/8 | 0.25–2.29; one run 6.26 | baseline CV 0.4–1.2 % |
| Windows x64 Vite | 8/8 | 1.04–2.47 | |
| **Windows ARM64 MSVC** | **0/8** | **7.42–14.0** | baseline CV 5.2–8.8 %; baseline bimodality coefficient > 0.555 in 4 of 8 runs; single pairs −14 % to +43 % |
| Windows ARM64 Vite | 8/8 | 0.66–3.63 | |
| Linux x86-64 make -j8 | 7/8 | 0.79–4.74; one run 21.6 | |
| Linux x86-64 Vite | 8/8 | 0.83–2.45 | |
| Linux ARM64 make -j8 | 8/8 | 0.95–2.78 | |
| Linux ARM64 Vite | 7/8 | 1.17–5.70 | |
| Desktop MSVC (not a gate) | 0/5 | 5.89–11.15 | Defender and a busy desktop |

Windows ARM64 MSVC has never been precise enough on its hosted runner.  That holds for runs
whose medians looked like passes (+0.72, +1.01 %) as much as for the +5.18 % failure.

**The rule.**  With the CI90 of the median paired overhead (machine_perf's bootstrap) and the
5 % threshold:
- **PASS:** the CI90 lies entirely below 5 %; or it contains 5 %, is at most 5 pp wide, and the
  median is below 5 %.
- **FAIL:** the CI90 lies entirely at or above 5 %; or it contains 5 %, is at most 5 pp wide,
  and the median is at or above 5 %.
- **UNMEASURABLE ON THIS RUNNER:** the CI90 contains 5 % and is wider than 5 pp.  The
  measurement cannot resolve the threshold.  **This is never a pass**; it is reported with every
  raw pair.
- **INVALID:** fewer pairs than required.

**Why 5 pp.**  A half-width of at most 2.5 pp, half the budget, bounds the error of reading the
median against the threshold to half the budget.  Well-behaved hosted runners give 0.25–2.5 pp
at 20 pairs.  Only the noisy exceptions exceed 5 pp.

**Sample count: 150 pairs**, for every workload on every platform, fixed before the run and
never adapted to the data.  The calibration resamples each historical measurement's own pairs:

| P(CI90 width ≤ 5 pp) | 20 | 60 | 100 | 150 pairs |
|---|---|---|---|---|
| Windows ARM64 MSVC (mean / worst historical run) | 0.11 / 0.05 | 0.42 / 0.20 | 0.62 / 0.34 | **0.79 / 0.56** |
| Windows x64 MSVC | 0.94 / 0.57 | 0.98 / 0.88 | 1.0 / 0.98 | 1.0 / 0.98 |
| Vite (all hosted), Linux ARM64 make | ≥ 0.90 / ≥ 0.39 | ≥ 0.97 / ≥ 0.77 | ≥ 0.99 / ≥ 0.94 | 1.0 / 1.0 |
| Linux x86-64 make | 0.81 / 0.0 | 0.88 / 0.03 | 0.88 / 0.07 | 0.89 / 0.09 (one pathological run) |

On time:
- The campaign costs about 1.1 minutes per pair on Windows ARM64 and 0.95 on Windows x64
  (run 36449450012).
- At 150 pairs every native job stays inside its 330-minute limit; Windows ARM64 needs about
  3.4 hours.
- More pairs would not fit.

Even at 150 pairs, Windows ARM64 MSVC may remain unmeasurable (about a 1-in-5 chance).  If it
does, it is recorded as **hosted runner inconclusive**, not as a pass, and a definitive number
needs dedicated ARM64 hardware.

**Unchanged:**
- the 5 % threshold;
- the workloads;
- WhyFS's on/off behaviour;
- security software (Defender stays on);
- `machine_perf.py` itself (only its `--pairs` argument is 150).

The spawn workload runs in the same campaign, so the historical total-< 5 % spawn rule is now
reported at 150 pairs too.

### 9. The authoritative run under the measurability rule: run 36462972085 (commit 71bee51) -- **FAIL (Windows ARM64 `label` CLI latency)**

The rule and the 150-pair sample count were committed before this run (71bee51).  One run,
not repeated.  `results/release-1.0.0-meas/`.  Product code is identical to 80dabe3.

**Real workloads: every one measurable, every one PASS.**

| Platform | Workload | Status | Median | CI90 (width) | Baseline CV / spread | WhyFS CPU (median, s) |
|---|---|---|---|---|---|---|
| Windows x64 | MSVC | PASS | +1.45 % | 1.38..1.61 (0.23) | 2.3 % / 26 % | 0.078 |
| Windows x64 | Vite | PASS | +2.34 % | 2.04..2.62 (0.58) | 6.5 % / 73 % | 0.0 |
| **Windows ARM64** | **MSVC** | **PASS** | **+1.72 %** | **0.91..2.66 (1.75)** | 6.6 % / 43 % | 0.094 |
| Windows ARM64 | Vite | PASS | +1.14 % | 0.79..1.38 (0.59) | 2.8 % / 17 % | 0.0 |
| Linux x86-64 | make -j8 | PASS | +2.72 % | 1.90..3.89 (2.00) | 6.4 % / 34 % | 0.01 |
| Linux x86-64 | Vite | PASS | +0.40 % | −0.41..0.79 (1.21) | 6.0 % / 46 % | 0.0 |
| Linux ARM64 | make -j8 | PASS | +1.59 % | 1.25..1.86 (0.61) | 4.1 % / 46 % | 0.0 |
| Linux ARM64 | Vite | PASS | −0.02 % | −0.47..0.57 (1.05) | 2.1 % / 17 % | 0.0 |

- Each workload ran 150 pairs; every raw pair is in `machine_perf.json`, and the
  classification is in `contract.json`.
- Windows ARM64 MSVC, never resolvable at 20 pairs, is resolved at 150: **+1.72 %**, a PASS.

**Spawn stress (part B): PASS on all four platforms.**
- Zero loss, and 300/300 outputs correct under stress.
- WhyFS CPU per iteration against its ceiling:

  | Platform | CPU / ceiling | Frozen calibration |
  |---|---|---|
  | Windows x64 | 74.1 / 80.2 ms | 53.5 ms |
  | Windows ARM64 | 87.5 / 129.3 ms | |
  | Linux x86-64 | 24.1 / 42.1 ms | |
  | Linux ARM64 | 21.7 / 32.9 ms | |

- WhyFS's own share was not shown to exceed 3.0 pp on any platform.

**The historical total-< 5 % spawn rule** (150 pairs):
- Windows x64 +5.34 % (4.82..5.68): not met.
- Windows ARM64 +7.14 % (4.50..10.21): not met.
- Linux x86-64 +3.91 %: met.
- Linux ARM64 +4.02 %: met.

**Every functional gate passed on all four platforms:**
- tests (Windows 108, Linux 246 + 246);
- MSI 32/32, upgrade 16/16, `.deb` 24/24;
- product 47/47 and 48/48, outage 16/16 and 13/13;
- all corpora 79/79 with lost 0; secret 22/22;
- functional and graduation PASS; process decoding 0 mismatches.

**The failure: Windows ARM64 `label` CLI median 108.8 ms** (p95 116.9) against the precommitted
< 100 ms (`why` 90.0 ms).
- **It grew on Windows x64 too:** `label` 66–72 ms in the 20-pair runs, 93.1 ms here.
- **The cause is measured, not noise.**
  - machine_perf times `label` on files the campaign itself rebuilt many times: the MSVC
    `app.exe` and the spawn test's `out-150.txt`.
  - At 150 pairs those paths carry hundreds of recorded generations.
  - `label`'s cost grows about linearly with the queried path's own history.
  - On the dedicated desktop, one file rewritten 1, 300 and 600 times gave `label` 61.5, 69.7
    and 81.5 ms, against `why` 55–61 ms (`results/desktop-1.0.0/label-history-probe.txt`).
  - Total store size alone does not explain it: a new file on a 677 MB store gives 59.9 ms.
- **The 20-pair runs never built histories this long**, which is why the effect only surfaced
  now.
- **It is a real product cost.**  A build output that is rebuilt hundreds of times gets a slower
  `label`, and on the slowest supported CPU that crosses the 100 ms criterion.
- **Not changed in this pass:** product code.  The fix belongs to the label's history
  processing, bounded or summarised for long histories, and needs a new validation.

### 10. The label-history fix (d2d7984) and its scoped native validation -- **PASS**

Section 9's failure was `label` latency on files with long histories.  Its cost grew with the
path's number of generations.

**Profiled before any change** (`scripts/profile_label.py`):
- the real `explain_file` on a snapshot of the 677 MB desktop store;
- every SQL statement timed, and SQLite VM work counted;
- probes built through the installed service, each generation written and read by fresh
  processes.

| Generations | 1 | 100 | 300 | 600 | 1,000 | 5,000 |
|---|---|---|---|---|---|---|
| `label`, before (ms) | 7.9 | 12.2 | 19.2 | 30.9 | 47.4 | 227.5 |
| SQL statements, before | 48 | 246 | 646 | 1,246 | 2,046 | 10,046 |
| `label`, after (ms) | 8.5 | 10.9 | 12.1 | 12.5 | 12.2 | 7.9 |
| SQL statements, after | 54 | 199 | 199 | 199 | 199 | 199 |

The fix (commit d2d7984) is query-side only:
- **No schema change, no migration**, and capture, collectors and writer untouched.
- **Identical results via bounded lookups:** index-ordered lookups replace whole-history sorts
  and scans.
- **The label's dependents and readers:** a path with more than 1,000 events or 50 reader
  processes gets them from its most recent activity, and the label says so (`scope`).
- **Nothing is dropped:** `whyfs history FILE --limit 0` and `whyfs impact FILE` still read
  everything.

**Scoped native validation: [run 36500071218](https://github.com/jay-showforge/whyfs/actions/runs/36500071218)**, commit 57d60e4 (d2d7984's product
code plus a README change), on the four native hosted runners.  All jobs passed:
- tests: Windows 116, Linux 254 + 254, including the 8 new long-history tests;
- exact-artifact MSI clean install 32/32 and upgrade 16/16; `.deb` 24/24;
- product 47/47 and 48/48; outage 16/16 and 13/13;
- both corpora 79/79 with lost 0; secret 22/22; the Windows functional gate PASS;
- the long-history gate (`scripts/label_latency_gate.py`).

The long-history gate: real histories built through the installed service, then the CLI timed
round-robin, 25 rounds.

| `label` median (ms) at 1 / 100 / 300 / 600 / 1,000 / 5,000 generations | Worst p95 | `why` median |
|---|---|---|
| **Windows ARM64: 77.1 / 80.8 / 83.7 / 84.5 / 84.3 / 83.7** (the 150-pair run had measured 108.8) | 89.1 | 73 |
| Windows x64: 59.8 / 62.2 / 66.0 / 67.0 / 67.1 / 66.6 | 70.0 | 57 |
| Linux x86-64: 34.8 / 38.5 / 41.7 / 43.2 / 43.2 / 43.4 | 47.3 | 33 |
| Linux ARM64: 29.6 / 33.2 / 36.5 / 38.0 / 38.0 / 38.2 | 38.9 | 28 |
| WSL2 (local, Linux x86-64 package): 22.5 / 24.8 / 27.0 / 27.9 / 27.6 / 27.7 | 30.3 | 21 |

At every depth on every platform, the label names the latest generation's writer, and
`history --limit 0` returns every generation.

**Not re-run, by design.**  The capture and performance campaigns were not repeated for this
query-side change: `machine_perf` at 150 pairs, spawn stress and graduation.  Their
authoritative results remain those of run 36462972085 (71bee51, identical capture code).  That
run's CLI measurement is the one that failed at 108.8 ms; the long-history gate above measures
the same situation directly, up to 5,000 generations.

---

# v0.1 development benchmark

> **Historical record (v0.1 / v0.2, workspace capture).**

This is an engineering checkpoint, not a universal performance claim.

Environment: Linux x86-64 container, Python 3.13.5, local filesystem.
Workload: create 3,000 small workspace files, then read all 3,000. Seven paired runs after warmup, alternating baseline/capture order. The measurement isolates the native capture backend and deliberately excludes Python CLI startup and SQLite post-run import.

```
baseline median: 0.6932s
capture median:  0.7076s
median paired native-capture overhead: 3.59%
paired overheads: 8.8%, 3.6%, 3.7%, -1.3%, -4.5%, -2.6%, 7.4%
```

The collector records only workspace paths by default. Real workloads, storage devices, languages, and filesystem patterns will differ; rerun with `python scripts/benchmark.py` on target hardware.

---

## v0.2 always-on eBPF benchmark (WSL2, real kernel)

**Result: the <5% target is met for real builds, but not reliably for exec-heavy work. v0.2 does not graduate.**

Host: Windows 11 10.0.26200, WSL 2.5.10.0, kernel 6.6.87.2-microsoft-standard-WSL2,
Intel i5-14400F (16 vCPUs), 16 GB RAM, ext4, BCC 0.29.1, Python 3.12.3.
Harness: `scripts/v02_graduation.py --pairs 10 --warmups 2`. Raw data is in `results/v02-validation/`.

### Method

- Workloads run as the normal user (`runuser`, clean `env -i`, Linux-only `PATH`); the daemon runs as root.
- **Paired and alternating:** order is off/on, then on/off; 2 warm-up pairs are discarded.
  The reported number is the **median of the 10 per-pair overheads**. The median of medians is also recorded.
- Each monitored run starts a fresh daemon (`whyfs daemon start`), then does one build that is
  recorded separately as *first build after daemon start*, then the measured build, then stops.
  So the headline number is the per-build cost of a running daemon, and the start-up cost is reported alongside it.
- Workloads:
  1. `make -s -j8`: a 36-unit C project after `make clean` (37 `cc1`/`as` processes plus a link).
  2. A Vite 5 production build (Node 18; async fs goes through io_uring).
  3. `for i in $(seq 1 300); do ./static_copy raw.txt out-$i.txt; done`: a static binary,
     300 fork/execs, with outputs deleted before every run.
- Collector CPU is read from `/proc/<daemon>/stat` around the measured build.
  Stats, stored events and DB growth cover the whole daemon session (both builds).

### Every authoritative run (median paired overhead, %)

| Run | Commit | make -j8 | Vite | static ×300 | Verdict |
|---|---|---|---|---|---|
| grad-final | 46b9764 | 3.06 | −1.83 | **7.60** | FAIL |
| grad-final2 | c8eca9c | 0.86 | 0.42 | 4.29 | PASS |
| grad-final2-replication | c8eca9c (same) | 1.66 | 0.61 | **7.92** | FAIL |
| grad-final3 | adca5fe (final) | 1.11 | 1.13 | **5.56** | FAIL |

First build after daemon start (median %): make 18.2 / 20.0 / 14.3 / 11.2; Vite 2.3 / 1.6 / 6.3 / 3.9;
static 13.5 / 9.4 / 12.1 / 11.3, in the same run order.

Earlier development runs are also kept (`grad-prelim-per-event-wakeup`, `grad-probe-batched-wakeup`).
They used a per-event ring-buffer wakeup and no in-daemon first build.
They measured make 16.0%, Vite 7.4% and static 16.8% (10 pairs), then make 16.1%,
Vite 7.2% and static 10.8% after batched wakeups (4 pairs).

The rule for graduating was fixed before the deciding run: a passing run had to be replicated on the same commit.
grad-final2 passed, and its replication failed.

### Final commit detail (grad-final3)

| | make -j8 | Vite | static ×300 |
|---|---|---|---|
| baseline median | 0.09 s | 0.32 s | 0.13 s |
| paired overheads (10) | median 1.11% | median 1.13% | median 5.56% |
| collector CPU during build (median) | 0.10 s | 0.01 s | 0.10 s |
| ring-buffer events per session | 9,126 | 1,422 | 6,827 |
| stored events per session | 1,333 | 176 | 4,520 |
| DB growth per session | 474 KiB | 64 KiB | 1.5 MiB |
| kernel drops / queue drops | 0 / 0 | 0 / 0 | 0 / 0 |
| SQLite batches (median) / largest batch | 7 / 512 | 9.5 / 46 | 15 / 512 |

SQLite writes are batched (up to 512 rows or 100 ms) on a writer thread. Under a root daemon,
those writes run in a child process that has dropped to the workspace owner's uid.
The traced workload never waits on a commit.

**Queries** (populated DB: 72k events, 25 MB): `why` 0.14 ms median / 0.27 ms p95 in-process;
`whyfs why` CLI end-to-end 50 ms median, mostly Python start-up; `impact common.h` 47 ms.

**Unmodified shipped gate** (`scripts/v02_gate.py`, final commit): PASS on every check. It measured
`make -j4` at 1.09% (5 baseline runs, then 5 runs with the daemon on; not alternating).

### Where the exec-heavy overhead comes from

Diagnosis on the static loop:

- **Userspace is not the cause.** Replacing the Python event callback with a no-op did not change
  wall time, and neither did pinning the collector away from the workload's CPUs.
- **In-kernel BPF run time** (`kernel.bpf_stats_enabled`) was about 3.1 ms per 300 processes after
  the optimisations, down from 3.75 ms. Per call:
  - `security_file_open`: about 0.85 µs (`bpf_d_path` plus a 600-byte reservation).
  - `sched_process_fork`: about 0.95 µs.
  - `sched_process_exec`: about 0.9 µs (argv copy).
  - `security_file_permission`: about 0.13 µs.
- **Wall-clock overhead** is about 20–30 µs per short process, so hook dispatch and cache effects
  make up the rest. Build workloads amortise this and stay in the 0–3% range.

WSL2 timing noise is large: individual pairs range from about −10% to +16%. Rerun the harness on
target hardware before drawing conclusions for another machine.
