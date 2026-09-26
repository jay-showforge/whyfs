# whyfs v0.2 — daemon-gap report: why the real daemon measures more than the profiler

**Standing verdict: V0.2 PERFORMANCE GATE REMAINS FAILED** (frozen a5f4746: static ×300 at 5.80% / 7.19%).
This was a diagnostic session. **No production behavior was changed**, and graduation was not rerun.

## Answer

**Why does the real daemon measure 5.8–7.2% when the corrected profiler measured ~3.9%?**

Mostly because **the ~3.9% was a low reading, not the center of the distribution.** The production
path's real steady-state cost on this workload is **≈ 6.3–6.5 ms per run, ≈ 5.1–5.2%**, and that holds
in every real-process topology measured here. The architectural variables suspected of making the
daemon worse were each measured, and **none produced a significant difference**:

| Suspect | Measurement | Result |
|---|---|---|
| separate daemon process vs in-process collector | R: E − C | **+1.33 ms, 90% CI −0.49..+2.54**: not significant |
| cold/fresh daemon state decaying with use | F1/F2: 25 consecutive runs on one daemon | **no decay**; overhead is flat from run 1 to run 25 (median +5.14% / +5.61% / +5.15% for runs 1–5 / 6–15 / 16–25) |
| startup aftermath (BCC/clang compile, first build, CPU/cache state) | K: start daemon, first build, *stop*, then measure | **+0.63%, CI −0.66..+1.94**: no significant residue |

Supporting evidence that the ~3.9% was optimistic:

- **The profiler's own run disagreed with itself.** In the run that produced 3.86% (`results/v02-hotpath/20260926-opt1-a30fd65`), phase T gave +4.77 ms per run (3.86%, CI 2.00..6.46). Phase U, from the same run on the same code, gave full − baseline = **+7.72 ms (≈ 6%)**, CI 6.58..8.41.
- **In this experiment, the profiler-equivalent in-process topology (C) measured 4.45%** (CI 3.32..5.88), and the real separate-process production path (E) measured **5.09%** (CI 4.51..5.97). Those overlap each other and the harness campaigns.

**One part is not fully explained.** The exact graduation-harness pattern (G: fresh daemon per measured
build) measured **7.80%** (+9.78 ms, CI 6.81..9.88%). That is ≈ 3.3 ms above the steady-state
separate-process figure (E, +6.33 ms) and the persistent daemon (F1, +6.54 ms). The executed
evidence does not attribute that excess to the fresh lifecycle:

- K shows no startup residue.
- F shows no elevated early runs.
- In G itself, the first build after start (6.39%) was *below* the measured second build (7.80%).

G ran last in the session, and the persistent series F2, run just before it, drifted up to about +12%
in its final four runs. So session-level variance is a plausible explanation, but **it is not
demonstrated. The ≈ 3 ms excess of the harness pattern over steady state is reported as unexplained.**

**Bottom line:** removing `realpath` was real at the mechanism level. It still holds in the real daemon:
617 name resolutions but only 18 canonicalizations per run. But the remaining steady-state cost of
the production path is ≈ 5%, and on WSL2 the run-to-run variance is ±2–3 percentage points. So
individual 20-pair campaigns land between about 4% and 8%, and a < 5% gate cannot be passed reliably.

## Experiment

`scripts/v02_daemon_gap.py`, with `scripts/v02_gap_agent.py` as the separate-process collector.

- Commit 14f630b: production code identical to frozen a5f4746 (0-line diff in `src/`, `tests/`, the harness). Tests OK before the run.
- Raw data: `20260926-gap-14f630b/gap.json`, with derived tables in `…/derived.json`, `…/tables/*.csv` and `…/GAP_TABLES.md`.
- Workload: exactly the graduation harness's static ×300 (prep `rm -f out-*.txt`, the harness loop, as the user via `runuser … env -i`; asserted against `scripts/v02_graduation.py`).
- **All timing is measured inside the workload's own shell** (`date +%s%N`). No timing comes from a Python process that takes part in collection, so the GIL mistake cannot recur.
- Per-run OS metrics:
  - `/usr/bin/time` rusage for the workload and its reaped children (context switches, faults; zero cost);
  - migrations of the loop shell (`/proc/$$/sched`);
  - `/proc` for the collector and store worker (CPU, faults, context switches and migrations summed over threads, `write_bytes`);
  - collector counters (events, records, drops, SQLite ingest time and rows, resolve/canon calls);
  - BPF run time in dedicated `bpf_stats` phases.
- `perf stat -a` was calibrated first: it added **+4.94 ms** per run (CI 3.07..8.92) to the baseline loop, so it was **disabled** for all measurements.

| Phase | What | Design |
|---|---|---|
| R | A baseline / B kernel only / C in-process full / D separate process, processing, no SQLite / E separate process, production path | one persistent agent and one in-driver collector, attach/detach per run; **40 rounds rotated over 10 orders** |
| S | BPF run time per run | agent, full mode, `bpf_stats` on, idle-subtracted, 10 reps |
| F1 | **persistent real daemon** (`whyfs daemon start`), bpf_stats off | 10 baselines, start, **25 consecutive runs recorded individually**, stop, 10 baselines |
| F2 | same, bpf_stats on | per-run BPF time from the daemon's prog fds |
| G | graduation-harness pattern | prep, start, sleep .3, first build, prep, measured, sleep .3, stop; **20 alternating pairs** + 2 warm-up |
| K | lifecycle control | as G, but the daemon is stopped before prep and the measured build; 20 pairs + 2 warm-up |

## Results

### Steady-state topology split (R; per 300-process run)

| Mode | Configuration | Wall | Overhead vs A (90% CI) |
|---|---|---|---|
| A | baseline | 125.5 ms | — |
| B | kernel only (separate agent, callback discards) | 128.9 ms | +3.05% (1.23..4.20) |
| C | in-process full collector (profiler topology) | 131.1 ms | +4.45% (3.32..5.88) |
| D | separate process, full processing, no SQLite | 131.3 ms | +5.10% (3.57..6.36) |
| E | separate process, production path | 132.0 ms | +5.09% (4.51..5.97) |

| Difference | ms per run (90% CI) |
|---|---|
| B − A: kernel programs + ring consumption | +3.91 (1.55..5.26) |
| D − B: event processing in a separate process | +3.34 (2.36..4.01) |
| E − D: SQLite store | +0.95 (0.11..1.78) |
| **E − A: production path, steady state** | **+6.33 (5.67..7.54)** |
| C − A: in-process full collector | +5.59 (4.14..7.39) |
| E − C: separate vs in-process | +1.33 (−0.49..+2.54), n.s. |

BPF run time (S): **3.27 ms per run** (CI 3.13..3.39), consistent with B − A.

### OS-level metrics per run (R, medians)

| Metric | A | B | C | D | E |
|---|---|---|---|---|---|
| workload voluntary / involuntary context switches | 356 / 5 | 365 / 4.5 | 358 / 6.5 | 357 / 8.5 | 360 / 7 |
| workload minor faults | 22,830 | 22,828 | 22,834 | 22,825 | 22,830 |
| loop-shell migrations | 0 | 1 | 1 | 1 | 1 |
| collector user / sys CPU | — | 0.02 / 0.06 s | 0.09 / 0.08 s | 0.10 / 0.095 s | 0.10 / 0.08 s |
| **collector voluntary context switches** | — | **98** | 2,178 | **3,300** | 2,118 |
| collector migrations | — | 1 | 30 | 47 | 26 |
| collector minor faults | — | 0 | 79 | 30 | 110 |
| events received / records submitted | — | — | 3,748 / 3,014 | 3,748 / 3,014 | 3,748 / 3,014 |
| name resolutions / canonicalizations (`realpath`) | — | — | — | 617 / 18 | 617 / 18 |
| SQLite ingest (store worker, wall) / rows | — | — | — | — | 44 ms / 3,014 |
| store worker CPU / bytes written | — | — | 0.02 s / 7.2 MB | — | 0.02 s / 7.5 MB |
| kernel / queue drops | — | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |

### Persistent daemon time series (F1: bpf_stats off; one daemon, no restart)

Baseline median 126.5 ms (before 125.8, after 126.9). Overhead per run:

| run | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| % | +4.2 | +4.3 | +6.9 | +5.1 | +5.6 | +6.0 | +9.0 | +3.2 | +6.1 | +4.7 | +5.2 | +3.7 | +3.3 | +13.8 | +8.5 | +2.0 | +5.0 | +5.8 | +6.2 | +3.1 | +5.0 | +3.8 | +7.2 | +6.3 | +5.3 |
| daemon minflt | 448 | 36 | 43 | 133 | 14 | 147 | 3 | 91 | 16 | 120 | 17 | 139 | 6 | 75 | 15 | 145 | 23 | 92 | 19 | 106 | 14 | 142 | 4 | 107 | 11 |

Median: runs 1–5 +5.14%, runs 6–15 +5.61%, runs 16–25 +5.15%, all **+5.17% (+6.54 ms)**. Every run
received 2,416 new stored events. Daemon CPU was flat at 0.08–0.12 s per run, and store-worker writes at
8.3–10.2 MB per run. Zero drops.

### F2: bpf_stats on

| run | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| % | +3.9 | +31.7 | +3.5 | +6.3 | +7.0 | +5.5 | +8.2 | +7.1 | +8.3 | +6.4 | +8.1 | +3.8 | +10.3 | +8.1 | +9.7 | +8.4 | +2.2 | +6.9 | +6.2 | +7.9 | +6.3 | +12.2 | +11.8 | +12.9 | +12.2 |
| BPF ms | 3.34 | 5.31 | 3.31 | 3.70 | 3.43 | 3.46 | 3.49 | 3.48 | 3.99 | 3.66 | 3.69 | 3.53 | 3.70 | 3.56 | 3.60 | 3.67 | 3.53 | 3.74 | 3.69 | 3.54 | 3.35 | 3.63 | 3.61 | 3.65 | 3.75 |

Median: runs 1–5 +6.28%, runs 6–15 +8.11%, runs 16–25 +8.14%, all +7.91%. The `bpf_stats` accounting
adds a little per program call, so these read slightly higher than F1.

Run 2 (+31.7%) coincides with 49 loop-shell migrations and 5.31 ms of BPF time: a scheduling outlier.
The last four runs rise to about +12% with BPF time unchanged, which is drift outside the BPF programs.

**Shape: high → high → high. There is no warm-up decay.** BPF run time per run is flat, so kernel state
does not warm. Daemon page faults drop after run 1 (448 → tens), but workload time does not follow, so
Python runtime and allocator warm-up are not a measurable cost. The store worker's per-run write volume
and CPU are flat, so SQLite cache state does not warm measurably. The workload's own faults and
context switches are identical across all configurations.

### Harness pattern and lifecycle control

| Phase | Measured build overhead (90% CI) | First build after start | Pairs (%) |
|---|---|---|---|
| G: fresh daemon per measured build | **+7.80%** (6.81..9.88) = +9.78 ms | +6.39% | 6.6, 11.2, 11.6, 9.9, 10.6, 10.2, 7.1, 6.8, 5.3, 8.4, 8.4, 4.3, 5.5, 15.6, 5.9, 6.7, 6.8, 9.8, 7.2, 18.3 |
| K: same, daemon stopped before measuring | **+0.63%** (−0.66..+1.94) = +0.79 ms | +7.36% (daemon present) | 0.6, 2.1, −6.0, 1.1, 1.0, −0.0, −1.1, 3.9, 2.8, −0.7, −4.4, −17.8, −4.2, 9.6, 0.6, −2.4, 4.2, 1.9, −0.2, 2.7 |

## Component model (static ×300, per 300-process run)

| Component | Measured added cost/run | Confidence / noise | Avoidable? |
|---|---|---|---|
| Kernel BPF programs + ring consumption | **+3.91 ms** wall (B − A); **3.27 ms** BPF run time (S) | wall CI 1.55..5.26; run-time CI 3.13..3.39 | **partially**: `io_seen` open-time delete ≈ 0.45 ms and WSL-`init` foreign walks ≈ 0.13–0.2 ms; the rest is evidence collection |
| Event processing (separate process) | **+3.34 ms** (D − B) | CI 2.36..4.01 | **likely partially**: coincides with ≈ 3,300 collector voluntary context switches per run (vs 98 kernel-only), ≈ 1 per submitted record |
| SQLite store | **+0.95 ms** (E − D) | CI 0.11..1.78 | partially: 7.5 MB written per run for 3,014 rows. **Confirms ≈ 1 ms** in the real separate process (earlier estimate 1.1–1.3 ms) |
| Daemon startup / warm state | **≈ 0**: no decay over 25 runs; K residue +0.79 ms | K CI −0.84..+2.45 ms | not a cost center |
| Process topology (separate vs in-process) | +1.33 ms (E − C) | CI −0.49..+2.54, n.s. | — |
| Harness fresh-daemon pattern excess over steady state | ≈ +3.2–3.5 ms (G − E, G − F1) | not reproduced by F or K; session drift plausible, unproven | **unexplained** |
| Unexplained, steady state | −1.88 ms: components sum to 8.21 ms vs E − A 6.33 ms | medians of paired differences are not additive; each CI ±1–2 ms | — |
| **Total, steady-state production path** | **+6.33 ms (5.09%)**; persistent daemon +6.54 ms (5.17%) | E CI 4.51..5.97% | |

## Next optimization (proposed, not implemented)

**Target: per-record cross-thread handoff in the collector.** The poller thread hands every
normalized record to the SQLite writer thread with its own `queue.put`, which wakes the writer:
a futex wake and a cross-CPU thread wakeup per record.

Evidence:

- **Size:** event processing (D − B) is the largest avoidable-looking component, at **+3.34 ms** per run.
- **Context switches:** in D the collector makes **3,300 voluntary context switches per run** for **3,014 submitted records**, against 98 in kernel-only mode (B).
- **Busy vs waking:** in the Step 1 "burn" control, a busy Python thread with no wakeups did *not* slow the workload (+0.50 ms, CI −0.45..+1.85). So *waking*, not *computing*, is the suspect.

Proposed change:

- Batch the handoff: one queue item per ring-buffer drain cycle (a list of records) instead of one per record.
- The same records go to SQLite in the same order, with the same bounded-queue drop accounting, so it is evidence-neutral.
- Expected to cut writer wakeups from about 3,000 per run to about 20 (one per 50 ms poll).

Test protocol:

1. Unit tests for record order, bounded-queue drop counting and flush-on-stop.
2. Rerun this exact topology matrix; compare D − B, collector context switches and E − A.
3. Only then a frozen-commit graduation campaign pair.

**Honest expectation:** even if all of D − B's wakeup component disappeared, the steady-state
path would still carry about 3–4 ms of kernel cost plus about 1 ms of store cost, roughly 3.5–4%.
That is below 5% in steady state, but not by the 2–3-point margin that WSL2's run-to-run variance
would need for two 20-pair campaigns to pass reliably. The kernel items (`io_seen` delete,
foreign-task walks) would be the following candidates.
