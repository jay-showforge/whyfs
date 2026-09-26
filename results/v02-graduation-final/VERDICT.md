# whyfs v0.2 — authoritative graduation attempt after optimization 1 (2026-09-26)

## Verdict: **V0.2 PERFORMANCE GATE REMAINS FAILED**

Both independent static-binary ×300 campaigns ran on the same frozen commit through the real daemon
and the unmodified graduation harness. **Both are ≥ 5%:** 5.80% and 7.19%. Each fails on its own,
and no averaging applies.

There is no correctness regression. Every functional, accuracy, drop, make, Vite and query check
passed in both campaigns, and the unmodified original `scripts/v02_gate.py` passes. Because the
static gate failed, those results do not change the verdict.

## Frozen code under test

`freeze-manifest.txt` records the following.

| | |
|---|---|
| frozen commit | `a5f474656015383fbb215110e9e8765ad3959937` (clean tree before and after both campaigns) |
| runtime diff vs optimization commit `a30fd65` | 0 lines in `src/`, `tests/`, `scripts/v02_graduation.py`, `scripts/v02_gate.py`; a30fd65..a5f4746 added only an offline analysis script (`scripts/v02_hotpath_compare.py`) and results |
| `scripts/v02_gate.py` vs as-received (7d0a9b1) | 0 lines (unmodified) |
| host | Windows 11 Home 10.0.26200.9457; WSL 2.5.10.0; kernel 6.6.87.2-microsoft-standard-WSL2 |
| CPU / RAM | Intel i5-14400F, 16 vCPU / 16 GB |
| toolchain | Python 3.12.3; BCC 0.29.1; Ubuntu clang 18.1.3 |
| BTF / kernel headers | `/sys/kernel/btf/vmlinux` present; `kheaders` loaded |
| privileges | euid 0, CapEff 000001ffffffffff; `whyfs doctor` ready (cap_bpf, cap_perfmon, btf_vmlinux) |

No code was modified between or during the campaigns.

## Protocol (fixed before any timing)

- Command: `sudo python3 scripts/v02_graduation.py --user ftmon --pairs 20 --warmups 2`, unmodified.
- The harness runs as one unit: functional suite, noise checks, then make, Vite and static ×300 performance. It has no flag to time static alone, so each campaign is one complete harness run.
- Every monitored run uses a **fresh daemon** (`whyfs daemon start`). The daemon does one build that is recorded separately as *first build after start*, then the prep, then the **measured build**, then stops.
- Workloads run as the user through `runuser … env -i`.
- Order alternates between off/on and on/off; 2 warm-up pairs are discarded; 20 pairs are measured.
- Each campaign ran exactly once. Campaign 2 started immediately after campaign 1 with nothing changed.
- Static decision: each campaign's `median_paired_overhead_percent` must be < 5%. Make, Vite and functional checks count only if both static campaigns pass, and must then pass in both.

## Static binary ×300: the deciding workload

| Campaign | baseline median | monitored median | **median paired overhead** | median of medians | first build after start | drops (kernel/queue) | daemon CPU per measured build | ring-buffer events per session |
|---|---|---|---|---|---|---|---|---|
| 1 | 130.4 ms | 138.1 ms | **5.80% — FAIL** | 5.87% | 7.95% | 0 / 0 | 0.080 s | 6,826 |
| 2 | 129.0 ms | 138.7 ms | **7.19% — FAIL** | 7.48% | 11.65% | 0 / 0 | 0.080 s | 6,826 |

Raw per-pair overheads (%):

- Campaign 1: 3.79, 1.31, 5.54, 2.88, 8.71, 7.42, 7.19, 4.10, 4.18, 4.41, 6.78, 8.64, 6.05, 12.59, 3.81, 1.75, 6.16, 7.09, 7.01, 1.56
- Campaign 2: 2.26, 6.95, 7.79, 6.94, 6.19, 9.74, 7.44, 22.27, 19.09, 5.19, 13.24, 12.40, 18.59, 7.72, 6.24, 4.45, 12.28, 3.44, 3.09, 5.53

Every run with its timings, collector stats and DB growth is in `campaign-N/graduation.json` under `performance.static_binary_x300.runs`.

## Other workloads and gates (both campaigns)

| Check | Campaign 1 | Campaign 2 |
|---|---|---|
| make -j8 (36 units): median paired overhead | 0.40% ✅ | 1.06% ✅ |
| make: first build after start | 14.42% | 16.08% |
| Vite build: median paired overhead | −1.44% ✅ | 0.41% ✅ |
| Vite: first build after start | 3.98% | 1.77% |
| drops, every workload | 0 / 0 ✅ | 0 / 0 ✅ |
| creator attribution | 44/44 = 100% ✅ | 44/44 = 100% ✅ |
| useful-input recall | 118/118 = 100% ✅ | 118/118 = 100% ✅ |
| static binary, parallel build (parentage, census, header/source impact, rebuilds), Vite (io_uring-era) and rename lineage; raw/default query views | all pass ✅ | all pass ✅ |
| `why` in-process median / p95 | 0.33 / 0.52 ms ✅ | 0.29 / 0.49 ms ✅ |
| `whyfs why` CLI end-to-end median | 47.5 ms ✅ (< 100 ms) | 46.3 ms ✅ |
| `impact common.h` median (not gated) | 104.8 ms | 90.8 ms |
| harness checks passed | 45/46 (fails only static) | 45/46 (fails only static) |

## Tests and the original gate (same frozen commit, after both campaigns)

| | |
|---|---|
| full suite as root | **62 tests, OK**: includes v0.1 preload end-to-end, privacy, privilege separation, symlink/`..` resolution, and live kernel/daemon tests (`tests-root.log`) |
| full suite as normal user | **62 tests, OK, 16 skipped**: the live tests need root/BCC (`tests-user.log`) |
| unmodified `scripts/v02_gate.py` | **PASS**: static creator and input, node inputs, parallel-build transitive impact, zero kernel drops; `make -j4` overhead 0.20% (`v02_gate.json`) |

As agreed beforehand, the passing original gate cannot override the failed static campaigns.

## Did removing the userspace filesystem resolution make whyfs reliably fast enough?

**No.** The optimization is real at the mechanism level, measured with the identical in-process protocol:

- `lstat` calls fell from about 3,038 to 338 per run;
- userspace interference fell from 4.30 ms to 2.07 ms;
- the `realpath` share went to zero;
- kernel event and ring-buffer counts were identical, with zero drops;
- accuracy was preserved;
- two resolution correctness bugs were fixed.

Details are in `results/v02-hotpath/HOTPATH_REPORT.md`. It did **not** bring the authoritative static
×300 median under 5%:

| Harness static ×300 median paired overhead | Commit | Result |
|---|---|---|
| grad-final (v0.2.0a1 work) | 46b9764 | 7.60% |
| grad-final2 | c8eca9c | 4.29% |
| grad-final2-replication | c8eca9c | 7.92% |
| grad-final3 | adca5fe | 5.56% |
| **campaign 1** (after optimization) | a5f4746 | **5.80%** |
| **campaign 2** (after optimization) | a5f4746 | **7.19%** |

In the authoritative harness, the post-optimization campaigns fall within the range of the
pre-optimization runs. The ~1.7-point improvement seen in the in-process profiler (5.52% → 3.86%)
is **not reproduced** by the real-daemon harness. That discrepancy is itself an open measurement
question for the next cycle, not something to explain away here.

The two setups differ in known ways, none yet shown to matter:

- the harness starts a fresh daemon for each monitored run, including a BCC/clang compile shortly before the measured build;
- the harness measures the second build of each daemon session;
- the daemon runs in a separate process, whereas the profiler's collector is in-process;
- the profiler reattaches programs to an already-loaded object.

## Remaining measured cost centers (from Step 1, post-optimization run `20260926-opt1-a30fd65`)

| Cost center | Per 300-process run | Notes |
|---|---|---|
| Remaining userspace processing interference | ≈ 2.1 ms (X: 2.07, 1.57..2.97; U: 2.13; V: 2.57) | mechanism not isolated; `realpath` component eliminated |
| Kernel BPF work | ≈ 2.93 ms (`bpf_stats`) | `io_seen` LRU operations ≈ 1.2 ms (open-time delete ≈ 421 ns each × 1,077); ring buffer ≈ 0.7 ms; namespace translation ≈ 0.5 ms (WSL `init` foreign tasks ≈ 0.2 ms); `bpf_d_path` ≈ 0.26 ms |
| SQLite / store | ≈ 1.26 ms (U: full − no-store, 0.30..2.90) | batched ingest in the privilege-separated worker |
| Hook dispatch | not measurable | |
| **New:** profiler vs harness gap | ≈ 1.5–3 percentage points | the harness measures more overhead than the in-process profiler; to be characterized before the next optimization is chosen |

The historical failed runs (`results/v02-validation/`) and the profiler runs are all preserved,
including the two runs invalidated by in-process GIL timing (`results/v02-hotpath/20260926-step1-*`,
`…-step1b-*`, labeled in HOTPATH_REPORT.md). A new optimization cycle may begin only from here.
