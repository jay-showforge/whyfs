# Benchmarks

This file has two parts:
- **the WhyFS 1.0 performance contract**, and the evidence behind it;
- **the historical v0.1 / v0.2 benchmarks**, kept as they were written (below).

Per-platform results are in [docs/PLATFORM_VALIDATION.md](docs/PLATFORM_VALIDATION.md).

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
