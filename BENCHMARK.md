# v0.1 development benchmark

> **Historical record (v0.1 / v0.2, workspace capture).**  The measurements for WhyFS 1.0 --
> machine-wide service, all supported platforms, native runners -- are in
> [docs/PLATFORM_VALIDATION.md](docs/PLATFORM_VALIDATION.md).

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
