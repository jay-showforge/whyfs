# whyfs project status — v0.2.0a1

## Verdict: **V0.2 DOES NOT GRADUATE**

The eBPF backend loads, captures correctly, and passes every functional,
accuracy, drop, noise, query-latency and build-overhead check on a real
WSL2 host. It fails one performance check: **median slowdown under 5% on an
exec-heavy workload** (a statically linked binary run 300 times in a shell loop).
Across four authoritative 10-pair runs, that workload's median paired overhead
was 7.60%, 4.29%, 7.92% and 5.56%. Sub-5% is not reliable there, so v0.2 is not
called graduated. Build workloads were 0.4–3.1% in every run.

### Update 2026-09-26: hot-path profiling, optimization 1, second graduation attempt

**V0.2 PERFORMANCE GATE REMAINS FAILED.**

- Step 1 profiling (`results/v02-hotpath/HOTPATH_REPORT.md`) found that about half of the static-loop
  overhead was collector event processing interfering with the workload. The largest avoidable part
  was a per-event `realpath()` on names.
- Optimization 1 (commit a30fd65) resolves names against the already-canonical base. It cut `lstat`
  calls from 3,038 to 338 per run, and fixed two resolution bugs: symlinks followed on rename/unlink,
  and `link/..` collapsed lexically.
- Two authoritative 20-pair campaigns on frozen commit a5f4746, through the real daemon, measured the
  static ×300 median at **5.80% and 7.19%**. Both fail.
- Make (0.40%, 1.06%), Vite (−1.44%, 0.41%), the functional and accuracy suite (44/44, 118/118, zero
  drops), all 62 tests and the unmodified `v02_gate.py` passed.
- See `results/v02-graduation-final/VERDICT.md`. The in-process profiler's improvement (5.52% → 3.86%)
  did not carry over to the real-daemon harness; that gap is the next thing to characterize.

### Update 2026-09-26 (later): gap resolved; two hypotheses rejected; alpha limitation accepted

**V0.2 PERFORMANCE GATE REMAINS FAILED.** No graduation rerun, because no candidate produced a clear win.

- **Daemon gap** (`results/v02-daemon-gap/DAEMON_GAP_REPORT.md`): there is no real fresh-vs-steady or
  in-process-vs-daemon difference.
  - The steady-state production path costs ≈ 6.3–8.3 ms per 300-process run (≈ 5–7%) in every topology.
  - The profiler's 3.86% was a low reading.
- **Writer-handoff batching** (commit 96b9b9f, `results/v02-handoff/HANDOFF_REPORT.md`):
  - Handoffs fell from 3,014 to 7 per run, collector context switches −79%, collector CPU −26%.
  - Workload time did not change (−0.50 ms, CI −1.27..+0.81), so the hypothesis was rejected.
  - Kept as a collector resource improvement.
- **io_seen** (`results/v02-ioseen/IOSEEN_REPORT.md`):
  - The per-open reset is **required**. Without it, the kernel's reuse of freed `struct file` memory
    suppressed 93 of 100 reopen reads in the new tests.
  - The cheapest correct variant saves ≈ 0.1 ms of BPF time and no measurable workload time.
  - Rejected and reverted; production is unchanged.
- **Accepted limitation (the bound set for this work):** on exec-heavy microprocess workloads, a fresh
  process every ~0.4 ms, whyfs v0.2 costs ≈ 5–7% on this WSL2 host.
  - The cost spreads across per-event kernel hook work (≈ 3 ms BPF per 300 processes), which *is* the
    evidence collection, and ≈ 2 ms of userspace processing and store.
  - No remaining single correctness-neutral cost is large enough to justify further sub-millisecond work.
  - Normal builds measure 0–3%.
  - v0.2 remains an **alpha** with this limitation documented.
- Known noise issue KI-1 (the daemon records its own `daemon.json` replace) is in `docs/KNOWN_ISSUES.md`.

Do not describe v0.2 as proven always-on host-level provenance yet.
The capture is proven correct; the overhead on fork/exec-heavy work is not yet within target.

## Validation host

| | |
|---|---|
| Windows | Windows 11 Home 10.0.26200 |
| WSL | 2.5.10.0, kernel 6.6.87.2-microsoft-standard-WSL2 (BTF present) |
| Distro | Ubuntu 24.04, ext4 (`/home`) |
| CPU / RAM | Intel i5-14400F, 16 vCPUs / 16 GB |
| Toolchain | Python 3.12.3, BCC 0.29.1, clang 18.1.3, gcc 13.3, GNU make 4.3, Node 18.19.1, Vite 5.4.21 |
| Privileges | root, CAP_BPF, CAP_PERFMON; kernel headers via `modprobe kheaders` |
| eBPF load | yes (fentry/LSM hooks, ring buffer) |

The Windows Python installs were not modified. Everything ran inside the WSL distro.

## What was found and fixed during validation

The shipped v0.2.0-alpha gate failed immediately: the BPF program never loaded
(`BPF stack limit is exceeded`, `gate-as-received.stderr`). The fixes below each have a regression test:

- **Kernel program** builds events in ring-buffer reservations (the stack limit).
- **File I/O is observed at the VFS/LSM layer** (`security_file_open` + `bpf_d_path`,
  `security_file_permission`, `security_mmap_file`, `do_renameat2`, `do_unlinkat`).
  Syscall tracepoints were blind to io_uring, and Node/libuv on Ubuntu 24.04 does its async
  file I/O through io_uring: a Vite build issued 97 io_uring requests and its outputs were
  missed entirely.
- **Process identity.** PIDs are translated in-kernel to the collector's PID namespace (WSL runs
  distros in a nested namespace). Per-run process-instance keys survive PID reuse. Threads are
  not processes.
- **Resolution.** I/O is keyed by kernel `struct file *`, not fd numbers, which fixes fd reuse,
  redirection and dup/inheritance. Short-lived processes use a cwd model instead of `/proc`.
  User strings are read at syscall exit. argv is no longer truncated to argv[0], and timestamps
  are wall-clock, not monotonic.
- **Lineage semantics.**
  - Rename-aware `why` and `impact`.
  - Exec-image boundaries: `why` counts reads by the program image that wrote.
  - Causal `impact` only counts reads before the write.
  - gcc's `cc1 → /tmp/cc*.s → as` hop is bridged through derived temporaries.
- **Privacy.** Process rows and command lines are persisted only for processes that produced
  stored evidence, plus a bounded ancestor chain. Before this, every process in the namespace
  was stored, which is broader than preload.
- **Root daemon hardening.** The SQLite store runs as the workspace owner via privilege
  separation. State files are opened with no-follow. Symlinked state is refused. State is
  created 0700/0600, and non-root queries work.
- **Lost-evidence bug**, found by the unmodified shipped gate: in a root-owned workspace the
  in-process store used one SQLite connection across threads, so every event was dropped.
  Fixed, with live end-to-end daemon tests for root- and user-owned workspaces.
- **Overhead reductions:**
  - Batched ring-buffer wakeups instead of one wakeup per event.
  - A `bpf_get_ns_current_pid_tgid` fast path for pid translation.
  - One dedup-map delete per open instead of two.

## Gate results (final commit)

- **Functional:** static binary; `make -j8` of 36 units with header and source rebuilds;
  Vite build plus a post-build script; cp/mv rename chain; `why` / `why --raw` / `impact` /
  `history`. All pass.
- **Creator attribution:** 44/44 (100%). **Useful direct-input recall:** 118/118 (100%).
- **Parentage and census:** `cc1` and `as` each observed 75 times (2 × 37 translation units + 1 rebuilt source), `collect2` 3 times.
  Linker ancestry is `collect2 → gcc → make`.
- **Drops:** 0 kernel, 0 queue, in every run.
- **Queries:** `why` median 0.14 ms in-process, about 50 ms end-to-end via CLI; `impact` on a header about 45 ms.
- **Unmodified shipped gate** (`scripts/v02_gate.py`): **PASS**. It times only `make -j4` (1.09%).
- **Graduation harness** (`scripts/v02_graduation.py`): 45/46 checks. It fails only
  `perf.static_binary_x300.median_overhead_lt_5pct`.

See [BENCHMARK.md](BENCHMARK.md) for every run, and `results/v02-validation/` for raw data.

## Tests

54 tests: v0.1 preload end-to-end, resolver regressions, privacy, state hardening,
static BPF-source checks, and 16 live kernel/daemon tests.
All pass as root; as a normal user, the 16 live tests are skipped and the rest pass
(`results/v02-validation/tests-final-*.log`). The v0.1 preload backend still works.

## What is needed to graduate

The exec-heavy overhead is kernel-side. Replacing the Python callback with a no-op, or
pinning the collector to other CPUs, did not change it. In-kernel BPF time is about
3.1 ms per 300 short processes, and the rest is hook dispatch.
Candidate work, with the static loop as the benchmark:

1. Cheaper exec/fork handling: skip the upid walk for the child and parent where a cached
   mapping exists, and shrink exec events (argv is 511 bytes per exec today).
2. Filter opens of files that can never be stored (pseudo-filesystems, non-workspace
   read-only opens by processes with no workspace I/O) before `bpf_d_path`.
3. A CO-RE/libbpf collector (roadmap v0.4), to measure without BCC's runtime-compiled programs.
4. Re-run `scripts/v02_graduation.py --pairs 10 --warmups 2` at least twice on the same commit.
   Graduate only if both runs pass.

Also reported and not hidden: the **first build after a daemon (re)start** is slower
(make 11–20%, static 9–13%, Vite 2–6% median). An always-on daemon pays this once per start.
