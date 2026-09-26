# whyfs v0.2 — Step 1 hot-path report (static-binary ×300)

**Standing verdict: V0.2 DOES NOT GRADUATE.** This report measures where the exec-heavy overhead goes.
No production optimization was made during Step 1: the BPF program and collector are
unchanged, and diagnostics compile only under `WF_PROFILE` / `WF_PROFILE_TIME` / `WF_NULL_MASK`.

## Headline

Median paired overhead was **5.52%** (90% CI 3.37–7.25%) over 20 alternating pairs, or 7.06 ms per
300-process run (23.5 µs per process).

| Source | Share | Mechanism |
|---|---|---|
| **Userspace event processing** | ≈ 45–50% | Interferes with the workload while it runs. Pure CPU load does *not* do this (a spinning thread costs +0.50 ms, CI −0.45..+1.85), but real processing does (+4.25 ms, 3.34..5.35). |
| — of which `realpath()` | ≈ 2.5 ms/run (CI 1.9–4.1) | `lstat` traffic from name canonicalization. |
| **Kernel BPF programs** | ≈ 3 ms/run, ≈ 35% | `io_seen` hash-map operations are the largest part (~40% of BPF time). Hook dispatch itself is not measurable (null-all − baseline: −0.23 ms, CI −1.71..+0.97). |
| **SQLite store** | ≈ 1.1 ms/run (CI 0.43–1.96), ≈ 10–15% | Batched ingest in the privilege-separated worker. |

Selected next target: **userspace name resolution**. `realpath()` on rename, unlink and exec names
is also *semantically wrong* for rename and unlink: it follows a final-component symlink. That was
confirmed by two new failing regression tests (see "Correctness finding").

## Evidence, runs and methodology

All runs used the exact workload from `scripts/v02_graduation.py`:

- the same `STATIC_C` source, built the same way (`gcc -static -O2`);
- prep `rm -f out-*.txt`;
- the loop `for i in $(seq 1 300); do ./static_copy raw.txt out-$i.txt; done`, run as the user through `runuser … env -i`.

The profiler asserts at start-up that both command strings appear verbatim in the harness.

| Run (`results/v02-hotpath/…`) | Commit | Phases | Status |
|---|---|---|---|
| `20260926-step1-f7e978e` | f7e978e | P, T, A | Counts valid. **Wall timings contaminated** (Python-side timing; see below). Kept, not used for conclusions. |
| `20260926-step1b-2471a52` | 2471a52 | Q, U | Section times valid. **Phase U wall timings contaminated** (same reason). Kept. |
| `20260926-step1c-751d6f3` | 751d6f3 | P, Q, T, A, U, V, W | **Authoritative for Step 1.** Shell-timed. |
| `20260926-step1d-7726faf` | 7726faf | X | **Authoritative.** Shell-timed; isolates `realpath`. |

These commits differ from the v0.2.0a1 baseline (247dcb0) only in diagnostics:

- compile-time counters and timers;
- `BCCCollector(extra_cflags=…)`;
- `wf_cur_tgid()` gained a program-id argument and a single-return shape, which is equivalent code in the production build;
- the profiler and report scripts.

Every run directory has `git-status.txt`, `git.diff`, `environment.json`, `params.json`,
`console.log`, raw `hotpath.json`, `derived.json`, CSV tables and `HOTPATH_TABLES.md`.

Host: Windows 11 10.0.26200, WSL 2.5.10.0, kernel 6.6.87.2-microsoft-standard-WSL2, i5-14400F (16 vCPU),
16 GB RAM, BCC 0.29.1, Python 3.12.3.

Phases:

- **P**: `-DWF_PROFILE` build under the real collector and privilege-separated store. 10 counted reps. Each rep has an equal-length idle window, subtracted as background.
- **Q**: the same, plus `-DWF_PROFILE_TIME` section timers. Timers add about 2 × `bpf_ktime_get_ns` each, so section times are **approximate** and used only to split a program's cost.
- **T**: **production build (no diagnostic flags)** under the real collector.
  - 2 warm-up + 20 alternating detached/attached pairs.
  - Then 10 `bpf_stats` run-time reps with idle subtraction. Stats are off during timing because stats accounting adds cost.
- **A**: for each hot hook, the production program vs the same program with that hook's body nulled (`WF_NULL_MASK`). Both are loaded; 40 rotated baseline/normal/nulled rounds. Plus a null-all variant.
- **U**: one real collector; 40 rounds counterbalanced over 8 orders: baseline / kernel-only (ring callback discards) / no-store (full processing, SQLite ingest discarded) / full.
- **V**: as U, with **burn** (callback discards while a Python thread spins for the whole run) in place of full. **W**: per-event-type callback time, and a cProfile of 5 no-store runs.
- **X**: baseline / kernel-only / no-store / canon-only (discard, but perform exactly the `realpath` calls processing makes) / no-store-nocanon (processing with `realpath` → `normpath`; diagnostic only). 40 rotated rounds.

### Measurement artifact found and corrected

The first two runs timed the workload in the same Python process as the collector. A busy
collector thread holds the GIL, which delays the timing thread each time it wakes to drain the
child's pipes or reap it. That inflates Python-side times without slowing the workload. With a
spinning thread, Python-side timing showed +55 ms while the shell-timed loop showed +0.3 ms.

From run 1c on, the loop is timed **inside the workload's shell**: `date +%s%N` around the
unchanged harness command. Python-side times are still recorded as `*_outer`.

The authoritative graduation harness is unaffected, because its daemon is a separate process.
The v0.2.0a1 claim "userspace is not responsible" (from one unpaired comparison) is superseded
by this report. The earlier evidence is left untouched.

### Validation checks (run 1c)

| Check | Result |
|---|---|
| open: calls = early exits + records (1384 = 306 + 1077) | ✅ |
| open: ring-buffer records = `io_seen` deletes (1077) | ✅ |
| permission: `io_seen` updates = records (980) | ✅ |
| mmap: updates = records (89) | ✅ |
| fork / exec / exit ≈ processes (305 / 306 / 305 for 300 + runuser, env, bash, seq) | ✅ |
| production timing built without `WF_PROFILE` (phase T flags = []) | ✅ |
| idle windows subtracted (10/10 in P, Q and T run-time reps) | ✅ |
| ablation rounds per variant | 40 × 7 (+1 warm-up each) ✅ |
| timing pairs | 20 (+2 warm-up) ✅ |
| kernel drops / queue drops | 0 / 0 in every phase ✅ |
| workload identical to harness | asserted by the profiler ✅ |
| any conclusion from a single sample | no: medians over ≥ 10 reps / 20 pairs / 40 rounds, with bootstrap 90% CIs |

**Noise:** single pairs vary widely (phase T IQR of per-pair overhead 1.93–9.81%, about ±5 ms per run),
so **effects below ~1 ms per run are not wall-measurable** with 20–40 rounds. Kernel sub-costs are
therefore ranked by `bpf_stats` (precise) and phase Q (approximate). All seven per-hook ablations are
**inconclusive**: every 90% CI spans 0.

Absolute overhead also differs between phases run minutes apart: full − base was 7.06 ms in T and
10.72 ms in U. Differences *within* a rotated phase are more reliable than comparisons across phases.

## Per-hook table (run 1c; per 300-process run)

Counts come from the WF_PROFILE build. "idle-adj." means the workload window minus an equal idle
window. Run time and ns/call come from the production build.

| hook | calls (window) | calls (idle-adj.) | early exits | `io_seen` lookups | updates | deletes | rb records | rb bytes | upid walks | BPF µs/run | ns/call | % BPF | ablation body ms (90% CI) | necessity |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| security_file_open | 1398 | 1384 | 306 | 0 | 0 | 1077 | 1077 | 637,584 | 305 | 1258 | 910 | 42.1% | −0.08 (−0.76..+0.85) inconclusive | necessary (workspace opens are the evidence); the delete's lock and the 306 foreign calls are avoidable |
| security_file_permission | 3992 | 3963 | 2676 | 3914 | 980 | 0 | 980 | 78,400 | 305 | 890 | 277 | 29.8% | +0.53 (−0.51..+1.77) inconclusive | necessary (actual read/write evidence); 306 foreign calls avoidable |
| sched_process_fork | 305 | 305 | 0 | 0 | 0 | 0 | 305 | 24,400 | 305 | 287 | 942 | 9.6% | +0.30 (−1.49..+1.47) inconclusive | necessary here: every process in this workload touches the workspace |
| sched_process_exec | 306 | 306 | 0 | 0 | 0 | 0 | 306 | 337,824 | 306 | 248 | 812 | 8.3% | −0.27 (−1.30..+2.22) inconclusive | necessary (exe and argv of relevant processes) |
| security_mmap_file | 1466 | 1466 | 1377 | 1441 | 89 | 0 | 89 | 7,120 | 0 | 198 | 135 | 6.6% | −1.00 (−2.39..+0.82) inconclusive | necessary (mmap read/write evidence); mostly dedup exits |
| sched_process_exit | 305 | 305 | 0 | 0 | 0 | 0 | 305 | 24,400 | 0 | 92 | 301 | 3.1% | −0.90 (−1.71..+0.33) inconclusive | necessary (PID-reuse process keys) |
| sys_enter/exit_chdir | 2 + 2 | 2 + 2 | 0 | — | — | — | 0 | 0 | 0 | 16 | ~4000 | 0.5% | — | necessary (cwd model) |
| rename / unlink / fchdir | 0 in the timed loop | | | | | | | | | 0 | | | — | the 300 unlinks happen in the untimed prep |

Total production BPF run time: **2.99 ms per run = 9.96 µs per process.** Null-all vs baseline:
dispatch is **not distinguishable from zero** (−0.23 ms, CI −1.71..+0.97). Normal vs null-all:
body work +2.83 ms (CI 1.53..3.93), which agrees with `bpf_stats`.

### Map operations actually paid

`io_seen` (LRU hash) is the only map the hot path touches. The lifecycle hooks use no maps.
There are no kernel maps for PID/process, relevance or fd state: those live in userspace.

| hook | map | lookups | updates | deletes | per process | Q time per op |
|---|---|---|---|---|---|---|
| security_file_open | io_seen | 0 | 0 | 1077 | 3.6 | **421 ns per delete** (453 µs/run) |
| security_file_permission | io_seen | 3914 | 980 | 0 | 16.3 | 116 ns (643 µs/run) |
| security_mmap_file | io_seen | 1441 | 89 | 0 | 5.1 | 69 ns (106 µs/run) |
| fork / exec / exit | — | 0 | 0 | 0 | 0 | — |
| rename / unlink / chdir | pending_*, scratch_* | only on those syscalls (not in the timed loop) | | | | |

The open-time delete almost always targets an **absent** key: a fresh `struct file` pointer.
An LRU-hash delete takes the bucket lock even then, while a lookup is lockless.

### Section times inside programs (phase Q, approximate)

| hook | namespace translation | `bpf_d_path` | `io_seen` ops | ring buffer (reserve + fill + submit) | exec copies |
|---|---|---|---|---|---|
| security_file_open | 214 µs (155 ns × 1383) | 260 µs (241 ns × 1077) | 453 µs (421 ns × 1077) | 299 µs (278 ns × 1077) | — |
| security_file_permission | 108 µs (84 ns × 1286) | — | 643 µs (116 ns × 5555) | 128 µs (130 ns × 980) | — |
| security_mmap_file | 4 µs | — | 106 µs (69 ns × 1530) | 11 µs | — |
| sched_process_exec | 91 µs (298 ns × 306: parent walk) | — | — | 76 µs (247 ns) | 84 µs (276 ns: filename + 511-byte argv) |
| sched_process_fork | 92 µs (302 ns × 305: child walk) | — | — | 145 µs (475 ns, incl. child comm copy) | — |
| sched_process_exit | 23 µs (75 ns: fast path) | — | — | 40 µs (131 ns) | — |

## Userspace (runs 1c and 1d; rotated rounds, shell-timed; ms per run)

| comparison | U (1c) | V (1c) | X (1d) |
|---|---|---|---|
| kernel-only − baseline | +4.64 (3.63..5.94) | +3.82 (3.24..4.34) | +2.74 (1.99..3.55) |
| no-store − kernel-only (Python processing) | **+4.73 (4.29..5.28)** | **+5.44 (3.00..6.52)** | **+4.30 (3.57..5.32)** |
| full − no-store (SQLite store) | +1.12 (0.43..1.96) | | |
| burn − kernel-only (CPU spin only) | | +0.50 (−0.45..+1.85) | |
| no-store − burn | | +4.25 (3.34..5.35) | |
| canon-only − kernel-only (`realpath` calls alone) | | | +0.65 (−0.62..+1.54), inconclusive |
| no-store-nocanon − kernel-only | | | +1.44 (0.33..2.54) |
| **no-store − no-store-nocanon (`realpath` in processing)** | | | **+2.53 (1.91..4.07)** |

Collector CPU per run: kernel-only 48 ms, no-store 193 ms, full 147 ms. Store worker: about 20 ms.

What the three phases show:

- **Userspace processing reproducibly costs about 4.3–5.4 ms per run**, and the effect is not generic CPU load.
- Removing `realpath` from processing removes about 2.5 ms of it.
- The `realpath` calls alone, done in a quick burst, do not reproduce the effect. So it depends on the calls interleaving with the running workload, with the `lstat` path walks happening in the directory where the workload is creating and deleting files at that moment. The precise kernel-level contention point was **not** isolated.
- The remaining about 1.4 ms (CI 0.33..2.54) of processing cost has **no isolated mechanism: uncertain.**

Per-event callback time (phase W, no-store):

| event | per run | µs/event | ms/run |
|---|---|---|---|
| exec | 310 | 108 | 33.6 |
| open | 1264 | 24.4 | 30.8 |
| unlink | 300 | 84.7 | 25.4 |
| read / write | 793 / 300 | 14.5 / 14.4 | 11.5 / 4.3 |
| fork / exit / mmap / chdir | | 6.9 / 4.1 / 2.2 / 32 | 2.1 / 1.3 / 0.3 / 0.1 |

cProfile over 5 runs: 15,190 `posix.lstat` calls (**≈ 3,040 per run**) from about 614 `realpath` calls per run.
Exec names (`./static_copy`) and unlink names (`out-N.txt`) each walk about 5–6 path components.

## WSL `init` (foreign-task) invocations

Diagnostic evidence (`nsfail` probe, reproduced by the phase P/Q counters):

- WSL's `init` lives in the root PID namespace, outside the monitored one.
- For **every** new process it opens and reads `/proc/<pid>/cmdline`.
- `bpf_get_ns_current_pid_tgid` returns `-EINVAL` for it, and the upid walk then runs and can never succeed.

| hook | foreign invocations/run | upid walks/run | est. ns/call | est. µs/run | events emitted |
|---|---|---|---|---|---|
| security_file_open | 306 | 306 | ~436 | ~133 | 0 |
| security_file_permission | 306 | 306 | ~230 (incl. `io_seen` lookup) | ~70 | 0 |
| **total** | **612 (≈ 2 per process)** | **612** | | **≈ 204 µs/run** | **0** |

That is ≈ 6.8% of BPF run time and ≈ 2.9% of the measured wall overhead, and it is an upper bound on
the effect on wall time: `init` runs concurrently, on its own CPU. It emits no provenance.

Deterministic early rejection is possible without losing valid events. A task whose PID namespace is
an *ancestor* of the monitored one, meaning its upid level is lower than ours, can never have a pid in
our namespace, so the walk's result (0, event dropped) is known in advance. Tasks in *nested*
namespaces (containers) must still take the walk. The saving is only the walk (~0.13 ms per run),
because the hook dispatch and failed helper call remain. **Small; not selected.**

## Rankings (static ×300, per 300-process run)

### 1. Total cost

| Rank | Cost center | Calls/run | ns/call | Total | % of measured overhead* |
|---|---|---|---|---|---|
| 1 | Userspace event processing (interference) | 3,064 events | 14–108 µs CPU/event | **4.3–5.4 ms** (X: 4.30, 3.57..5.32) | ≈ 45–50% |
| 1a | … `realpath` / `lstat` within processing | ~614 realpaths / ~3,040 lstat | ~10 µs per lstat (CPU) | **2.53 ms** (1.91..4.07) | ≈ 25–30% |
| 1b | … remaining processing (mechanism unknown) | | | 1.44 ms (0.33..2.54) | ≈ 15% (uncertain) |
| 2 | Kernel BPF programs (`bpf_stats`) | 7,733 invocations | 387 (average) | **2.99 ms** | ≈ 35% |
| 2a | … `io_seen` map operations | 7,501 | 69–421 | ~1.20 ms (Q) | ≈ 40% of BPF |
| 2b | … ring-buffer emission | 3,062 records | 130–475 | ~0.70 ms (Q) | ≈ 23% of BPF |
| 2c | … namespace translation (incl. WSL `init`) | 4,285 | 75–436 | ~0.53 ms (Q) | ≈ 18% of BPF |
| 2d | … `bpf_d_path` | 1,077 | 241 | ~0.26 ms (Q) | ≈ 9% of BPF |
| 2e | … exec filename + argv copies | 306 | 276 | ~0.08 ms (Q) | ≈ 3% of BPF |
| 3 | SQLite store (batched, privilege-separated worker) | ~5 batches | — | **1.12 ms** (0.43..1.96) | ≈ 10–15% |
| 4 | Hook dispatch (trampolines) | 7,733 | — | not measurable (−0.23, −1.71..+0.97) | ~0 |

\* Shares use the ~7–11 ms/run total; kernel sub-rows are shares of BPF time.

### 2. Cost per invocation

| Rank | Operation | ns (or µs) per call | Calls/run |
|---|---|---|---|
| 1 | Python callback, exec event (includes `realpath` of the exe) | 108 µs | 310 |
| 2 | Python callback, unlink event (includes `realpath`) | 85 µs | 300 |
| 3 | Python callback, open event | 24 µs | 1,264 |
| 4 | Python callback, read / write event | 14.5 µs | 1,093 |
| 5 | BPF `sched_process_fork` program | 942 ns | 305 |
| 6 | BPF `security_file_open` program | 910 ns | 1,384 |
| 7 | BPF `sched_process_exec` program | 812 ns | 306 |
| 8 | ring-buffer reserve/fill/submit for fork (incl. comm copy) | ~475 ns | 305 |
| 9 | namespace translation, WSL-`init` foreign task | ~436 ns (open) / ~230 ns (perm) | 612 |
| 10 | **`io_seen` delete at open (LRU hash, bucket lock)** | **~421 ns** | 1,077 |
| 11 | upid walk (fork child, exec parent) | ~300 ns | 611 |
| 12 | BPF `sched_process_exit` program | 301 ns | 305 |
| 13 | ring-buffer emission for open | ~278 ns | 1,077 |
| 14 | BPF `security_file_permission` program | 277 ns | 3,963 |
| 15 | `bpf_d_path` | ~241 ns | 1,077 |
| 16 | `io_seen` lookup/update (permission) | ~116 ns | 4,894 |
| 17 | fast namespace translation (helper) | ~75 ns | ~3,060 |

### 3. Avoidable cost

| Rank | Candidate | Estimated saving/run | Evidence-neutral? | Confidence |
|---|---|---|---|---|
| **1** | **Resolve rename/unlink/exec names without `realpath`**: canonical base (cwd model or directory file) joined with the name; parent canonicalized only when the name has `/` or `..`; exec keeps one final-component check | **~2.5 ms** (X: 1.91..4.07) | Yes, and it **fixes** a wrong-path bug for final-component symlinks | High (direct measurement) |
| 2 | `io_seen` open-time delete → lockless lookup, delete only if present | ≤ ~0.35 ms (Q) | Yes (no I/O can happen on a `struct file` before its open returns) | Medium; below wall noise, needs `bpf_stats` to verify |
| 3 | Reject ancestor-namespace (WSL `init`) tasks before the upid walk | ≤ ~0.13 ms (upper bound ~0.20) | Yes (these tasks can never have a pid in our namespace) | Medium; wall effect likely smaller (concurrent CPU) |
| 4 | Remaining userspace processing cost | up to ~1.4 ms | unknown | Uncertain (no mechanism isolated) |
| 5 | SQLite store | up to ~1.1 ms | persisting evidence is required; only tuning is possible | Uncertain |
| 6 | fork child upid walk / exec record size (1,104 B) | ≤ ~0.1 ms each | uncertain | Low |
| — | fork/exec/exit bookkeeping, workspace open `d_path`, read/write dedup | 0 in this workload | **not avoidable here**: every one of the 300 processes touches the workspace | — |

## Which hypotheses the measurements support

| Hypothesis | Verdict |
|---|---|
| Unconditional fork bookkeeping | **Not supported** as the target. 0.29 ms kernel, and every process here is workspace-relevant, so deferral would save nothing on this benchmark. |
| Unconditional exec bookkeeping | **Kernel side not supported** (0.25 ms). The userspace exec callback (108 µs/event) matters through its `realpath`. |
| Namespace translation | Minor: ~0.53 ms (18% of BPF), of which WSL `init` ≈ 0.2 ms. |
| Path construction / workspace filtering | Kernel `bpf_d_path` minor (0.26 ms). **Userspace path canonicalization is supported: the largest avoidable cost measured.** |
| BPF hash-map activity | The largest kernel component (~1.2 ms, ~40% of BPF). The open-time LRU delete is the costliest single map operation. |
| File-permission / read-write hooks | 30% of BPF time, but necessary (actual read/write evidence). |
| Ring-buffer emission | ~0.7 ms, ~23% of BPF. |
| **Another measured source** | **Yes: userspace event processing interferes with the workload (≈ 45–50%), and the SQLite store (≈ 10–15%).** |

## Correctness finding (new regression tests)

`_resolve()` canonicalized every rename, unlink and exec name with `os.path.realpath`, which follows
a **final-component symlink**. `rename(2)` and `unlink(2)` act on the link itself. Two new tests
fail on the unmodified code:

- `test_rename_destination_symlink_is_not_followed`: after renaming a symlink to `y`, whyfs recorded the destination as `target.txt`.
- `test_unlink_of_symlink_records_the_link`: whyfs recorded the unlink of `link` as an unlink of `target.txt`.

Two further tests pin the behavior that must be preserved:

- `test_rename_through_symlinked_directory_is_canonical`: directory components still follow symlinks.
- `test_exec_through_symlink_records_the_target`: exec follows its final symlink.

## Decision: the one next optimization

**Target: userspace name resolution for rename, unlink and exec events. Replace the per-event
`realpath()` walk with resolution against the already-canonical base.** The cwd model and directory
file paths come from kernel `d_path` or earlier canonicalization, so they are already canonical.

- **Rename/unlink:** join the base and the name without touching the filesystem when the name is a single component. If the name contains `/` or `..`, canonicalize only its parent and never follow the final component.
- **Exec:** same join, plus one `lstat` of the final component. Full `realpath` only if that component is a symlink.

Why this target:

- It is the largest measured *avoidable* cost: ≈ 2.5 ms per run (CI 1.91..4.07), directly measured by phase X.
- It is correctness-positive (fixes the symlink bug above) and removes no evidence.
- It is independently testable.
- It is larger than the kernel candidates combined (≤ ~0.5 ms), which are also below the wall-clock noise floor.

**Honest expectation:** removing about 2.5 ms of ~7–11 ms would bring the static ×300 overhead from
about 5.5–8% to roughly 3.5–6%. That alone may **not** secure < 5% in two independent campaigns.
The remaining about 1.4 ms of unexplained processing cost and the ~1.1 ms store cost would be the
next measured candidates.

## Not concluded (inconclusive or unmeasured)

- Per-hook wall-clock ablations (all seven 90% CIs span zero).
- The mechanism of the remaining ~1.4 ms of userspace processing cost.
- Whether WSL `init`'s foreign invocations delay the workload at all, since they run on another CPU.
- Whether BCC/runtime machinery contributes. Dispatch is ~0 and `bpf_stats` agrees with the body-ablation total, so there is no evidence it matters. A CO-RE/libbpf prototype is not justified by these data.
