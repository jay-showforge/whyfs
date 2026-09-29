# Platform validation

WhyFS 1.0 supports exactly: **Windows x64, Windows ARM64, Linux x86-64, Linux ARM64, WSL2.**
macOS is not supported (a future/community target).

A platform counts as supported only with **native runtime evidence**: the package installs
from a clean state, the collector runs on that CPU and kernel, the shared corpus and the
product gate pass, nothing is lost silently, secrets are redacted, observation gaps are
recorded, the package upgrades and uninstalls cleanly, and performance is measured on that
machine.  Cross-compilation, PE/ELF header checks and emulation are supporting evidence only.

## Support matrix (frozen for 1.0)

| Platform | Status | Native environment |
|---|---|---|
| Windows x64 | **Supported.**  Real workloads < 5 %.  Spawn stress ×300 against the historical total-< 5 % rule: hosted runner +4.17 to +6.48 % with identical code (the observation floor alone up to +5.90 %); dedicated desktop −0.70 %.  Judged by the 1.0 contract ([BENCHMARK.md](../BENCHMARK.md#whyfs-10-performance-contract)) | GitHub `windows-2022`: AMD EPYC 7763 (1 core), Windows Server 2022 10.0.20348.  Also a Windows 11 desktop (i5-14400F, Defender on) |
| Windows ARM64 | **Supported** | GitHub `windows-11-arm`: Azure Cobalt 100 (2 cores), Windows 11 Enterprise 10.0.26200 |
| Linux x86-64 | **Supported** | GitHub `ubuntu-24.04`: kernel 6.17.0-1022-azure.  Also WSL2 (kernel 6.6.87.2) |
| Linux ARM64 | **Supported** | GitHub `ubuntu-24.04-arm`: kernel 6.17.0-1022-azure, aarch64 |
| WSL2 | **Supported** | covered by the Linux x86-64 package and gates, with systemd running `whyfs.service` |
| macOS | **Not in 1.0.0.  In development** (branch `macos-support`): every executed gate passes on GitHub-hosted Intel and Apple Silicon Macs, which run with SIP disabled; a standard Mac needs Apple's Endpoint Security entitlement (BLOCKED_EXTERNAL).  [docs/MACOS.md](MACOS.md) and [the macOS section](#macos-development-branch-macos-support) | GitHub `macos-15-intel` (x86_64), `macos-15`, `macos-14`, `macos-26` (arm64) |

Linux requires a kernel with BTF, BPF trampolines (fentry) and the BPF ring buffer
(Ubuntu 24.04's kernels have all three; `whyfs doctor` checks).

## Current state (commit 57d60e4)

**Verified:**
- **The label-history fix (d2d7984)** passed its scoped validation on all four native hosted
  runners ([run 36500071218](https://github.com/jay-showforge/whyfs/actions/runs/36500071218), commit 57d60e4).  That includes native **Windows ARM64**
  (`windows-11-arm`, Cobalt 100) and native **Linux ARM64** (`ubuntu-24.04-arm`, aarch64).
  - Every functional, product, observation, corpus, secret, package and upgrade gate passed.
  - Windows ARM64 `label` is 77.1–84.5 ms median from 1 to 5,000 generations; the limit is
    100 ms.
  - Details: [BENCHMARK.md section 10](../BENCHMARK.md#10-the-label-history-fix-d2d7984-and-its-scoped-native-validation----pass).
- **WSL2 (local):** the same commit's package upgraded in place, with suites, product, outage,
  corpus and long-history gates all passing (`results/wsl2-d2d7984/`).
- **The dedicated Windows x64 desktop:**
  - The d2d7984 query code passed the outage, corpus, secret and long-history gates
    (`results/desktop-d2d7984/`).
  - Its product gate was 46/47.  The one failure (`P.store_free_of_secrets`) is this desktop's
    non-fresh store: it holds the command lines of earlier `grep … SECRETVAL` evidence scans.
    No secret passed redaction.
- **Performance of real workloads and spawn stress:** run 36462972085 (71bee51, the same
  capture code).

**Not re-run, by design:** the capture and performance campaigns, for a query-side change.

**Observed:** with the WhyFS service running, WSL2's 6.6 kernel hung the live eBPF unit tests
in `bpf_trampoline_get` (`results/wsl2-hang-evidence.txt`).  CI runs them before the service
is installed, and so does the WSL2 rerun; both pass.

## Final artifact check ([run 36510467027](https://github.com/jay-showforge/whyfs/actions/runs/36510467027), release commit f6c6010): **PASS**

This run is **not a product qualification**.  f6c6010 changes only LICENSE (the Change Date)
and documentation relative to 57d60e4.  Product qualification remains
[run 36500071218](https://github.com/jay-showforge/whyfs/actions/runs/36500071218) and the runs cited above.

The final packages embed LICENSE, so they were rebuilt from f6c6010 and the existing
`release-validation.yml` was run on them unchanged, on the four native hosted runners.

| Platform | Tests | Package | Product | Outage | Secret | Corpora | Functional | Label gate |
|---|---|---|---|---|---|---|---|---|
| Windows x64 (`windows-2022`) | 116 OK | MSI 32/32, upgrade 16/16 | 47/47 | 16/16 | 22/22 | 79/79 ×2, lost 0 | PASS | PASS |
| Windows ARM64 (`windows-11-arm`) | 116 OK | MSI 32/32, upgrade 16/16 | 47/47 | 16/16 | 22/22 | 79/79 ×2, lost 0 | PASS | PASS |
| Linux x86-64 (`ubuntu-24.04`) | 254 + 254 OK | `.deb` 24/24 | 48/48 | 13/13 | 22/22 | 79/79 ×2, lost 0 | — | PASS |
| Linux ARM64 (`ubuntu-24.04-arm`) | 254 + 254 OK | `.deb` 24/24 | 48/48 | 13/13 | 22/22 | 79/79 ×2, lost 0 | — | PASS |

- **Embedded LICENSE check:** PASS for all four packages
  ([RELEASE_ARTIFACTS.md](RELEASE_ARTIFACTS.md)).
- **Normal CI on f6c6010:** `test.yml`, run 36510466786, PASS.
- **Evidence:** `results/release-final-f6c6010/`.

## Authoritative run 36462972085 (commit 71bee51, 150 pairs, measurability rule): **FAIL on one check**

`results/release-1.0.0-meas/`.  Details in
[BENCHMARK.md section 9](../BENCHMARK.md#9-the-authoritative-run-under-the-measurability-rule-run-36462972085-commit-71bee51----fail-windows-arm64-label-cli-latency).
- **Every functional gate** passed on all four platforms.
- **Every real workload** was measurable and PASSED.  Windows ARM64 MSVC: **+1.72 %** (CI90
  0.91..2.66).
- **The spawn stress contract** passed on all four platforms.
- **Failed:** Windows ARM64 `label` CLI median **108.8 ms** (< 100 ms required).  `label`'s cost
  grows with the queried file's own history.  The 150-pair campaign rebuilt its query targets
  hundreds of times; on Windows x64 `label` rose from 66–72 to 93.1 ms.
- Not released; no artifact approved.

## Measurability rule for real workloads (frozen before the next authoritative run)

A real-workload result is judged against 5 % only when its CI90 can resolve the threshold:
PASS, FAIL or **UNMEASURABLE ON THIS RUNNER** (never a pass).  Every real workload now runs
150 pairs on every platform.  The rule and the sample count come only from the historical
measurements ([BENCHMARK.md section 8](../BENCHMARK.md#8-measurability-of-real-workload-results-frozen-before-the-next-authoritative-run)).
Windows ARM64 MSVC was never resolvable at 20 pairs: CI90 7.4–14 pp wide in all 8 hosted runs.
The run below stays recorded as a failure under the contract that was frozen for it.

## Authoritative release-candidate run 36449450012 (commit 80dabe3): **FAIL on one contract check**

Judged by the 1.0 contract, frozen in 80dabe3 before the run
([BENCHMARK.md, section 7](../BENCHMARK.md#7-the-authoritative-run-under-the-contract-run-36449450012-commit-80dabe3----fail-contract-a-windows-arm64)).
`results/release-1.0.0-final/`.
- **Every functional gate** passed on all four platforms.
- **Contract B (spawn stress)** passed on all four:
  - zero loss;
  - 300/300 stress outputs correct;
  - WhyFS CPU inside its ceiling;
  - WhyFS's own share not above the bound.
- **Contract A (real workloads < 5 %)** passed on Windows x64, Linux x86-64 and Linux ARM64.  It
  **failed on Windows ARM64: MSVC +5.18 %** (CI90 1.44..12.36).  The same code measured +1.01 %
  and +0.72 % in the two previous runs, and that runner's baseline alone moves by up to 30 %
  within a run.
- **The historical total-< 5 % spawn rule** was met on Windows x64 (−0.07 %), Windows ARM64 and
  Linux x86-64, and not met on Linux ARM64 (+5.10 %).
- Not released; no artifact approved ([RELEASE_ARTIFACTS.md](RELEASE_ARTIFACTS.md)).

## 1.0 performance methodology (read this first)

The performance record below is complete, including every failed run.  WhyFS 1.0 judges
performance by the contract in [BENCHMARK.md](../BENCHMARK.md#whyfs-10-performance-contract):

- **A. Real development workloads** must stay below **5 % median total overhead**: MSVC and Vite
  on Windows, `make -j8` and Vite on Linux.  Idle CPU, zero loss and CLI latency also apply.
  This is unchanged.
- **B. The process-spawn stress test ×300** is always run and always reported: the total (the
  historical pre-1.0 rule, total < 5 %), the observation floor, WhyFS's own share, CPU, I/O and
  loss.  It passes on:
  - zero loss;
  - correctness under stress (300/300 outputs labelled);
  - WhyFS's own share not shown to exceed 3.0 pp;
  - WhyFS CPU within 1.5 × the frozen implementation.

Why the methodology changed:
- On the hosted Windows x64 runner, the required kernel events alone have cost up to +5.90 %.
  Identical code measured +4.17 % and +6.48 % in total.
- On the dedicated development desktop, the original unchanged campaign passes: spawn ×300
  −0.70 %, CI90 −1.67..+0.27.  There the floor is about +1.2 % and WhyFS's own share cannot be
  distinguished from zero (`results/desktop-1.0.0/`).

### Dedicated desktop (Phase 1 evidence)

| | |
|---|---|
| Machine | Intel Core i5-14400F, 10 cores / 16 threads, Windows 11 Home 10.0.26200, Defender real-time protection on; WSL and Docker Desktop stopped for the measurement |
| WhyFS | the exact release-candidate MSI `whyfs-1.0.0-x64.msi` (run 36395424116, sha256 7801f421…; collector sha256 84909d59…), `whyfs 1.0.0`, product code of ec52053 |
| Original unchanged campaign (20 pairs) | **PASS**: spawn ×300 −0.70 % (−1.67..+0.27), MSVC −0.35 %, Vite −0.54 %; idle 0.72 % of a core (this desktop's own in-scope activity), 131 MB; CLI 71 / 85 ms; lost 0 |
| Decomposition (20 pairs per variant, two sessions in opposite order) | floor +1.23 / +1.25 %; total +0.59 / +1.48 %; WhyFS-controlled −0.64 pp (−2.28..+1.07) / +0.23 pp (−2.03..+2.48) |
| WhyFS CPU per measured run | 36–37 ms: merge 17–18, writer 7–9, Kernel-File consumer 8.5, system-logger consumer 2.5–3, service 0.1 |
| Correctness under stress | 300/300 outputs labelled with `copy.exe`, complete, identity matching |

## Final release run 36395424116 (commit 37f7e7a, the release candidate): **FAIL** under the historical rule

`results/release-1.0.0-rc2/`.  Release candidate 37f7e7a has product code byte-identical to
ec52053 (run 7).  Every functional gate passed on all four platforms:
- tests: Windows 108 + 108, Linux 246 + 246 per platform;
- MSI 32/32 and upgrade 16/16 on both Windows architectures, `.deb` 24/24 on both Linux
  architectures;
- product 47/47 and 48/48, outage 16/16 and 13/13;
- all corpora 79/79 with lost 0, secret 22/22, functional and graduation PASS.

Two performance checks failed:

| Platform | Failing workload | Result | Same code earlier |
|---|---|---|---|
| Windows x64 | `native_exe_x300` | **+6.48 %** (CI90 4.97..7.48) | +4.17 % (3.83..4.53) in run 7 |
| Linux x86-64 | `static_binary_x300` (Linux code unchanged since graduation) | **+5.50 %** (CI90 3.58..6.74) | +3.19 to +4.06 % in runs 5–7 |

- **All other workloads passed:** Windows x64 MSVC +1.42 %, Vite +2.41 %, CLI 67 / 70 ms; Linux
  x86-64 make -j8 +1.37 %; Windows ARM64 and Linux ARM64 passed every check.
- Events lost: 0 on all four platforms.
- The raw Windows x64 spawn pairs were −0.58, −0.37, 1.71, 2.32, 2.39, 3.69, 4.97, 6.07, 6.29,
  6.39, 6.56, 6.60, 7.06, 7.48, 7.60, 7.78, 8.94, 8.95, 13.74 and 15.29 %.

### The floor

The service-mode diagnostics measured the cost of the required kernel events alone: every
event source on, nothing processed or stored in user space (`discard`).

| Diagnostic run (hosted `windows-2022`, 1 core / 2 logical processors) | Kernel floor (discard) | CI90 |
|---|---|---|
| 36383973618, 10 pairs | +4.30 % | 2.66..5.23 |
| 36385436978, 20 pairs | **+5.90 %** | 3.12..7.79 |
| 36389288157, 20 pairs, machine_perf timing | +3.25 % | 2.42..4.12 |
| 36391352936, 20 pairs, machine_perf timing | +3.75 % | 3.40..4.58 |

The same runs split the floor by source:
- about 1 % remains without Kernel-File;
- about 3.1 % without VAMAP;
- about 3.25 % without the system logger's process and VAMAP flags.

The user-space share on top of the floor is now about 0.7 % (it was ~1.35 %).  So:
- **User space cannot close the gap.**  Even at zero user-space cost, the required events alone
  have measured above 5 % on a hosted runner.  Identical code measured +4.17 % and +6.48 % on
  two runners.
- **Getting below the floor would remove evidence.**
  - Kernel-File: Create, Cleanup, Close and QueryInformation track file objects and learn file
    keys, and Read and Write are the I/O evidence itself.
  - The system logger: process start and end, and mapped views.
  - The manifest ties Cleanup, Close and QueryInformation to the FILEIO keyword, so they
    cannot be enabled more narrowly.  The unmap events cannot be separated from the map events.
  - Removing any of these loses file identity, I/O attribution, or the MSVC linker's mapped
    reads and writes.
- **The threshold stays.**  It was not changed, the workload and protocol were not changed, and
  the run was not repeated.

## Windows x64 process-spawn performance: measured and reduced (run 36391350371, commit ec52053)

The earlier release run (below) failed one check: Windows x64 `native_exe_x300`, +5.16 %
against < 5 %.  This section records how the remaining cost was measured, what was changed,
and the unchanged authoritative campaign that followed.

### Where the cost was (service mode, x64 runner, raw data in `results/native-ci/diag-service-*`)

`scripts/diag_service_cost.py` runs machine_perf's unchanged workload and pairing against the
installed service.  Around every measured run it records precise OS counters:
- idle-processor cycles;
- per-process and per-collector-thread cycles and context switches;
- I/O operations and bytes.

It compares three service variants:
- **normal:** the product.
- **no_write:** everything except the SQLite writes (`WHYFS_DIAG_NO_WRITE`).
- **discard:** events delivered and counted, nothing processed (`WHYFS_DIAG_DISCARD`).

The runner has one core with two logical processors.

| Variant, machine_perf timing, 20 pairs | Median overhead | CI90 | Collector CPU during the measured run |
|---|---|---|---|
| discard: the **kernel floor** (required event generation only) | +3.25 % | 2.42..4.12 | 1 ms |
| no_write | +3.78 % | 3.14..4.50 | 16 ms |
| normal, before | +4.60 % | 2.89..6.89 | 20 ms (bimodal: 5 ms, or 20–43 ms when the previous run's deferred processing overlaps) |
| normal, after (ec52053) | +4.46 % | — | 14 ms (the same runner's floor was +3.75 %) |

- **The kernel floor.** With nothing processed in user space, the enabled event sources cost
  +3.25 to +3.75 % depending on the runner.  Kernel-File is the largest source; turning it off
  leaves about +1 %.
- **Event volume per `copy.exe` (clean runner, `results/native-ci/diag-profile/`).**
  - Kernel-File:
    - about 13 Create, 15 QueryInformation, 13 Cleanup and 14 Close events, mostly from the
      loader opening DLLs;
    - a few reads and writes.
  - System logger: about 22 mapped-view and 22 unmap events.
  - Every one of these is required.  Their keywords come from the provider manifest:
    - Cleanup, Close and QueryInformation exist only under the FILEIO keyword;
    - Create and the file-object map track every I/O;
    - QueryInformation is how a file's key is learned before its first mapped view;
    - mapped views are the MSVC linker's reads and writes;
    - the unmap events cannot be separated from them.
- **User space was the reducible share (~1.35 % before).**  The store writer was the larger
  part.  For 300 processes it wrote 2,530 I/O operations (6.3 MB) and read 810 pages, and every
  one of those I/Os is also a kernel file event.  First-write file identity added one
  open-query-close per file.  Classifying the same OS paths again on every Create was the rest.
- **Process records were not the cost.**  In this workload every process writes a labelled
  file, so each process record is required provenance.  Deferring process persistence would
  have nothing to defer.

### What was changed (commit ec52053; semantics unchanged)

1. **Store writer:**
   - Change: a 16 MB page cache and a 4000-page checkpoint interval.
   - Why: the rows of 300 spawns touch about 900 scattered index pages (paths, file IDs, PIDs).
     With a 2 MB cache and a 1000-page checkpoint they were re-read and re-copied repeatedly.
   - Benchmark against the real schema: write operations −14 %, reads −76 %, writer CPU −20 %.
   - Durability is unchanged (WAL, synchronous=NORMAL).
2. **File identity at first write:**
   - Change: `NtQueryInformationByName(FileStatInformation)` replaces open + FileIdInfo +
     close on NTFS drive-letter paths.
   - Cost: 6.4 against 16.7 µs per file.
   - The identity string is identical.  This was verified for regular files, directories, a
     missing file, a symlink (its own ID, never the target's: like
     `FILE_FLAG_OPEN_REPARSE_POINT`, the query does not follow a final reparse point) and UNC
     (through the handle fallback).
   - `FileIdentityTests` checks this on every build (`--file-id-check`).
3. **Kernel-File consumer:**
   - Change: raw NT paths already classified out of scope are memoized.
   - Bounded to 4,096 entries and verified against the stored path.
   - Paths with an 8.3 `~` are never memoized.
   - Safe because the classification depends only on the path, the scope rules and the device
     map, all fixed for the collector's lifetime.

### The unchanged authoritative campaign on ec52053 (`results/native-ci/run7/`)

The same `native-validation` workflow, the same `machine_perf.py` (workload, 300 processes,
20 counterbalanced pairs, pauses, threshold).

| Platform | Functional gates | Performance |
|---|---|---|
| Windows x64 | tests 108 OK; MSI 32/32; upgrade 16/16; product 47/47; outage 16/16; corpora 79/79 + 79/79, lost 0; secret 22/22; functional 23/23; decoding 0 mismatches | **spawn ×300 +4.17 % (CI90 3.83..4.53)**; MSVC +1.15 % (0.96..1.56); Vite +2.86 % (2.69..3.73); idle 0.003 % of a core, 47 MB; lost 0; CLI 65 / 67 ms |
| Windows ARM64 | tests 108 OK; MSI 32/32; upgrade 16/16; product 47/47; outage 16/16; corpora 79/79 + 79/79; secret 22/22; functional 23/23 | spawn −10.66 % (−14.92..−0.37: a noisy runner); MSVC +1.01 %; Vite +0.95 %; idle 0.10 %; lost 0; CLI 77 / 80 ms |
| Linux x86-64 | tests 246 + 246 OK; `.deb` 24/24; product 48/48; outage 13/13; corpora 79/79 + 79/79; secret 22/22; graduation PASS | static ×300 +4.00 % (2.81..4.67); make -j8 +2.80 %; Vite −0.22 %; idle 0.10 %; lost 0; CLI 26 / 28 ms |
| Linux ARM64 | tests 246 + 246 OK; `.deb` 24/24; product 48/48; outage 13/13; corpora 79/79 + 79/79; secret 22/22; graduation PASS | static ×300 +3.91 % (3.06..5.91); make -j8 +1.55 %; Vite −0.83 %; idle 0.11 %; lost 0; CLI 23 / 24 ms |

**Margin, stated plainly** (written before the final release run, which then failed; see above).
- The Windows x64 spawn workload now passes with its whole confidence interval below 5 %.
- The kernel floor under it (+3.25 to +3.75 %) is fixed by required evidence.  User space now
  adds about 0.7 %.
- A slower runner can still move the result by several tenths of a percent.
- The Linux code is unchanged by this work.  Linux ARM64's static ×300 interval reaches 5.91 %
  on a median of 3.91 %.

## Earlier release run 36377152638 (commit b5562df): **FAIL on one check** (superseded)

`results/release-1.0.0/`.  The same workflow, on the release commit, building the release
packages.  Every functional gate passes on all four platforms.  One performance check fails:

| Platform | Result |
|---|---|
| Windows x64 | tests 107 OK; MSI 32/32; upgrade 16/16; product 47/47; outage 16/16; corpora 79/79 + 79/79, lost 0; secret 22/22; functional PASS; decoding 0 mismatches.  **Perf FAIL:** process spawn ×300 **+5.16 %** (CI90 +4.72..+6.61; criterion < 5 %).  MSVC +1.53 %, Vite +1.51 %, idle 0.0 %, lost 0, CLI 69 / 72 ms |
| Windows ARM64 | tests **107** OK (the redaction-parity and scope tests now run natively); MSI 32/32; upgrade 16/16; product 47/47; outage 16/16; corpora 79/79 + 79/79; secret 22/22; functional PASS.  Perf PASS: MSVC +3.96 %, Vite +1.07 %, spawn −0.25 %, idle 0.10 %, lost 0, CLI 83 / 83 ms |
| Linux x86-64 | tests 245 + 245 OK; `.deb` 24/24; product 48/48; outage 13/13; corpora 79/79 + 79/79; secret 22/22; graduation PASS.  Perf PASS: make -j8 +4.06 %, Vite +0.25 %, static ×300 +3.19 %, idle 0.13 %, lost 0, CLI 25 / 26 ms |
| Linux ARM64 | tests 245 + 245 OK; `.deb` 24/24; product 48/48; outage 13/13; corpora 79/79 + 79/79; secret 22/22; graduation PASS.  Perf PASS: make -j8 +1.88 %, Vite +0.14 %, static ×300 +3.63 %, idle 0.11 %, lost 0, CLI 24 / 26 ms |

**The Windows x64 process-spawn overhead sits at the 5 % threshold.**  Its product code is
identical to f2b9ca6 (below), which measured +4.54 %.  Across all native runs:
- before the store-writer fix: 4.84, 5.22, 6.52 and 6.57 %;
- after it: 4.54 and 5.16 %.

A cost decomposition on the same runner (`results/native-ci/diag-final/`, standalone
collector, 12 pairs) gives:

| Configuration | Overhead |
|---|---|
| Full processing | +4.20 % |
| Events consumed and discarded | +2.28 % |
| Without the Kernel-File provider | +1.62 % |
| Without mapped-file (VAMAP) events | +3.83 % |

About 2.3 % is kernel-side event generation and delivery, which cannot be removed without
dropping evidence that labels depend on.  The rest is collector processing plus the service
and store.  The threshold was not changed, and the run was not repeated to obtain a passing
sample; the cost was measured and reduced instead (the section above).

## Native evidence: run 36374200705 (commit f2b9ca6)

`.github/workflows/native-validation.yml`, dispatched on the private repository.  Every gate
is a separate step with its own verdict; the architecture of each runner is checked before
anything else.  The downloaded results are in `results/native-ci/run6/`.  The 1.0.0 release
commit changes only documentation and test discovery (the Windows redaction/scope tests now
find the ARM64 collector too).  The release artifacts are built and re-validated by a final
run on that commit; see [RELEASE_ARTIFACTS.md](RELEASE_ARTIFACTS.md).

### Functional gates

| Gate | Windows x64 | Windows ARM64 | Linux x86-64 | Linux ARM64 |
|---|---|---|---|---|
| Test suite | 107 OK (12 skipped) | 105 OK (14 skipped)¹ | 245 OK as root, 245 as a user | 245 OK as root, 245 as a user |
| Process-record decoding self-check (direct vs TDH) | 0 mismatches | 0 mismatches | — | — |
| Clean install of the package (MSI / `.deb`), including labels with no `init`, the Explorer / file-manager entries, the windowless launcher, uninstall | **32/32** | **32/32** | **24/24** | **24/24** |
| MSI major upgrade (0.9.0 → 1.0.0), downgrade refusal, data kept | **16/16** | **16/16** | — | — |
| Product gate: A–H, agents, privacy, observation, and U (the WhyFS window, Explorer verb, search) | **47/47** | **47/47** | **48/48** | **48/48** |
| Observation-integrity (outage) gate | **16/16** | **16/16** | **13/13** | **13/13** |
| Shared corpus through the machine collector (no workspace) | **79/79**, lost 0 | **79/79**, lost 0 | **79/79**, lost 0 | **79/79**, lost 0 |
| Shared corpus through an explicit workspace capture | **79/79**, lost 0 | **79/79**, lost 0 | **79/79**, lost 0 | **79/79**, lost 0 |
| Live secret-redaction gate | **22/22** | **22/22** | **22/22** | **22/22** |
| Functional fixture gate (native exe, PowerShell, Python, Node/Vite, MSVC, mmap, renames, parallel, foreign file objects) | **23/23** PASS | **23/23** PASS | — | — |
| Linux graduation harness | — | — | **46/46** PASS | **46/46** PASS |

¹ In this run the Windows redaction-parity and scope-vector unit tests looked only for the x64
collector and skipped on ARM64.  The ARM64 collector's redaction was verified live by the
secret gate (22/22).  The tests now find the collector for the machine's architecture, and
the release run executed them natively on ARM64 (107 tests).

### Observation integrity

The outage gate forces the scenario that matters (`scripts/outage_gate.py`):
1. **File A** is created while WhyFS is watching.
2. The service is killed.
3. **File B** is created.
4. The service recovers by itself.
5. **File C** is created.

On all four platforms:
- **A** is labelled with complete origin, and lists the outage as a later gap.
- **B** has no creator (nothing is fabricated).  It is marked incomplete, with the recorded gap
  in which it appeared, and the human label explains why.
- **C** is labelled complete after automatic recovery.
- The service starts with the OS, restarts after a crash, and reports the gap in `status`.
- **Windows only:**
  - an explicit workspace capture does not blind the machine collector;
  - an ETW session stopped by another program makes the collector restart;
  - labels resume afterwards.

Reboot survival was tested on WSL2 (`scripts/boot_check.py`, full VM shutdown and boot, 4/4).
Hosted runners cannot be rebooted mid-job.

### Performance (20 counterbalanced pairs; threshold: median paired overhead < 5 %)

| | Windows x64 | Windows ARM64 | Linux x86-64 | Linux ARM64 |
|---|---|---|---|---|
| Idle collector CPU (10 min) | 0.005 % of a core, 48 MB | 0.068 %, 48 MB | 0.122 %, 260 MB | 0.103 %, 271 MB |
| Build workload | MSVC /MP8, 240 units: **+1.76 %** (CI90 +1.44..+1.99) | **+2.55 %** (+1.00..+11.13) | make -j8: **+2.79 %** (+2.33..+3.77) | **+2.21 %** (+1.33..+3.02) |
| Vite build | **+2.11 %** (+1.58..+2.71) | **+2.73 %** (+1.31..+3.58) | **+0.30 %** (−0.28..+0.79) | **+0.07 %** (−1.69..+1.85) |
| Process spawn ×300 (native exe / static binary) | **+4.54 %** (+3.76..+5.91) | **−0.76 %** (−10.49..+2.25) | **+3.68 %** (+3.11..+4.28) | **+4.24 %** (+3.49..+4.87) |
| Events lost | 0 | 0 | 0 | 0 |
| `why` / `label` CLI, median (p95) | 65 / 66 ms (71 / 75) | 88 / 92 ms (106 / 102) | 29 / 31 ms | 23 / 24 ms |
| Store after the whole campaign | 49 MB | 48 MB | 47 MB | 47 MB |

Every perf gate passed in this run; the earlier release run did not (Windows x64 spawn +5.16 %),
which led to the reduction above.
Two margins are small and are stated plainly:
- **Windows x64 process spawn:** the median is 4.54 %, but its CI90 upper bound (5.91 %) is
  above 5 %.
- **Windows ARM64 CLI:** the median is 88–92 ms against the 100 ms criterion; the p95 is over
  100 ms.

The spawn workload is the worst case for any process monitor, at about 4 ms per process on
x64.  Builds, the workloads WhyFS is for, cost 0.1–2.8 % on every platform.

### What the native runs found and fixed (earlier runs of the same workflow)

| Run | Finding | Fix |
|---|---|---|
| 1 | Machine corpus 0/49 after another gate: stopping an explicit workspace capture also stopped the machine collector's ETW sessions, so the collector kept running blind | the service stops machine sessions only at its own start; the collector exits (and is restarted) when a session disappears; 3 outage-gate checks |
| 1 | `whyfs status` wrote a file under `/run/whyfs` | status is read-only |
| 1 | Windows ARM64 MSI: error 1620 | Arm64 packages need Windows Installer schema 500 |
| 2 | Windows 8.3 short paths (`C:\Users\RUNNER~1\…`) in queries and in collector renames | queries expand them; the collector expands paths of files already gone through their longest existing directory |
| 3–4 | Windows per-process collector cost on 1-core runners; the Kernel-Process v4 layout differed from the assumed one (caught by the new self-check) | process records are decoded directly, with layouts learned from TDH and cross-checked |
| 4 | `whyfs agent start --root-pid parent` registered the launcher | the default root is the calling shell |
| 4 | Linux static ×300 +5.23 % | derived temporaries are recorded only when they bridge into a labelled file; scope classification is memoized (collector CPU per exec −75 %) |
| 5 | Windows spawn ×300 +6.57 % / +7.41 %: the store writer committed every ~100 ms handoff separately, rewriting hot index pages into the WAL, during the next workload | group commit (at most once per second); directory-only 8.3 expansion |
| 5 | Windows ARM64 CLI 100.3 ms | the CLI fast path no longer imports the `json` package (byte-identical output, tested) |
| 5 | `whyfs label FILE` crashed when its output was piped on Windows | the fast path reconfigures stdout like the full CLI; product-gate check added |
| release | Windows x64 spawn ×300 +5.16 % on the release commit | measured in service mode: a +3.25 % kernel floor, and user space overlapping the next run; store-writer page cache and checkpoint, handle-free file identity, and an out-of-scope path memo (ec52053): +4.17 %, CI90 3.83..4.53 |

## Emulated ARM64 supplement (supporting evidence only)

Before native runners were authorized, both ARM64 packages were exercised under QEMU TCG on the
x64 host (`results/arm64-qemu-supplemental*`).  That found three real arm64 defects, all fixed
before the native runs:
1. BCC's `support_kfunc()` is hard-coded to x86_64.
2. The collector was group-writable when built with umask 002.
3. Start/stop waits were too short for BPF compilation on slow machines.

No timing claims were made from emulation, and none of it substitutes for the native results
above.

## Reproducing

- **Hosted:** run the `native-validation` workflow (`workflow_dispatch`).
- **Linux (as root, from the source tree; USER is an unprivileged account):**
  ```bash
  env PYTHONPATH=src:tests python3 -m unittest discover -s tests
  bash packaging/linux/build_deb.sh dist
  bash packaging/linux/test_deb.sh dist/whyfs_*_$(dpkg --print-architecture).deb USER results/deb-test
  python3 scripts/product_gate.py --installed --user USER --out results/product-gate
  python3 scripts/outage_gate.py --user USER --out results/outage-gate
  env -u PYTHONPATH python3 scripts/run_corpus.py --installed --machine --user USER --out results/corpus-machine
  python3 scripts/secret_gate.py --user USER --out results/secret-gate
  python3 scripts/machine_perf.py --user USER --out results/machine-perf --pairs 20 --idle-min 10
  python3 scripts/run_corpus.py --user USER --out results/corpus
  python3 scripts/v02_graduation.py --user USER --out results/graduation --pairs 20
  ```
- **Windows (elevated PowerShell for install steps; gates run as a normal user):** see the
  `windows` job of the workflow.  It covers `native\windows\build.ps1`, `make_msi.py`,
  `test_msi.ps1`, `test_msi_upgrade.ps1`, `scripts\product_gate.py`, `scripts\outage_gate.py`,
  `scripts\run_corpus.py`, `scripts\secret_gate.py`, `scripts\win_gate.py` and
  `scripts\machine_perf.py`.
