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
| Windows x64 | **Functional: supported.  Performance gate: FAIL on the release run** (process spawn ×300 +5.16 %, see below) | GitHub `windows-2022`: AMD EPYC 7763 (1 core), Windows Server 2022 10.0.20348.  Also a Windows 11 desktop (i5-14400F, Defender on) |
| Windows ARM64 | **Supported** | GitHub `windows-11-arm`: Azure Cobalt 100 (2 cores), Windows 11 Enterprise 10.0.26200 |
| Linux x86-64 | **Supported** | GitHub `ubuntu-24.04`: kernel 6.17.0-1022-azure.  Also WSL2 (kernel 6.6.87.2) |
| Linux ARM64 | **Supported** | GitHub `ubuntu-24.04-arm`: kernel 6.17.0-1022-azure, aarch64 |
| WSL2 | **Supported** | covered by the Linux x86-64 package and gates, with systemd running `whyfs.service` |
| macOS | **Not supported** | — |

Linux requires a kernel with BTF, BPF trampolines (fentry) and the BPF ring buffer
(Ubuntu 24.04's kernels have all three; `whyfs doctor` checks).

## Release run 36377152638 (commit b5562df, the 1.0.0 release commit): **FAIL on one check**

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
sample.

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

Every perf gate passed in this run; the release run above did not (Windows x64 spawn +5.16 %).
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
