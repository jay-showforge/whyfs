# Platform validation

whyfs 1.0 supports exactly: **Linux x86-64, Linux ARM64, Windows x64, Windows ARM64, WSL2.**
macOS is not in scope for 1.0 (future/community target; contributions welcome).

A platform counts as supported only with **native runtime evidence**: the package installs,
the collector runs on that CPU and kernel, the shared A–H corpus and why/impact/history pass,
nothing is lost silently, secrets are redacted, the package uninstalls cleanly, and
performance is measured.  Cross-compilation, PE/ELF header checks and emulation are
supporting evidence only.

## Status

The product under validation is the machine-labels product frozen at **3dc9266**:
- machine-wide labels with no `init`;
- the local API and agent sessions;
- the WhyFS window with the Explorer / file-manager entries;
- impact and observation gaps.

The earlier workspace-mode records (38aa328, 43e69dd) are kept below, in WINDOWS.md and in
PROJECT_STATUS.md.

| Platform | Status | Evidence on 3dc9266 |
|---|---|---|
| Linux x86-64 | **PASS (native)** | `results/linux-r4/`.  WSL2 kernel 6.6.87.2, Ubuntu 24.04, i5-14400F.  Suites OK (root and user).  `.deb` **24/24** (machine service, label without init, private store, file-manager entries, purge), SHA-256 `08eaebc17ef9037d0f9a325c7c15455e9895e838c695f831eafaf9faa9f1f849`.  Product gate **46/46**.  Machine and workspace corpus **79/79**, lost 0.  Secret gate **22/22**.  Machine perf: idle **0.29 %** of a core; make -j8 −4.3 %, Vite −1.6 %, static ×300 −1.8 % (no measurable slowdown); lost 0; why/label CLI **21/22 ms** |
| WSL2 | **PASS (native)** | the Linux x86-64 evidence above *is* WSL2, with systemd running `whyfs.service` |
| Windows x64 | **PASS (native)**, frozen at `3dc9266` | [WINDOWS.md](WINDOWS.md), `results/win-r5/`.  MSI **32/32**, upgrade **16/16**, product gate **44/44** (incl. Explorer menu and WhyFS window), corpora **79/79**, secret gate **22/22**, functional gate PASS (64/64, 142/142).  Idle **0.068 %** of a core; MSVC +3.40 %, Vite −3.34 %, exe ×300 −0.97 %; lost 0; why/label **82/84 ms** |
| Linux ARM64 | **pending native run** | emulated supplement on 3dc9266 (below); the earlier emulated runs found 3 real arm64 defects, now fixed |
| Windows ARM64 | **pending native run** | ARM64 MSI rebuilt from 3dc9266: `whyfs-0.9.0.dev1-arm64.msi`, SHA-256 `4d47731162fddfa10f8a32dee6693b222f66b59e4afe5e2d7883048c14d35e49`.  All 27 PE images are ARM64 (0xAA64), including the windowless `whyfsw.exe` (subsystem 2) and the CPython 3.13.5 ARM64 runtime.  Never executed |

## Emulated ARM64 supplement (not native evidence)

`results/arm64-qemu-supplemental*`.  Environment: QEMU 8.2 TCG (`-cpu max`, 8 vCPU) on the
x64 host, Ubuntu 24.04 arm64 cloud image, kernel 6.8.0-142-generic.  Timing is meaningless
under emulation, so no performance claim is made, and start/stop waits were raised for the
runs (`WHYFS_START_TIMEOUT`, `WHYFS_STOP_TIMEOUT`).

The emulated runs found three real defects that would have hit native ARM64 users:

1. **whyfs refused to start on arm64 kernels.**  BCC 0.29's `BPF.support_kfunc()` is
   hard-coded to x86_64, although arm64 has BPF trampolines.  Detection now asks the kernel.
2. **The arm64 `.deb` shipped a group-writable collector** when built with umask 002.  whyfs
   correctly refused to trust it.  Package modes are now explicit and tested.
3. **`daemon start`/`stop` waited only 5 s** for BPF compilation and for the final drain.
   Slow machines exceed that.  The default is now 60 s, configurable.

Results on the fixed code (run 3):
- `.deb` 15/15, including the installed-package corpus 79/79 on aarch64;
- source-tree corpus 79/79, lost 0;
- secret gate 22/22;
- user test suite 191 OK;
- the live eBPF module: see `results/arm64-qemu-supplemental-3/live.log`.

Ready artifact: `whyfs_0.9.0~dev1_arm64.deb`, SHA-256
`7218b01b2e19c58d7a70c7a4df251c805da8b3c7913440b611c9194b8659531c`.  It was built natively in
the arm64 guest; its collector is an aarch64 ELF.  This is the package that passed 15/15
above.

These results do **not** replace the native run below.

## What remains, and the exact environment it needs

No native ARM64 machine is available here (the only host is an x64 PC).  Publishing the
repository to use hosted CI is not authorized, so the ARM64 runs below have **not been
performed**.  Everything they need is in this repository and prepared.

### Linux ARM64

**Environment (any one):**
- GitHub Actions `ubuntu-24.04-arm` (Arm-hosted, native Neoverse; Ubuntu 24.04), via
  `.github/workflows/native-validation.yml`, job `linux`; or
- any native arm64 machine or VM on arm64 hardware (Ampere/Graviton cloud instance,
  Raspberry Pi 5 with 8 GB, Apple-silicon Linux VM with hardware virtualization) running
  **Ubuntu 24.04 arm64** with a kernel that has `CONFIG_DEBUG_INFO_BTF=y`, fentry (BPF
  trampoline) support on arm64 and the BPF ring buffer (Ubuntu 24.04's 6.8 kernel has all
  three; the BPF LSM is *not* needed: the programs attach with fentry to the kernel's
  `security_*` functions).  `whyfs doctor` checks this.  Root access is required.

**Commands (as root, from the source tree; USER is an unprivileged account):**
```bash
apt-get install -y bpfcc-tools python3-bpfcc libbpf-dev libsqlite3-dev libelf-dev zlib1g-dev \
  pkg-config gcc make clang nodejs npm rsync file dpkg-dev linux-headers-$(uname -r)
env PYTHONPATH=src:tests python3 -m unittest discover -s tests              # root suite
sudo -u USER env PYTHONPATH=src:tests python3 -m unittest discover -s tests   # user suite
bash packaging/linux/build_deb.sh dist                                        # native arm64 .deb
bash packaging/linux/test_deb.sh dist/whyfs_*_arm64.deb USER results/deb-test
python3 scripts/run_corpus.py --user USER --out results/corpus
python3 scripts/secret_gate.py --user USER --out results/secret-gate
# Vite fixture for the graduation harness: ~USER/vite-template with vite@5.4.21 installed
python3 scripts/v02_graduation.py --user USER --out results/graduation --pairs 20
python3 scripts/v02_gate.py
```

**Pass criteria:**
- all tests OK;
- `deb_test.json` all 1 (install, prebuilt collector used, tamper refusal, installed corpus,
  systemd unit, remove, user data kept);
- corpus 79/79 with lost 0;
- secret gate 22/22;
- graduation verdict PASS: static-binary provenance, make -j8 parallel build, Node/Vite
  (libuv io_uring), rename, attribution ≥ 99%, recall ≥ 95%, zero drops, why < 100 ms,
  and all three workloads < 5% median paired overhead.

Alignment and endianness are exercised by the differential tests (native C collector versus
the Python reference on randomized kernel-ordered streams) and by the corpus through the
ring-buffer layout.

### Windows ARM64

**Environment (any one):**
- GitHub Actions `windows-11-arm` (Arm-hosted, native), via the same workflow, job `windows`;
  or
- a native Windows 11 ARM64 machine (Snapdragon X / Surface Pro 11 / Windows Dev Kit 2023, or
  an Azure Cobalt/Ampere VM) with Visual Studio 2022 Build Tools including the ARM64
  toolset, Node.js, and **Python 3.12 and 3.13 ARM64** (3.12 hosts `msilib` for the MSI
  builder; 3.13 is the runtime bundled into the MSI).  Administrator rights are needed for
  the install tests; the gates run as a normal user.

The ARM64 MSI from `results/windows-arm64-build/ARTIFACTS.md` (check its SHA-256) can be
installed directly: skip the build and `make_msi` steps and run the tests from
`test_msi.ps1` onwards.  To rebuild it on the ARM64 machine itself, `make_msi.py` runs the
bundled runtime directly (no `--build-python` needed).

**Commands (elevated PowerShell, from the source tree):**
```powershell
powershell -ExecutionPolicy Bypass -File native\windows\build.ps1 -Arch arm64 -VsRoot <VS path>
cl /nologo /O2 native\windows\tools\asuser.c /Fe:C:\whyfs-tools\asuser.exe   # in a vcvarsarm64 shell
$env:PYTHONPATH = "src;tests"; python -m unittest discover -s tests
py -3.12 native\windows\make_msi.py --arch arm64 --runtime <Python 3.13 arm64 dir> --vcvars <vcvarsarm64.bat> --out dist
py -3.12 native\windows\make_msi.py --arch arm64 --runtime <...> --vcvars <...> --version 0.9.0.dev0 --out dist-old
powershell -File native\windows\test_msi.ps1 -Msi dist\whyfs-*-arm64.msi -Out results\msi-test -AsUser C:\whyfs-tools\asuser.exe
powershell -File native\windows\test_msi_upgrade.ps1 -Old dist-old\*.msi -New dist\*.msi -Out results\msi-upgrade
msiexec /i dist\whyfs-*-arm64.msi /qn
python scripts\run_corpus.py --out results\corpus
python scripts\secret_gate.py --installed --out results\secret-gate
$env:WHYFS_VCVARS = "<vcvarsarm64.bat>"; $env:WHYFS_VITE_TEMPLATE = "<dir with vite@5.4.21>"
python scripts\win_gate.py --out results\win-gate --pairs 20
```

**Pass criteria:**
- tests OK;
- MSI 20/20 and upgrade 16/16;
- corpus 79/79 with lost 0;
- secret gate 22/22;
- `win_gate` verdict PASS: functional fixture 23/23 (native ARM64 exe, PowerShell, Python,
  Node/Vite, MSVC, rename/move, delete/recreate, parent/child, reopen, parallel,
  case-insensitivity, scoping, mmap, redaction, foreign file objects), attribution ≥ 99%,
  recall ≥ 95%, zero ETW loss, why CLI < 100 ms, and median paired overhead < 5% (or, for a
  workload too noisy to measure, no evidence of ≥ 5% under the counterbalanced paired
  analysis; `scripts/win_msvc_paired.py`).

## After the ARM64 runs

1. Copy each run's `results/` into this repository (`results/arm64-linux-*`,
   `results/arm64-windows-*`) and record machine, kernel/OS build, CPU and commit.
2. If everything passes, the remaining release steps are mechanical:
   - version 1.0.0;
   - the real BSL Change Date in `LICENSE`;
   - final artifacts with SHA-256 sums;
   - clean-install tests from those artifacts;
   - release notes.
3. If an ARM64 run fails, fix it on that hardware and re-run the whole platform gate.  No
   partial credit.
