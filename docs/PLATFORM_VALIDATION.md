# Platform validation

whyfs 1.0 supports exactly: **Linux x86-64, Linux ARM64, Windows x64, Windows ARM64, WSL2.**
macOS is not in scope for 1.0 (future/community target; contributions welcome).

A platform counts as supported only with **native runtime evidence**: the package installs,
the collector runs on that CPU and kernel, the shared A–H corpus and why/impact/history pass,
nothing is lost silently, secrets are redacted, the package uninstalls cleanly, and
performance is measured.  Cross-compilation, PE/ELF header checks and emulation are
supporting evidence only.

## Status

| Platform | Status | Evidence |
|---|---|---|
| Linux x86-64 | **PASS (native)** | WSL2 kernel 6.6 on i5-14400F.  Graduation on frozen `04a6287` (`results/v02-graduation-native/`); re-run on the current code: see `results/linux-final-*` |
| WSL2 | **PASS (native)** | the Linux x86-64 evidence above *is* WSL2 (Ubuntu 24.04, kernel 6.6.87.2-microsoft-standard-WSL2), including the `.deb` with the systemd unit |
| Windows x64 | **PASS (native)**, frozen at `43e69dd` | [WINDOWS.md](WINDOWS.md) |
| Linux ARM64 | **pending native run** | builds natively under emulation; supplemental emulated results below |
| Windows ARM64 | **pending native run** | collector, service and launcher cross-build cleanly (MSVC `x64_arm64`, 0 warnings); **ARM64 MSI built** with the signed CPython 3.13.5 ARM64 runtime, all 26 PE images verified ARM64 (`results/windows-arm64-build/ARTIFACTS.md`); never executed |

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
