# whyfs on Windows

Status: **Windows x64 — COMPLETE (validated natively).**  Windows ARM64 — built and packaged
from the same sources; native runtime validation pending (see
[PLATFORM_VALIDATION.md](PLATFORM_VALIDATION.md)).

## How it works

| Piece | What it is |
|---|---|
| `whyfs.exe` | launcher on the system PATH; runs the private runtime `runtime\python.exe -B -m whyfs` |
| `whyfs-svc.exe` | the `whyfs` service (LocalSystem, auto-start).  Named pipe `\\.\pipe\whyfs-service`, SDDL: SYSTEM and Administrators full, authenticated users read/write.  Impersonates each client, checks that the client owns the workspace, refuses reparse points, canonicalizes with `GetFinalPathNameByHandle`, and starts one collector per workspace.  Only the user who started a collection (or an administrator) may stop it.  Orphaned `whyfs-*` ETW sessions are cleaned up. |
| `whyfs-collect-win.exe` | the native ETW collector.  Two real-time sessions, each with its own `ProcessTrace` thread, merged in timestamp order: (A) Microsoft-Windows-Kernel-File (keywords 0x1FB0, in-kernel event-ID filter 11,12,13,14,15,16,22,26,27,30) plus Kernel-Process; (B) the system logger (process start with command line and user SID, DCStart rundown; VAMAP for memory-mapped files).  Writes the canonical schema v1 into `<workspace>\.whyfs\whyfs.db` with `System32\winsqlite3.dll`, impersonating the requesting user. |

Normal users never need administrator rights after installation: `whyfs init`, `whyfs daemon
start|stop|status`, `whyfs why|impact|history` all run unelevated; the service does the
privileged ETW work on their behalf and writes only into workspaces they own.

### Windows-specific semantics (all documented in [SCHEMA.md](SCHEMA.md))

* **Paths compare case-insensitively** (NTFS semantics, ASCII folding like SQLite `NOCASE`).
* **No `open` events.**  Windows reports creates for every probe (attribute queries, failed
  opens); only actual reads, writes, maps, renames and deletes are evidence.
* **Memory-mapped files** (`etw:mmap`): the MSVC linker reads objects and writes its output by
  mapping them; mapped writes are bounded by the process end.
* **Foreign file objects**: an I/O counts only in the process that created the file object or
  one of its descendants (handle duplication across unrelated processes is rejected and
  counted as `foreign_file_object`).
* **Shared inputs**: `cl.exe` compiles every source of one command line in one process
  (reading all sources first); outputs of such a batch are labelled `shared` instead of being
  given false one-to-one lineage.  `/MP` children are exact.
* **Command lines** are the raw Windows command line (cmd.exe and PowerShell parse their own
  line), with secret values replaced by `<redacted>` (see *Privacy*).

## Validation record (x64, frozen)

Frozen at commit **43e69dd**.  Every gate below ran against these exact binaries (hashes of the tested
MSI and of the files it installed):

```
629f60d33c329f7f5f338fb88625a8cc2fef955f2adb35a2cff6388a4fd23896  whyfs-0.9.0.dev1-x64.msi
747f0d024ff768db6a6608e8417656958eefd4b29c7d14ee3b0fc245c4f44d34  whyfs-collect-win.exe (x64)
87ea955b2a562bf9a92cee3081bc9be838497e0ef4ab7c63191f3c74bd190a78  whyfs-svc.exe (x64)
1c77c0d6d982e4a6fb94062893e8873824ca323e688a34f0adfdd57c6f96b055  whyfs.exe (x64 launcher)
```

Machine: Windows 11 Home 10.0.26200, Intel Core i5-14400F, 32 GB, Defender real-time
protection **on** (never disabled for any measurement).  Toolchain: MSVC Build Tools 2022,
Windows SDK 10.0.26100.  Runtime bundled in the MSI: CPython 3.13.5.

| Gate | Result | Evidence |
|---|---|---|
| Unit / model / query tests (Windows) | 53 tests OK (10 Linux-only skipped), incl. native-collector redaction parity | `python -m unittest discover -s tests` |
| Functional fixture gate: native exe, PowerShell, Python, Node/Vite, MSVC (batch, `/MP`, incremental), rename/move, delete/recreate, parent/child, reopen, 16 parallel writers, case-insensitive query, outside-workspace scoping, mmap, secret redaction, foreign file objects | **23/23 PASS** | `results/win-gate-func-final2/` |
| Creator attribution | **64/64 = 100%** (gate ≥ 99%) | same |
| Useful-input recall | **142/142 = 100%** (gate ≥ 95%); 0 unlabelled false inputs | same |
| Event loss | **0** ETW buffers/events lost, 0 queue drops, 0 unresolved users, 0 late records in every run | all gates |
| Shared A–H corpus | **79/79**, lost 0 | `results/corpus-win-final/` |
| Live secret-redaction gate (cmd /c, `set … &&`, PowerShell `-Command` with `$env:`, plain argv) | **22/22**: no secret in why/history/impact (human or JSON), the DB, WAL, service logs or the report; wrapper lines stored with values redacted | `results/secret-gate-win/` |
| MSI clean install → standard-user flow → uninstall | **20/20** | `results/msi-test-4/` |
| MSI major upgrade, downgrade refusal, data retention | **16/16** (0.9.0 → 0.9.1; older MSI refused with 1603; workspace history kept) | `results/msi-upgrade-4/` |
| `whyfs why` end-to-end CLI latency | **83 ms median** at 97,636 stored events (gate < 100 ms); in-process query 1.2 ms median | `results/win-gate-3/` |

### Performance

Each workload runs in counterbalanced pairs (AB/BA order alternating), with a symmetric
warm-up and a fixed 1 s pause before every build.  Overhead is the median of per-pair
differences with a bootstrap CI.  Negative medians are reported as "no measurable slowdown",
never as a speedup.

| Workload | Pairs | Paired median overhead | CI (90%) | Lost |
|---|---|---|---|---|
| **MSVC, 240 units, `/MP8` + link (authoritative native-build result)** | 30 | **+3.43%** | +1.31% … +4.50% | 0 |
| MSVC, 240 units (gate run) | 20 | +2.90% | — | 0 |
| Vite production build | 20 | +0.20% | — | 0 |
| Native executable ×300 | 20 | −0.02% (no measurable slowdown) | — | 0 |
| MSVC, 36 units (small) | 30 | +2.09% | −1.57% … +7.71% | 0 |

**The small-MSVC bimodality.**  Early runs of the 36-unit build flipped between ~0.30 s and
~0.45 s.  A 30-run characterization *without whyfs* (`results/msvc-characterization/`)
reproduced the same two modes.  The split is in the link phase and tracks Windows Defender
real-time scanning of freshly written objects after short idle gaps; it exists with whyfs
off.  In the counterbalanced paired analysis (`results/msvc-paired/`) both conditions ran 0
of 30 fast-mode builds.  The small workload is too noisy for a precise percentage claim:
its CI straddles zero and does not exclude +5%, but it shows no evidence of a ≥5% cost.  The
stable heavy build above is the authoritative result.  Earlier protocols are preserved as
evidence of what went wrong: `win-gate-1` (asymmetric warm-up, −36%, invalid) and
`win-gate-2` (still bimodal).

The redaction fix of 2026-09-26 does not touch the measured hot path.  It runs once per
process start (about 4 µs for a 1.7 KB command line in the C collector, measured), inside
the collector, and never on the file-I/O path.  So the performance campaign was not
repeated.

### Privacy

* Command lines: the argv pass (switch followed by value, `key=value`) plus a command-text
  pass over the raw line that finds secrets argv parsing cannot isolate: `cmd /c ""tool"
  --password x API_KEY=y"`, `set "ACCESS_TOKEN=x" && …`, `powershell -Command "$env:API_KEY='x';
  … -Token y -Password:z"`, `Authorization: Bearer x`.  One policy with three
  implementations, `whyfs/redact.py`, `whyfs-collect.c` and `whyfs-collect-win.c`, all
  tested against the shared vectors in `tests/redaction_vectors.json`.
* Only processes that touch the workspace, and their bounded ancestors, are stored.  Files
  outside the workspace and temp roots are never stored.  Each store is written as the
  requesting user.

### Installer policy

* Per-machine MSI.  Installs to `%ProgramFiles%\whyfs`, which standard users cannot write.
  Adds the directory to the machine PATH, registers and starts the service, and bundles a
  private, isolated Python runtime (`._pth`, no site-packages, no environment influence).
* **Upgrade**: a major upgrade removes the older product completely before installing
  (`RemoveExistingProducts` right after `InstallValidate`).  Downgrades are refused.
* **Uninstall** removes the service, files, PATH entry and ETW sessions.  **User data policy:
  workspace stores (`<workspace>\.whyfs`) belong to their users and are never removed** by
  uninstall or upgrade.  Delete that directory to remove a workspace's history.
