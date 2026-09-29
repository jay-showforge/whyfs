# Known limitations (WhyFS 1.0)

WhyFS labels what it observes.  These are the boundaries of that observation, and of this
release.  Past defects and their fixes are recorded in [KNOWN_ISSUES.md](KNOWN_ISSUES.md).

## What WhyFS can know

- **Only activity observed while WhyFS was running.**
  - Files that existed before installation, or appeared while the service was down, have no
    recorded origin.  Their label says so (`no-record`), naming the gap when the file's
    timestamps fall inside one; WhyFS never invents a creator.
  - Downtime and event loss are recorded, and labels report them as observation gaps.
- **Process-level lineage.**  WhyFS sees which process read which files and wrote which files.
  It does not see which bytes of an input went into which output:
  - one process that reads several inputs and writes several outputs links them as *shared*
    and says so;
  - a long-running program such as an editor, an AI agent, a browser or an IDE, which reads a
    file and later writes many others, marks those as *possibly affected*, not as dependents.
- **Impact is observed, not analysed.**  "What depends on this file" lists what was observed
  reading it.  A program that has not read it yet, or read it before the observation window,
  is not known.  WhyFS never says that removing a file is safe.
- **Intent is never inferred.**  A task appears only when an agent session supplied one.
- **Agent detection is conservative.**  Claude Code, Codex CLI and Gemini CLI are recognised
  from their installed program layout and command line.  Any other agent must register its
  session (`whyfs agent start`, [AGENT_PROTOCOL.md](AGENT_PROTOCOL.md)); otherwise its files
  carry the real process chain but no agent label.
- **File contents are never read, and no content hashes are kept.**  Identity is the file
  system's own: Linux device/inode/generation, the NTFS file ID.  A copy made by a program
  WhyFS did not observe is a different file.
- **Local file systems.**  Network shares, FUSE and other remote file systems have not been
  validated; identity checks there may report `unknown`.
- **Reads are kept for 30 days by default** (creation records for 365).  After that, older
  uses of a file are no longer known, and labels say so.

## Platforms

- **Supported:** Windows x64, Windows ARM64, Linux x86-64, Linux ARM64 and WSL2
  ([PLATFORM_VALIDATION.md](PLATFORM_VALIDATION.md)).
- **Validated OS builds:** Windows 11 (x64 desktop, ARM64 runner), Windows Server 2022 (x64),
  Ubuntu 24.04 (x86-64, ARM64, WSL2).  Windows 10 and other Linux distributions have not been
  validated separately.
- **Not in 1.0.0:** macOS, in development on the `macos-support` branch ([MACOS.md](MACOS.md)).
  Other architectures are not supported.
  - **Functionally validated** only on GitHub-hosted runners, which have SIP disabled.
  - **Performance FAILED:**
    - Intel `make -j8` is +6.78 %;
    - Apple Silicon process spawn ×300 is +6.29 %;
    - the long-history label gate fails on both architectures, and neither cause is resolved.
  - **A standard Mac needs Apple's Endpoint Security entitlement,** plus Developer ID signing,
    notarization and Full Disk Access. That is externally blocked and not tested.
- **Linux requirements.**
  - A kernel with BTF and BPF trampolines (fentry), 5.x or later as shipped by current
    Ubuntu/Debian.  `whyfs doctor` checks.
  - The eBPF programs are compiled by BCC when the service starts: a few seconds, and about
    250 MB resident for the Python/LLVM runtime.
  - Packaged as `.deb` only.
- **WSL2.**  The Linux package labels Linux-side activity.  Windows-side activity needs the
  Windows installer.  Without `systemd=true` in `/etc/wsl.conf`, start the service with
  `sudo whyfs machine run`.
- **Windows 11 context menu.**  The WhyFS entries are classic shell verbs, listed under **Show
  more options** (Shift+F10).  The compact Windows 11 menu needs a packaged, signed shell
  extension; it is not part of 1.0.
- **The WhyFS window** opens in the default browser on `127.0.0.1`.  A machine without a
  browser, or one that blocks loopback, can use `whyfs label` / `whyfs search` or the API.
- **Reboot validation.**
  - A true OS boot was tested on WSL2: the VM was shut down and booted, and whyfs came up with
    no user action.
  - Hosted CI runners cannot be rebooted.  There, crash recovery was tested with a real kill,
    and auto-start was checked through the service configuration (`AUTO_START`, enabled
    systemd unit).

## Performance

The machine-wide service is measured natively on every supported platform
([PLATFORM_VALIDATION.md](PLATFORM_VALIDATION.md)): idle cost, development workloads, event
loss and query latency, under the 1.0 contract ([BENCHMARK.md](../BENCHMARK.md#whyfs-10-performance-contract)):
- **Process spawning.**  Workloads that start hundreds of tiny processes per second cost the
  most, because every process start is an event.  On a 1-core Windows x64 runner, 300
  back-to-back runs of a small native program cost between +4.17 % and +6.48 % with identical
  code (median of 20 pairs, on two runners).  That is over the historical < 5 % rule in some
  runs.  The kernel generating the file and mapping events that labels require costs +3.25 to
  +5.90 % by itself there.  WhyFS's own share is about 0.7 percentage points.  On a 10-core
  desktop the same workload costs −0.70 % (no measurable overhead).  Linux x86-64 measured
  +5.50 % once; WhyFS's own share there is larger than on Windows (+1.7 to +2.7 pp).  Builds cost 0.1–2.8 % on every platform.
- **Windows ARM64 build overhead needs a large sample on the hosted runner.**  At 20 pairs
  MSVC measured +0.72 to +5.18 % with identical code, and its CI90 was 7–14 pp wide, because
  that runner's own build time moves by up to 30 % within a run.  At 150 pairs it measured
  +1.72 % (CI90 0.91..2.66).
- **Long histories: the label's readers and dependents are the recent ones.**  For a path with
  more than 1,000 recorded events or 50 reader processes, `label` takes readers and dependents from
  its most recent activity, and says so.  `whyfs history FILE --limit 0` and `whyfs impact FILE`
  read everything.  (Until d2d7984, `label` slowed with a file's history: 108.8 ms on the Windows
  ARM64 runner for a file rebuilt hundreds of times; now 77–85 ms up to 5,000 generations.)
- **WSL2: live eBPF tests alongside the running service.**  With the WhyFS service running,
  WSL2's 6.6 kernel hung the test suite's own eBPF attach (`bpf_trampoline_get`).  Run the live
  tests with the service stopped, as CI does.
- **Query latency** is dominated by process start-up: about 25–30 ms on Linux, 65 ms on Windows
  x64, and 88–92 ms median on Windows ARM64 (Cobalt 100), where the 95th percentile exceeds
  100 ms.  The API itself answers in milliseconds.
- **Labels are not instant.**  A new file's label appears a few seconds after it is written:
  the Windows collector orders kernel events in a 5-second window and commits at most once
  per second.

## Distribution

- **The packages are not code-signed.**  Windows SmartScreen may warn before the MSI runs.
  Verify the SHA-256 against the published sums.  Signing is a release-process step, outside
  this validation.
- **No package repository.**  The packages are installed from files: an MSI, or a `.deb` via
  `apt install ./…`; there is no apt repository, winget or PyPI package.
- **Unattended upgrades.**  MSI major upgrade (0.9 → 1.0) is tested.  `.deb` upgrades use
  dpkg's normal replace path; only a clean install, removal and purge are gated.
