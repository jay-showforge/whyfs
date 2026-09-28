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
- **Not supported:** macOS, a future/community target.  Other architectures are not supported.
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

The machine-wide service is measured on every supported platform (PLATFORM_VALIDATION.md):
idle cost, development workloads, event loss and query latency.  Two points apply:
- **Process spawning.**  Workloads that start hundreds of tiny processes per second cost the
  most, because every process start is an event.  On small machines (one or two CPU cores)
  that is where the overhead comes closest to the 5% budget.
- **Query latency** is dominated by process start-up: about 20–30 ms on Linux, 80–90 ms on
  Windows.  The API answers in milliseconds.
