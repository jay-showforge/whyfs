# Changelog

## 1.0.0 (not yet published)

WhyFS automatically labels files with their provenance: what created them, when, how, which
inputs contributed and, when reliably known, which person or software agent caused the activity.

### Platforms
- Windows x64, Windows ARM64, Linux x86-64, Linux ARM64 and WSL2, each validated natively
  ([docs/PLATFORM_VALIDATION.md](docs/PLATFORM_VALIDATION.md)).
- macOS is not supported (future/community target).

### Automatic, machine-wide labels
- A native collector (Linux eBPF, Windows ETW) runs as an OS service from boot.  No workspace
  needs to be initialized.
- A scope policy decides what gets a label: user files everywhere, not OS internals or caches.
- File identity (inode/device/generation, NTFS file ID) follows renames and moves, and never
  attaches an old record to a new file at a reused path.
- The canonical label (`whyfs-label/1`) covers:
  - creator, process chain, user and inputs, including inputs bridged through temporary files;
  - history, dependents and impact;
  - agent session, and supplied intent only;
  - observation completeness.

### People, agents, power users
- **Explorer:** right-click → WhyFS (Windows); Files, Dolphin and Nemo on Linux; a WhyFS entry in
  the Start or application menu.
- **The WhyFS window:** local, read-only search and labels in the browser, served on `127.0.0.1`
  with a one-time launch token.
- **The local API `whyfs-api/1`** for agents and tools: provenance, inputs, dependents, history,
  search, agent sessions and session registration.
- **The CLI:** `label`, `search`, `why`, `history`, `impact`, `recent`, `status`, `forget`,
  `agent`, `api`, `ui`.

### Agents
- **Registered sessions.**  An agent registers its session; the service verifies the root
  process, and every descendant's files carry the session.  The default root is the calling
  shell (Windows: not the whyfs.exe launcher).
- **Detected agents:** Claude Code, Codex CLI and Gemini CLI, from their install layout and
  command line.
- **Intent** appears only as task text supplied by a session.  WhyFS never infers it.

### Observation integrity
- **Recovery.**  The service starts with the OS and restarts after a crash.
- **Heartbeats.**  Each run writes one every 10 s.  A crashed run is closed at its last
  heartbeat, so downtime is a recorded gap.
- **Loss counters.**  Kernel and userspace loss is counted per run, including evicted deferred
  temporary-bridge records.
- **Labels.**  Origin completeness is kept apart from later gaps.  A file that appeared during a
  gap gets no creator, and its label names the gap.
- **Windows sessions.**  An ETW session stopped by anything else makes the collector exit and
  restart; it never keeps running blind.

### Found and fixed during native validation
- Windows ARM64: the MSI could not be opened (Arm64 needs Windows Installer schema 500).
- Windows: 8.3 short paths (`C:\Users\RUNNER~1\…`).
  - Queries now expand them.
  - The collector expands paths of files that are already gone through their longest existing
    directory.
- Windows: stopping an explicit workspace capture stopped the machine collector's ETW sessions,
  silently.
- Windows: process records are decoded directly instead of through TDH lookups by name.  This
  cut per-process collector cost on small machines.  A self-check requires agreement with TDH.
- Linux: derived temporaries are recorded only when they bridge into a labelled file.  This
  cut collector CPU per short-lived process by about 75%.
- Windows: the store writer committed every ~100 ms handoff separately; it now group-commits
  at most once per second (spawn-heavy workloads on 1-core machines: +6.6 % → +4.5 %).
- Windows: 8.3 expansion asks the file system only for directories, not every new file.
- The `why`/`label` fast path no longer imports the `json` package (Windows ARM64 CLI
  100 → 88 ms), with byte-identical output.
- Windows: `whyfs label FILE` crashed when its output was piped.
- `status` wrote a file as a side effect.
- Label: "created" means since the path last existed; there is no invented working folder.

### Licensing
- Source available under the Business Source License 1.1, with Apache 2.0 as the Change License.
- The Additional Use Grant covers personal non-commercial use and non-commercial educational or
  research use.  Commercial production use requires a commercial license.
- The Change Date is set at first public distribution.

## 0.2.0a1 and earlier

Workspace-scoped capture (`whyfs init`, `whyfs trace`) and the v0.2 always-on Linux
collector.  See [PROJECT_STATUS.md](PROJECT_STATUS.md) for that history.
