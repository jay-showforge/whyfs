# Architecture

WhyFS has four layers:

1. **Observe:** a native collector in the OS event stream.
2. **Record:** a local evidence store.
3. **Explain:** queries that turn evidence into a provenance label.
4. **Present:** interfaces for people, agents and scripts.

Files are never modified.  File contents are never read.

```text
 OS kernel events                                   people            agents / tools      power users
 (Linux eBPF, Windows ETW)                          Explorer / Files  local API           CLI
        │                                           right-click,      (JSON over Unix     whyfs label/why/
        ▼                                           WhyFS window      socket / named      search/impact
 native collector ──► scope policy ──► evidence ──► query layer ◄─────pipe, per-user)────┘
 (per event, C)       (what gets a     store        (label, impact,         ▲
        ▲             label)           (SQLite,     observation,            │
        │                              schema v2)   search)          whyfs service (root / SYSTEM):
 machine service: starts with the OS, restarts after a crash,       collector supervision, API,
 heartbeat, retention                                                retention, visibility
```

## Observe

| | Linux (x86-64, ARM64, WSL2) | Windows (x64, ARM64) |
|---|---|---|
| Kernel source | eBPF programs on BTF fentry / LSM hooks and process tracepoints (BCC loads them; a native C collector drains the ring buffer and writes the store) | ETW: Microsoft-Windows-Kernel-File and Kernel-Process, plus the system logger (process start with command line and user SID, image maps, rundown) |
| Evidence | exec / fork / exit with user and command line; open (with the file's inode, device and generation); actual reads and writes; mmap; rename; unlink | process start and end; Create (no open evidence: Windows logs probes too); read, write, mapped views; rename; delete; the NTFS file ID at first write and at rename |
| Service | `whyfs.service` (systemd, enabled at install) runs `whyfs machine run` as root | the `whyfs` service (LocalSystem, auto-start, restart on failure) supervises `runtime\python.exe -m whyfs machine serve` |

Both collectors apply the same **scope policy**: component-wise path rules, `~` meaning every
home, `exclude-image` for programs.  A shared C matcher is tested against
`tests/scope_vectors.json`.  The policy decides which files get a label:
- everything users work with;
- not OS internals, caches, browser profiles or the collector itself;
- temporaries only when they carry data into real files.

Out-of-scope events are cut at the source.  On Windows that happens inside the ETW callback,
so the idle cost is near zero.  Command lines pass one redaction policy (`whyfs/redact.py` and
both collectors, shared vectors) before storage.

## Record

A single SQLite store, schema v2 ([SCHEMA.md](SCHEMA.md)):
- Linux: `/var/lib/whyfs/machine`, root-only.
- Windows: `%ProgramData%\whyfs\machine`, SYSTEM and Administrators only.

It holds:
- `runs`: collector sessions, with a heartbeat and a clean or unclean end;
- `processes`: tree, image, command line, user and start time;
- `events`: path, kind, read/write, file identity;
- `agent_sessions`;
- `collector_stats`: loss counters per run.

**Retention** keeps creation records for 365 days and pure reads for 30 days, under a 2 GiB cap,
pruned hourly.  `whyfs forget` deletes records.  An explicit `whyfs init` workspace store with
the same schema remains available for isolated captures (CI, tests).

## Explain

`whyfs/label.py` builds the canonical label (`whyfs-label/1`) from the evidence:
- **creator**: the process that last wrote the bytes, following renames back to the writer;
- **process chain** and **user**;
- **inputs**: files the creator read before writing, with system and loaded code hidden;
- **temporaries bridged**: data carried into the file through temporary files;
- **history**;
- **dependents**, **impact** and **observation** (below);
- **agent session**:
  - *registered*: an agent registered its session and its root process was verified;
  - *detected*: a known agent's program image and command line;
- **intent**: only the task text an agent session supplied.

**Identity rule.**  A record is attached to the file now at the path only when the recorded
identity (inode/device/generation or NTFS file ID) matches.  A new file at a reused path gets
`not-observed`, never the old record.

**Impact** is observed only.  It lists:
- files generated from this one;
- files written later by long-running programs that read it ("possibly affected");
- programs that read it.

It never says a file is safe to remove.

**Observation integrity** ([MACHINE_MODE.md](MACHINE_MODE.md#observation-integrity)):
- heartbeats and unclean-run closure turn downtime into recorded gaps;
- per-run loss counters record lost events;
- a label separates origin completeness from later gaps;
- a file that appeared while nothing was recording gets no creator.

## Present

- **People.**
  - Explorer (Windows): **WhyFS** in the right-click menu, as plain shell verbs running the
    console-less `whyfsw.exe`, plus a Start menu entry.
  - Linux file managers: Files, Dolphin and Nemo, plus an application-menu entry.
  - Both open the **WhyFS window**: a per-user, read-only page on `127.0.0.1` with a one-time
    launch token that searches the index and shows labels
    ([HUMAN_INTERFACE.md](HUMAN_INTERFACE.md)).
- **Agents.**  The local API `whyfs-api/1`: one JSON request and reply per line over
  `/run/whyfs/api.sock` (peer credentials) or `\\.\pipe\whyfs-api` (client token)
  ([AGENT_PROTOCOL.md](AGENT_PROTOCOL.md)).  Each requester sees only its own processes'
  evidence; root and elevated administrators see all.
- **Power users.**  The CLI: `whyfs label | why | history | impact | search | recent | status |
  forget | agent | api | ui`.  It prints the same JSON with `--json`.

All three read the same records through the same query code.  The product gate checks that the
window, the API and the CLI return the same label.
