# Machine-wide provenance labels: design

**Product.**  Install whyfs once.  From then on, files that are created or changed anywhere a
user works automatically get an external provenance label.  The label records where, when,
how, and what process (and, when reliably known, which AI agent session) caused them.  Files
are never modified.  The label lives in whyfs's own store.

## Components

```
kernel (eBPF) / ETW ── machine collector ── machine store ── local API service ── CLI / agents
                        (scope policy)       (one per host)   (per-user visibility)
                                                    ▲
                                  agent sessions ───┘ (registered or detected)
```

| | Linux | Windows |
|---|---|---|
| Starts with the OS | `whyfs.service` (systemd, enabled by the package) | `whyfs` service (auto-start, installed by the MSI) |
| Collector | `whyfs-collect --machine` | `whyfs-collect-win.exe --machine` |
| Machine store | `/var/lib/whyfs/machine/whyfs.db` (dir root 0700) | `%ProgramData%\whyfs\machine\whyfs.db` (SYSTEM + Administrators only) |
| Local API | Unix socket `/run/whyfs/api.sock` (peer uid via `SO_PEERCRED`) | named pipe `\\.\pipe\whyfs-api` (client SID via impersonation) |
| Config | `/etc/whyfs/config.json`, `/etc/whyfs/scope.conf` | `%ProgramData%\whyfs\config.json`, `scope.conf` |

`whyfs init` and workspace collectors remain available for explicit, isolated captures
(tests, CI).  They are **not** needed for labels.

## Scope policy (what gets a label)

Every regular file on the machine is in scope unless the policy excludes it.  The default
excludes are operating-system and application-internal churn only; location alone never
makes a user file invisible.  Full list: `src/whyfs/scope.py` (reference); the collectors
implement the same rules and are tested against `tests/scope_vectors.json`.

- **Excluded paths (not recorded):**
  - OS trees: `/usr /lib* /bin /sbin /boot /proc /sys /dev /run /snap /var/cache /var/lib
    /var/log /var/spool`, `C:\Windows`, `C:\Program Files*`, `C:\ProgramData`,
    `$Recycle.Bin`, `System Volume Information`.
  - Per-user application caches and state: `~/.cache`, browser profiles, trash,
    `AppData\Local`, `AppData\LocalLow`, `AppData\Roaming\Microsoft`, registry hives.
  - whyfs's own state.
- **Temporary roots** (`/tmp`, `/var/tmp`, `/dev/shm`, `%TEMP%`): recorded only as derived
  temporaries, i.e. written by a process that read an in-scope file.  A temp file moved into
  scope keeps its origin.
- **Excluded processes:** scanners and indexers whose reads are not provenance (Defender
  `MsMpEng.exe`, Windows Search, `tracker-miner-fs`, `baloo`).  Configurable.
- **User additions:** `scope.conf` lines `exclude <pattern>`, `include <pattern>` (include
  wins over a default exclude) and `exclude-image <pattern>`.  A `*` component matches one
  path component, and `~` means every user's home.

## Retention

| Class | Examples | Default |
|---|---|---|
| **Strong** | writes, renames, deletes; the creating process chain; reads by processes that wrote in-scope files (their inputs); agent sessions | kept `retention_days` (365) |
| **Weak** | read-only access by processes that never wrote an in-scope file (pure consumers, e.g. every tool reading `~/.gitconfig`) | kept `weak_retention_days` (30) |
| **Cap** | whole store | `max_db_mb` (2048): past the cap, weak records go oldest first, then strong records oldest first |

Pruning runs hourly in the service.  `whyfs forget` deletes records on request (a user can
delete their own; administrators anything).  `whyfs status` shows scope, size, counts and
the policy in effect.

## Users and privacy

Every process row carries its user (`uid:1000`, or a Windows SID).  The store is readable
only by the service.  Through the API:
- a normal user sees the events of their own processes;
- root / an elevated administrator sees everything.

File contents are never captured.  Command lines are redacted (`redact.py`).

## File identity

A path is not identity.
- **Linux:** each I/O event carries the kernel inode identity `(device, inode, generation)`,
  read from the `struct file` at event time.
- **Windows:** the collector records the volume serial number and 128-bit file ID at a
  file's first write (best effort; a file already renamed or deleted keeps no ID).

At query time the file's current identity is compared with the identity recorded for the
chosen record:
- **match:** the label applies;
- **mismatch:** the current file is a different file that reuses the path.  whyfs reports that
  the file's origin was not observed, and shows the old record only as "previous file at this
  path";
- **identity unknown:** the event sequence decides.  A delete or rename-away after the last
  write, with no later write, means the record is stale.

Records follow renames and same-volume moves through rename events.  On Linux, a hard link
is found through its identity.

## Agent sessions

OS evidence and agent context are stored separately.

- `agent_sessions(session_id, agent_name, agent_version, user, root_os_pid, root_start_ns,
  workspace, task, started_ns, ended_ns, source, confidence, evidence)`
- **Registered** (`source = registered`): an agent calls the local API (`whyfs agent start`,
  or protocol op `session_start`).  The API accepts a root PID only if the caller's user
  owns that process.  A task text is stored exactly as supplied and flagged as
  agent-supplied.
- **Detected** (`source = detected`): a process whose image path *and* command line match a
  known agent layout, for example Claude Code (`…/claude-code/<version>/claude(.exe)` or
  `node …/@anthropic-ai/claude-code/cli.js`) or Codex CLI (`…/@openai/codex/…`).  A file name
  alone never qualifies.
- **Inheritance** is computed at query time from the stored process ancestry: a file's label
  names the nearest ancestor of its creating process that is a session root.  The full
  process chain is always shown; the agent never replaces the creator.
- **Intent** ("why, in terms of a task") is shown only when a registered session supplied
  task text, labelled as supplied by the agent.  Otherwise the label says that no intent
  context was provided.  Intent is never inferred.

## Local API: `whyfs-api/1`

JSON, one request per line; each reply is one JSON object `{"ok": true, "result": …}` or
`{"ok": false, "error": …}`.  Operations:

- **Files:** `get_file_provenance`, `explain_file` (the label), `get_file_history`,
  `get_file_inputs`, `get_file_dependents`, `get_recent_changes`.
- **Agent sessions:** `get_agent_session`, `get_files_by_agent`, `session_start`,
  `session_end`.
- **Service:** `status`, `forget`.

The CLI (`whyfs label|why|history|impact|agent|status`) is a client of the same service.
There is no cloud component, account or telemetry.  See [AGENT_PROTOCOL.md](AGENT_PROTOCOL.md).
