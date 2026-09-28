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

## Observation integrity

**Guarantee.**  If the observer was active and healthy, a label reflects what it observed.  If
the observer was unavailable or evidence was lost, the label says so.

**Starts with the OS.**
- Linux: `whyfs.service` is enabled for `multi-user.target` at install.
- Windows: the `whyfs` service is `AUTO_START`.

No user action is needed after boot.

**Recovers from crashes.**
- Linux: systemd `Restart=on-failure` restarts the service 5 s after a crash.
- Windows: the service manager's recovery actions restart the service after 5 s, then 30 s.
  Inside it, the service restarts its host process, and the host restarts the collector, with
  backoff.

**Records its own downtime.**
- Every collector run writes a heartbeat (`collector_stats.heartbeat_ns`) every 10 s.
- A run that ends cleanly records its end.
- A crashed run never does.  The next run closes it at its last heartbeat and marks it unclean
  (`unclean_end`), so the interval until the next start is a recorded gap.
- A current run whose heartbeat is older than 45 s is reported as not recording.
- `whyfs status` / the `status` API list `recording_gaps` with their times and whether they
  followed a crash.

**Records loss.**
- Kernel-side: BPF ring drops, ETW lost events and buffers.
- Userspace: queue drops, late records, unresolved users.

Both are counted per run.  Loss in the session that created a file makes its origin incomplete;
loss afterwards is a later gap.

**Never fabricates.**  A file that appeared while nothing was observing has no recorded write, so
it gets no creator.  Its label is `no-record`, with `observation.complete: false`.  When its
timestamps fall inside a recorded gap, `observation.file_time_in_gap` names that gap.  Identity
checks keep an older record at the same path from being attached to it.

**Tested.**  `scripts/outage_gate.py` runs the forced-outage scenario on the installed service:
1. create File A;
2. kill the whole observer (Linux: SIGKILL to every process of the unit; Windows: the service
   process tree);
3. create File B while nothing observes;
4. let the OS service manager recover the observer by itself;
5. create File C.

The required outcome: A complete, B unknown with the gap named, C complete, and the gap reported
by `status`.  `scripts/boot_check.py` checks, after a real OS boot, that whyfs is recording with
no user action and that the downtime is a recorded gap (run on WSL2 by shutting down and booting
the VM).  `tests/test_observation.py` covers the query side.

## Human discovery

People reach labels without a terminal.  Right-click a file in Explorer or the Linux file
manager and choose **WhyFS**, or open **WhyFS** from the Start or application menu to search.
Both open the WhyFS window: a per-user page on `127.0.0.1` that asks the service through this
same API, as the user.  See [HUMAN_INTERFACE.md](HUMAN_INTERFACE.md).

Each label also carries:
- `impact`: what removing or changing the file would affect, from observed activity only;
  never "safe to remove";
- `observation`: whether whyfs was watching, without loss, since the file was created.

## Measured cost (native runners, run 36391350371, commit ec52053)

Median paired overhead over 20 counterbalanced pairs (the full table, with confidence
intervals: [PLATFORM_VALIDATION.md](PLATFORM_VALIDATION.md#performance-20-counterbalanced-pairs-threshold-median-paired-overhead--5-)).

| | Windows x64 | Windows ARM64 | Linux x86-64 | Linux ARM64 |
|---|---|---|---|---|
| Idle collector CPU (10 min) | 0.003 % of a core, 47 MB | 0.10 %, 49 MB | 0.10 %, 260 MB¹ | 0.11 %, 271 MB¹ |
| Build | MSVC +1.15 % | MSVC +1.01 % | make -j8 +2.80 % | make -j8 +1.55 % |
| Vite | +2.86 % | +0.95 % | −0.22 % | −0.83 % |
| Process spawn ×300 | +4.17 % | −10.66 % (noisy runner) | +4.00 % | +3.91 % |
| Events lost | 0 | 0 | 0 | 0 |
| `why` / `label` CLI | 65 / 67 ms | 77 / 80 ms | 26 / 28 ms | 23 / 24 ms |
| Store after the campaign | 49 MB | 48 MB | 47 MB | 47 MB |

¹ BCC's Python/LLVM runtime plus the native collector.

Labels appear a few seconds after the activity: the Windows collector orders ETW events in a
5 s window and the store writer commits at most once per second; on Linux the ring buffer is
drained and batched within about a second.

Store growth when idle is small, since idle desktops write few in-scope files.  Growth is
bounded by retention (365 days for strong records, 30 days for pure reads) and by the
`max_db_mb` cap (2048 MB by default); pruning runs hourly.
