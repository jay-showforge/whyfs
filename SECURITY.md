# Security and privacy

WhyFS observes process and file **metadata** machine-wide.  That is what makes it useful, and it
is also why that metadata can be sensitive.  This document describes what is recorded, who can
see it, and how WhyFS protects it.

## Reporting a vulnerability

Please report security issues privately to **licensing@tenzorpipe.org** (subject: "WhyFS
security").  Do not open a public issue.  Include the version (`whyfs --version`), the platform,
and a reproduction if possible.

## What is recorded

- **Recorded:**
  - which processes created, wrote, read, renamed, mapped and deleted which files;
  - process trees and executables;
  - command lines, with secrets redacted;
  - users;
  - file identity: inode/device/generation, NTFS file ID;
  - agent sessions, with any task text they supply (redacted).
- **Never recorded:** file contents, clipboard, keystrokes, network traffic, screen contents.
- **What gets a label** is decided by a scope policy.  User files anywhere are labelled; OS
  internals, application caches, browser profiles and the collector itself are not
  (`whyfs status --scope`).  Administrators can add rules in `scope.conf`, excluding paths or
  programs.
- **Only relevant processes are stored.**  A process's row and command line are written only
  when it (or a descendant) produced stored file evidence, plus a bounded chain of ancestors.
- **Temporary files** (`/tmp`, `%TEMP%`) are recorded only when they carry data from labelled
  files into other labelled files.  On Linux they are written to the store only once that
  bridge is complete.

## Where it is stored, and who can read it

- **One machine store.**
  - Linux: `/var/lib/whyfs/machine`, root-owned `0700`.
  - Windows: `%ProgramData%\whyfs\machine`, a protected DACL of SYSTEM and Administrators only.

  No user can read the store directly, and no user can forge its records.
- **Queries go through the local API.**  The OS identifies the requester, never the request
  itself: `SO_PEERCRED` on the Unix socket, impersonation of the named-pipe client on Windows.
  - A normal user sees only the evidence of their own processes, enforced by views that shadow
    every table.  Another account's file reads as having no record.
  - root, or an *elevated* administrator, sees everything.
- **No squatting.**
  - Linux: the socket lives in a root-owned directory.
  - Windows: the service creates the pipe first (`FILE_FLAG_FIRST_PIPE_INSTANCE`) with an
    explicit DACL.  Clients refuse a pipe that is not owned by SYSTEM or Administrators.
- **The WhyFS window** is a per-user process bound to `127.0.0.1`.  It is not a service and not
  reachable from the network:
  - it opens only with a one-time launch token (60 s), read from a user-private state file;
  - the token sets an `HttpOnly; SameSite=Strict` cookie;
  - every request needs the cookie, the `X-Whyfs` header and the exact `127.0.0.1:<port>`
    Host;
  - only read-only operations are forwarded, as the user who opened it;
  - recorded text is rendered as text, never as HTML;
  - a content security policy blocks everything but the page itself;
  - it exits when idle.

  Details: [docs/HUMAN_INTERFACE.md](docs/HUMAN_INTERFACE.md#security-of-the-window).
- **No network.**  WhyFS makes no outbound connections: no cloud, no telemetry, no update
  checks.

## Secrets on command lines

Secret values are redacted **before storage**, identically on Linux and Windows:
- switch values: `--token x`, `/password:x`, `-Password x`;
- `KEY=value` with a sensitive key;
- the same forms inside shell wrappers: `sh -c '…'`, `cmd /c "…"`, PowerShell `-Command`,
  `$env:KEY=…`;
- `Authorization:` header text.

The reference implementation is `src/whyfs/redact.py`.  Both native collectors are tested
against its shared vectors (`tests/redaction_vectors.json`).  `scripts/secret_gate.py` checks
live that no secret reaches the store, the logs or any output.  Agent task text passes the same
redaction.

Redaction is defence in depth, not a guarantee: programs can put secrets in unusual forms.
Prefer environment variables, files or platform secret stores over command-line arguments.

## Agents

- **Registration.**  An agent session is accepted only for a root process owned by the
  requesting user, and is bound to that process instance's start time, so a reused PID cannot
  inherit it.
- **Detection.**  Detected agents are recognised only from their installed program layout and
  command line, never from a file name.
- **Intent.**  Task text is stored as agent-supplied context: it is never verified, and it is
  shown as such.

## The collector and the service

- **Linux.**
  - `whyfs.service` runs as root.  The eBPF programs are loaded by BCC.
  - A native collector drains the ring buffer.  It refuses to run a binary that is writable by
    others or does not match its recorded source hash.
  - Store writes happen in a separate writer process.
- **Windows.**
  - The `whyfs` service runs as LocalSystem from `%ProgramFiles%\whyfs`, which standard users
    cannot write.  It supervises the machine collector and the API.
  - Explicit workspace captures are served impersonating the client, only for workspaces the
    client owns, and reparse points are refused.
- **Observation integrity.**  Downtime, crashes and lost events are recorded, never hidden
  ([docs/MACHINE_MODE.md](docs/MACHINE_MODE.md#observation-integrity)).
- **Collection only.**  The capture path never executes workload commands.  It observes kernel
  events and persists metadata.

## Retention and deletion

- **Retention** defaults to 365 days for creation records and 30 days for pure reads, under a
  2 GiB cap.  Configure it with `retention_days`, `weak_retention_days` and `max_db_mb`.
- **`whyfs forget PATH | --everything`** deletes records: a user's own, or anyone's for an
  administrator.
- **Uninstalling.**  On Linux, `apt purge` deletes the store.  On Windows, delete
  `%ProgramData%\whyfs` after uninstalling.
- **Explicit workspace captures** (`whyfs init`) keep their own store in `<workspace>/.whyfs`.
  - It is created `0700`, with the database `0600`.
  - Keep it out of shared or synced folders; `whyfs init` adds it to `.gitignore`.

## Known gaps

- **Unrecorded operations.**  Metadata-only operations (`chmod`, `chown`, `utimes`, `link`,
  `symlink`, `truncate` without a write) are not recorded.
- **Files already open** when the collector starts have no open event.  I/O on them is not
  attributed; it is counted, never guessed.
- **Long paths.**  Linux paths over 512 bytes are counted, not stored.
- **Kernel requirements.**  Linux needs BTF and fentry support (`whyfs doctor`).  On WSL2 the
  kernel headers come from the in-kernel `kheaders` module.
