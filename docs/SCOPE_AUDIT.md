# Workspace-scoping audit (before machine-wide labeling)

Audited on 2026-09-27 at commit 1b16d48, before any machine-wide change.  This describes
exactly where whyfs 0.9 limits what it records.

## 1. What the kernel / ETW layer captures

Neither collector is scoped in the kernel.  Both see the whole machine.

**Linux** (BPF programs in `ebpf_bcc.py`, loaded by BCC):

| Hook | Captured | Scope in kernel |
|---|---|---|
| `security_file_open` (fentry) | every successful open of a **regular file or directory** by any process, with the kernel-resolved absolute path (`bpf_d_path`), `f_flags`, inode low 32 bits | only non-regular, non-directory files skipped; processes outside the collector's PID namespace skipped |
| `security_file_permission` | first read and first write per (struct file, inode, tgid), deduplicated in the `io_seen` LRU map | regular files only |
| `security_mmap_file` | file-backed mmap (read; shared writable = write) | regular files only |
| `do_renameat2`, `do_unlinkat` (fentry/fexit) | successful rename/unlink, with raw names and dirfd files | none |
| `sys_enter/exit_chdir`, `fchdir` | cwd changes | none |
| `sched_process_exec` | exec: filename + first 511 bytes of argv | none |
| `sched_process_fork` (raw) | new thread groups (threads skipped) | none |
| `sched_process_exit` | leader exit | none |

**Windows** (`whyfs-collect-win.c`): two real-time sessions.
- Kernel-File (keywords 0x1FB0, in-kernel event-ID filter
  11,12,13,14,15,16,22,26,27,30) plus Kernel-Process.
- The system logger with PROCESS (command line, user SID, rundown) and VAMAP (mapped files).

Every file Create, read, write, cleanup, close, rename, delete and map on the machine
arrives, from every user.

**So unrelated host activity is observed, then dropped in user space.**  Nothing is lost to
the kernel filter that a machine-wide mode needs.

## 2. What is discarded before the store (user space)

| Stage | Linux (`whyfs-collect.c` = `ebpf_bcc._process_event`) | Windows (`whyfs-collect-win.c`) |
|---|---|---|
| **Path scope** | `within_ws(path)`: under `--root` (the workspace), never under `<workspace>/.whyfs`.  `--capture-all` makes every path in scope except the state dir | `in_ws()`: identical rule, case-insensitive |
| **Temp roots** | paths under `--temp-root`s (`/tmp`, `$TMPDIR`) are kept only as *derived temporaries*: a write by a process that read a workspace file, then later reads of that temp | same (`%TEMP%`, `%TMP%`) |
| **User scope** | none: a root daemon records every user's processes that touch the workspace | `user_ok()`: only processes whose SID equals the requesting user (`--user-sid`); others counted as `other_user`; unknown-user evidence held up to 10 s, then counted `user_unresolved` |
| **Opens** | every in-scope open is persisted as an `open` event (no read/write bits) | never persisted (Windows logs failed probes as Creates) |
| **Foreign file objects** | n/a (struct file identity) | I/O on a FileObject not created by the process or an ancestor is rejected (`foreign_file_object`) |
| **State dir** | `<workspace>/.whyfs` is never evidence | same |

## 3. Which processes become "relevant"

A process becomes relevant on its first persisted file event (`make_relevant`).  Its
process row, the rows of up to **8 ancestors** (`MAX_ANCESTORS`), and their held exec
records are then persisted.  Processes that never touch an in-scope file are never stored.
Command lines are redacted before storage (`redact.py` rules).

## 4. Which files are persisted, and how records are keyed

- `events` rows: `(run_id, ts_ns, pid = per-run process key, kind, path, path2, is_read,
  is_write, flags, api, os_pid)`.
- `processes` rows: `(run_id, pid key, ppid, parent_key, exe, cwd, command, os_pid,
  first_seen_ns)`.
- **Keying is by path string only.**  There is no file identity (inode / file ID).  A rename
  links old and new paths through the `rename` event.  `why` follows rename chains back to the
  last content writer (`_content_origin`).  A file recreated at the same path by an
  unobserved writer would be answered with the old record.
- Neither `processes` nor `events` has a user column.  The user is implied by who owns the
  workspace store.

## 5. How workspace initialization affects collection

- `whyfs init` creates `<dir>/.whyfs/whyfs.db`, one store per workspace.
- **Linux:** `sudo whyfs daemon start --workspace DIR` (or the `whyfs@DIR` systemd template
  unit) starts one collector per workspace with `--root DIR`.  The store is written by a
  privilege-separated child running as the workspace owner.
- **Windows:** the `whyfs` service starts one ETW collector per `whyfs daemon start`
  request.  The request comes from the workspace owner; the collector runs with
  `--root DIR --user-sid <requester>` and writes as that user.
- Queries (`why`, `impact`, `history`) find the store by walking up from the file to the
  nearest `.whyfs` directory (`cli.project_root`).
- **A file outside every initialized workspace, or created while no collector ran for its
  workspace, has no provenance.**  That is the failure mode the product must remove:
  "whyfs doesn't know because you forgot to initialize that directory."

## 6. What a machine-wide mode must change (and must keep)

- **Keep:** the kernel/ETW capture, the event model, redaction, derived temporaries, the
  foreign-file-object guard, loss accounting, and the query semantics.
- **Replace the path predicate:** "under the workspace root" becomes "not excluded by the
  scope policy": system and application-internal churn excluded; everything else in scope,
  wherever it is.
- **Replace the store location:** one machine store, written by the privileged collector,
  never user-writable.  Per-user visibility is enforced when the store is read.
- **Add** a user on every process row, file identity on I/O events, agent sessions, a local
  query/registration service, and retention.
