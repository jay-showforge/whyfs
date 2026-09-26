# Security and privacy

whyfs observes process/file metadata. That is useful precisely because it can also be sensitive.

## Defaults

- provenance remains local in `.whyfs/whyfs.db`; nothing is uploaded
- no file contents are captured, by either backend
- workspace-only path evidence by default
- `--all-files` is explicit opt-in
- common secret-looking command-line values are redacted before storage
- the state directory is created `0700` and the database `0600` (SQLite gives its `-wal`/`-shm` files the same mode)

## eBPF backend privileges

The v0.2 BCC backend loads kernel programs and therefore runs as root (`sudo whyfs daemon start`). Treat that as a real security boundary. v0.2 limits what the root process does in the user-controlled workspace:

- **Privilege-separated store.** When the daemon is root and the workspace belongs to another user, all SQLite access runs in a forked child that has permanently dropped to the workspace owner's uid/gid (`setgroups([])`, `setgid`, `setuid`, verified). The root side only sends batches over a pipe and reads back integers. It never unpickles anything from the unprivileged side, and never opens the database itself. A planted `whyfs.db` symlink can therefore at most redirect writes the workspace owner could already make.
- **No-follow state files.** `daemon.json` and `daemon.log` are opened relative to an `O_NOFOLLOW` directory fd, with `O_NOFOLLOW` on the final component. They are replaced atomically with `renameat` and created `0600`, owned by the workspace owner. Hard-linked state files are refused.
- **Symlinked state is refused.** A `.whyfs` that is a symlink, or a symlinked `whyfs.db`, `-wal`, `-shm` or `-journal`, is rejected with an error rather than followed.
- **Root-created state is adopted safely.** If an earlier root run left a root-owned `.whyfs`, the daemon hands the directory and its regular, singly-linked files to the workspace owner. It never follows or chowns symlinks.
- **Non-root queries work.** The workspace owner runs `whyfs why`/`impact`/`history` without `sudo` against a daemon-written database.

The capture path never executes recovery or arbitrary workload commands. It observes kernel events and persists metadata only.

## What the eBPF backend sees vs. what it stores

The kernel sees every process in the daemon's PID namespace, which is broader than `LD_PRELOAD`, which only ever saw the traced command tree. v0.2 was audited for this difference:

| Evidence | preload (v0.1) | eBPF (v0.2) |
|---|---|---|
| file contents | never | never |
| file paths | workspace only (default) | workspace only (default), plus *derived temporaries* (below) |
| process rows / command lines | traced tree only | **only** processes that produced stored evidence, plus at most 8 ancestors for parentage |
| exec boundaries (`exec` events: pid + executable path) | n/a | same relevance rule as process rows |
| unrelated host activity | invisible | held in bounded memory, then discarded; never written |

Details:

- **Process relevance.** Fork/exec metadata for every process is held in a bounded in-memory map. A process row (redacted command line, executable, cwd) and its buffered exec boundaries are persisted only when that process first produces a stored file event. At that point its ancestor chain, capped at 8, is persisted so parentage works (for example `make → cc → cc1`). Processes that exit without touching the workspace are never written. This is covered by regression tests (`ProcessPrivacyTests`).
- **Derived temporaries.** A path outside the workspace is stored only if it was written by a process that had already read workspace files. Later reads of that path are also stored. This is how `cc1 → /tmp/ccXXXX.s → as` lineage is bridged. These are temp-file *names*, not contents.
- **Kernel path strings.** Paths come from the kernel (`bpf_d_path`, rename/unlink name strings) and are resolved in-kernel where possible. Paths longer than 512 bytes, or ones the kernel cannot render, are counted as `truncated_paths`/`unreadable_paths`, never guessed.
- **Command lines** are read from the exec'd process's argument area (up to 511 bytes) and pass through the same redaction as v0.1 before storage.

## Command-line secrets

Redaction is defense-in-depth, not a guarantee. Applications can place secrets in unusual argument formats or paths. Prefer environment variables, file descriptors, or platform secret stores over command-line arguments for secrets.

## Raw evidence

Human-view noise suppression never deletes raw evidence (`whyfs why FILE --raw` shows it). This improves auditability, but it means the database can reveal filenames and process relationships even when the default CLI hides them. Keep `.whyfs/` out of shared or synced folders; `whyfs init` adds it to an existing `.gitignore`.

## Known gaps

- Metadata-only operations (`chmod`, `chown`, `utimes`, `link`, `symlink`, `truncate` without a write) are not recorded.
- Files already open before the daemon starts have no open event, so I/O on them is not attributed; it is counted as filtered, never guessed.
- Paths over 512 bytes are counted, not stored.
- Kernel support: needs BTF and fentry (`BPF.support_kfunc()`). On WSL2 the kernel headers come from the in-kernel `kheaders` module, which the daemon loads with `modprobe kheaders` when root; `whyfs doctor` reports it.
