# Architecture

whyfs separates **capture**, **evidence storage**, and **human queries**.

## Capture backends

### `preload` — explicit compatibility backend

`whyfs trace -- command ...` injects a small `LD_PRELOAD` shim into dynamically-linked descendants. It is useful for demos, CI, product semantics, and systems where BPF is unavailable.

It is intentionally not described as host-complete. Static binaries and several other execution paths bypass it.

### `ebpf-bcc` — v0.2 always-on alpha

The Linux daemon attaches eBPF programs through BCC to BTF fentry hooks at the VFS/LSM layer, and to process tracepoints:

- `security_file_open`: the path is resolved in the kernel with `bpf_d_path`.
- `security_file_permission`: the first read and first write.
- `security_mmap_file`.
- `do_renameat2` and `do_unlinkat`.
- `sched_process_fork/exec/exit`.

Hooking below the syscall layer covers io_uring, `openat2`, `sendfile`, `splice` and `copy_file_range`; syscall tracepoints miss io_uring entirely. Events are built directly in ring-buffer reservations, which keeps them clear of the 512-byte BPF stack. They are committed without a per-event wakeup: the collector drains on a 50 ms timer, and a wakeup is forced once 1 MiB is pending.

To avoid flooding user space with every `read(2)` call, the BPF side emits only the first observed read and first observed write per `(process, struct file *)` until that file object is reopened. User space maps kernel file objects to paths. That makes fd reuse, dup, redirection and inheritance correct without `/proc` lookups, which are impossible for processes that have already exited. PIDs are translated in the kernel to the daemon's PID namespace (WSL2 runs distros in a nested namespace). Each observed fork gets a per-run process key, so PID reuse cannot merge two processes.

The callback does not write SQLite. It places normalized events on a bounded user-space queue. A single writer thread batches SQLite transactions (512 rows or 100 ms). When the daemon runs as root for a user's workspace, the writer sends batches to a forked child that has dropped to the workspace owner's uid/gid, and only that child touches the database.

Process rows are persisted only for processes that produce stored evidence, plus a bounded chain of ancestors. The kernel sees every process on the host; the store does not keep them.

If either the kernel ring buffer or user-space queue cannot accept evidence, whyfs increments visible drop counters rather than applying backpressure to the application.

## Evidence model

- **run** — explicit trace or daemon lifetime
- **process** — `(run_id, pid)` with parent, executable, cwd and redacted command. Under eBPF, `pid` is a per-run process key, and `os_pid`/`parent_key` hold the kernel pid and parent key.
- **file** — normalized absolute path
- **event** — observed read/write/open/rename/unlink relationship

Observed evidence and human relevance are deliberately separate concepts.

## Query semantics

`why FILE` finds the latest observed writer of `FILE` (following renames back to the original writer). It then lists the file reads that same process made with the same program image (since its last `exec`) before the write. Reads reached through derived temporaries, such as gcc's `/tmp/cc*.s`, are shown as one extra hop. A self-edge caused by opening an output `O_RDWR` is hidden from the human view but remains in raw evidence.

`impact FILE` walks forward from observed readers to files those processes wrote *after* reading, recursively, and follows renames.

`history FILE` lists observed writes and renames over time.

### Important causal limitation

Process-level provenance can over-approximate true data causality for long-lived processes. If a process reads 100 files and later writes one file, raw observation alone cannot prove which subset influenced the output. v0.2 preserves the evidence honestly; v0.3 focuses on relevance/confidence reduction without destroying the raw graph.

## BPF coverage and future CO-RE backend

BCC is used in v0.2-alpha because it keeps the first always-on collector small and inspectable. It is not the final distribution architecture. Once the semantics and event coverage graduate, the intended production backend is a CO-RE/libbpf implementation to avoid requiring a runtime compiler stack on every installation.
