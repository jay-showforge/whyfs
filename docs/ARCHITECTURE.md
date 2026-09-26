# Architecture

whyfs separates **capture**, **evidence storage**, and **human queries**.

## Capture backends

### `preload` — explicit compatibility backend

`whyfs trace -- command ...` injects a small `LD_PRELOAD` shim into dynamically-linked descendants. It is useful for demos, CI, product semantics, and systems where BPF is unavailable.

It is intentionally not described as host-complete. Static binaries and several other execution paths bypass it.

### `ebpf-bcc` — v0.2 always-on alpha

The Linux daemon attaches eBPF programs through BCC to syscall/process tracepoints. The kernel emits compact events to a shared BPF ring buffer.

To avoid flooding user space with every `read(2)` call, the BPF side emits only the first observed read and first observed write per `(process, fd)` direction until close. User space maintains `(tgid, fd) -> canonical path` mappings and falls back to `/proc/<pid>/fd/<fd>` when necessary.

The callback does not write SQLite. It places normalized events on a bounded user-space queue. A single writer thread batches SQLite transactions.

If either the kernel ring buffer or user-space queue cannot accept evidence, whyfs increments visible drop counters rather than applying backpressure to the application.

## Evidence model

- **run** — explicit trace or daemon lifetime
- **process** — `(run_id, pid)` with parent, executable, cwd, redacted command
- **file** — normalized absolute path
- **event** — observed read/write/open/rename/unlink relationship

Observed evidence and human relevance are deliberately separate concepts.

## Query semantics

`why FILE` finds the latest observed writer of `FILE`, then lists file reads observed for that same process before the write. A self-edge caused by opening an output `O_RDWR` is hidden from the human view but remains in raw evidence.

`impact FILE` walks forward from observed readers to files those processes wrote, recursively.

`history FILE` lists observed writes and renames over time.

### Important causal limitation

Process-level provenance can over-approximate true data causality for long-lived processes. If a process reads 100 files and later writes one file, raw observation alone cannot prove which subset influenced the output. v0.2 preserves the evidence honestly; v0.3 focuses on relevance/confidence reduction without destroying the raw graph.

## BPF coverage and future CO-RE backend

BCC is used in v0.2-alpha because it keeps the first always-on collector small and inspectable. It is not the final distribution architecture. Once the semantics and event coverage graduate, the intended production backend is a CO-RE/libbpf implementation to avoid requiring a runtime compiler stack on every installation.
