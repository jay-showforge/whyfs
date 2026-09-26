# whyfs

**Ask your filesystem why a file exists.**

`whyfs` records local process→file provenance and answers three questions:

```bash
whyfs why dist/app
whyfs impact src/parser.c
whyfs history dist/app
```

The goal is deliberately smaller than a security SIEM and more general than a language-specific build graph: preserve the causal file/process evidence the operating system already sees, locally, then make it usable.

> **v0.2 is an alpha.** The proven v0.1 `LD_PRELOAD` backend remains available as `whyfs trace`. v0.2 adds an always-on Linux eBPF/BCC backend and a hard graduation gate, but that kernel backend must be validated on a BPF-capable host before it is called release-ready.

## The experience

Explicit fallback capture works today:

```bash
whyfs init
whyfs trace -- bash -c 'tr a-z A-Z < raw.txt > upper.txt'
whyfs why upper.txt
```

Example:

```text
/path/upper.txt
└── created by /usr/bin/tr  (pid 4217)
    run: bash -c 'tr a-z A-Z < raw.txt > upper.txt'
    evidence: preload
    inputs:
      ├── /path/raw.txt
```

Then:

```bash
whyfs impact raw.txt
```

can follow downstream lineage across later recorded commands.

## v0.2: always-on Linux capture

First check the host:

```bash
whyfs doctor
```

The alpha eBPF backend currently uses BCC. On Debian/Ubuntu/WSL you typically need BCC, Clang, and kernel BPF support (package names vary by distro; commonly `bpfcc-tools` and `python3-bpfcc`). During alpha testing the daemon is normally run with sufficient BPF/perf privileges.

Foreground:

```bash
sudo whyfs daemon run --workspace /path/to/project
```

Background:

```bash
sudo whyfs daemon start --workspace /path/to/project
whyfs daemon status --workspace /path/to/project
sudo whyfs daemon stop --workspace /path/to/project
```

Once the daemon is running, work normally. No `whyfs trace -- ...` wrapper is required.

### Why eBPF matters

`LD_PRELOAD` cannot see everything. It misses statically linked programs, secure-exec/setuid programs, direct syscalls, and some internal libc/runtime paths. The test suite includes a statically linked C program specifically to prove the fallback **does not** claim evidence it never observed.

The v0.2 collector instead observes kernel syscall/process events and sends compact evidence to user space through a BPF ring buffer. User space resolves file descriptors to paths and writes SQLite in batches on a dedicated writer thread.

```text
Linux process/file events
        ↓
      eBPF
        ↓
   BPF ring buffer
        ↓
 userspace resolver
        ↓
 batch SQLite writer
        ↓
 why / impact / history
```

The monitored workload is never synchronously blocked on a SQLite commit. If evidence is dropped because buffers fill, `whyfs` counts and reports the loss instead of silently pretending the graph is complete.

## Raw evidence vs. human view

`whyfs` does **not** delete evidence just because it looks noisy.

The SQLite store retains observed events. The default human view hides common system/runtime reads when full-system capture is enabled. Use:

```bash
whyfs why FILE --all
```

to see the unpruned input view.

This distinction matters: relevance is an interpretation; the underlying observation should remain auditable.

## Privacy defaults

- local-only SQLite database at `.whyfs/whyfs.db`
- workspace paths only by default
- file contents are never captured
- common secret-looking top-level CLI arguments are redacted
- eBPF process command lines use the same redaction policy
- `--all-files` is explicit opt-in

See [SECURITY.md](SECURITY.md).

## What v0.2 records

The alpha eBPF backend currently covers:

- process fork / exec / exit
- successful `openat`
- first observed `read`, `pread64`, `readv` per open fd
- first observed `write`, `pwrite64`, `writev` per open fd
- file-backed `mmap` as read evidence
- successful `rename`, `renameat`, `renameat2`
- successful `unlink`, `unlinkat`

Known coverage work remains (for example `openat2`, descriptor duplication semantics, shared writable mmap, metadata-only mutations, and broader architecture/kernel portability). The project does not claim complete system provenance until those gates are closed.

## Graduation gate

The v0.2 kernel backend does not graduate on a toy echo command.

Run:

```bash
sudo -E python scripts/v02_gate.py
```

The gate uses:

1. a **statically linked C binary** that v0.1 cannot trace,
2. a real parallel multi-file C build,
3. a Node file-build workload,
4. paired build timing with the daemon on/off.

The current hard checks include:

- static-binary creator attribution
- static-binary direct input lineage
- transitive header → object → executable impact on a parallel build
- Node build inputs
- zero kernel ring-buffer drops
- median real-build slowdown below 5%

If the machine cannot load BPF/BCC, the gate returns `BLOCKED_ENVIRONMENT`; it does not silently substitute the preload backend.

## Development

```bash
make test
make demo
```

The unit/integration suite covers the v0.1 end-to-end path, v0.1's static-binary blind spot, v0.2 batched storage, path filtering, file-descriptor resolution, and machine-readable eBPF capability reporting.

## Positioning

`whyfs` is not claiming that file provenance is new.

Research systems such as PASS/CamFlow, security provenance systems, build provenance, data lineage, ReproZip-style execution capture, AgentFS, and language-specific lineage tools all demonstrate parts of the space.

The product bet is narrower:

> make host-observed process→file causality feel like an ordinary filesystem query.

Install it, work normally, then ask **why is this file here?**

## Non-goals

- storing file contents
- replacing Git
- claiming an inferred dependency was directly observed
- uploading provenance to a cloud by default
- hiding dropped-evidence counters

## License

MIT
