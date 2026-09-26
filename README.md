# whyfs

**Ask your filesystem why a file exists.**

`whyfs` records local process→file provenance and answers three questions:

```bash
whyfs why dist/app
whyfs impact src/parser.c
whyfs history dist/app
```

The goal is deliberately smaller than a security SIEM and more general than a language-specific build graph: preserve the causal file/process evidence the operating system already sees, locally, then make it usable.

> **v0.2 is an alpha and has not graduated.** The eBPF backend was validated on a real WSL2 kernel. It passed every lineage, accuracy (100% creator attribution, 100% useful-input recall), zero-drop and query-latency check, and build overhead was 0.4–3.1%. It **failed the <5% overhead target on an exec-heavy loop** (5.6–7.9% in 3 of 4 runs). See [PROJECT_STATUS.md](PROJECT_STATUS.md) and [BENCHMARK.md](BENCHMARK.md). The v0.1 `LD_PRELOAD` backend remains available as `whyfs trace`.

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

The v0.2 collector instead observes the kernel's VFS/LSM layer and process lifecycle. That also covers io_uring, which Node's libuv uses for async file I/O and which syscall tracepoints never see. It sends compact evidence to user space through a BPF ring buffer. The kernel resolves open paths (`bpf_d_path`), and user space maps later reads and writes by kernel file object. SQLite writes are batched on a dedicated writer. Under a root daemon, they run in a child process that has dropped to the workspace owner.

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

The SQLite store retains observed events. The default human view hides system/runtime reads (for example `/usr/lib`, `/etc`) and dependency trees (`node_modules`, `site-packages`), and says how many inputs it hid. Use:

```bash
whyfs why FILE --all      # include system/library reads
whyfs why FILE --raw      # unfiltered inputs plus the creator's raw stored events
whyfs impact FILE --raw   # include system/runtime outputs
```

to see the unpruned view.

This distinction matters: relevance is an interpretation; the underlying observation should remain auditable.

## Privacy defaults

- local-only SQLite database at `.whyfs/whyfs.db`
- workspace paths only by default
- file contents are never captured
- common secret-looking top-level CLI arguments are redacted
- eBPF process command lines use the same redaction policy, and are stored only for processes that touched the workspace (plus up to 8 ancestors)
- a root daemon writes its store as the workspace owner (privilege-separated); symlinked state is refused
- `--all-files` is explicit opt-in

See [SECURITY.md](SECURITY.md).

## What v0.2 records

The eBPF backend needs a kernel with BTF and fentry (BPF trampoline) support; it was validated on 6.6 (WSL2). `whyfs doctor` checks the host. It covers:

- process fork / exec / exit, with PIDs translated to the daemon's PID namespace and per-run process keys that survive PID reuse
- every successful file open (`security_file_open`), whatever the syscall: `open`, `openat`, `openat2`, or io_uring
- the first read and first write of each open file by each process (`security_file_permission`), including through `sendfile`, `splice`, `copy_file_range` and io_uring; fds are resolved by kernel file object, so dup, redirection, inheritance and fd reuse are handled
- file-backed `mmap` (a shared writable mapping counts as a write)
- `rename` and `unlink` in every syscall form (`do_renameat2`, `do_unlinkat`), plus `chdir`/`fchdir` for the cwd model
- exec boundaries: `why` attributes a write to the program image that performed it

Not covered: metadata-only operations (`chmod`, `chown`, `utimes`, `link`, `symlink`, `truncate`), files already open before the daemon started, and paths longer than 512 bytes. Paths the kernel cannot render are counted, never guessed. The project does not claim complete system provenance.

## Graduation gate

Two gates live in `scripts/`, and neither substitutes the preload backend when BPF is unavailable:

```bash
sudo -E python scripts/v02_gate.py                                              # shipped gate
sudo python scripts/v02_graduation.py --user $USER --out results --pairs 10     # full graduation harness
```

The full harness tests:

- a static binary
- a `make -j8` build with parentage, compiler and linker subprocesses, header and source rebuilds, and transitive impact
- a Vite build plus a post-build script
- rename/move chains
- default versus raw query views
- creator attribution (≥99%) and useful-input recall (≥95%)
- zero drops
- `why` latency under 100 ms
- paired, alternating performance runs on three workloads with a <5% median slowdown target

**Current status:** the shipped gate passes. The full harness passes 45 of 46 checks and fails the <5% target on its exec-heavy workload, so v0.2 **does not graduate** (see [PROJECT_STATUS.md](PROJECT_STATUS.md)).

## Development

```bash
make test
make demo
```

The suite has 54 tests. They cover:

- the v0.1 end-to-end path and v0.1's static-binary blind spot
- v0.2 resolver regressions: PID reuse, fd reuse, redirection, renames, exec boundaries and derived temporaries
- privacy, meaning which process rows are persisted
- state-directory hardening
- static checks of the BPF source
- live kernel and daemon tests

The live tests need root and BCC and are skipped otherwise.

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
