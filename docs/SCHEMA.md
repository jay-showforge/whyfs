# whyfs canonical provenance schema (version 1)

Every platform collector writes the same records into the same SQLite store, and
`why`, `impact` and `history` read only these fields. They never see which backend
produced them.

| Collector | Platform | Notes |
|---|---|---|
| eBPF | Linux | |
| ETW | Windows | |
| preload | Linux | explicit `whyfs trace` only |

- **The contract in code:** `src/whyfs/schema.py`. Its `validate_record` runs on every record in the collector test suites.
- **Behavioural parity:** checked by the shared corpus, `tests/corpus` + `scripts/run_corpus.py`.

```
platform-native collector ──► canonical records ──► store (SQLite) ──► query layer ──► why / impact / history
```

## Store

| Table | Row | Key fields |
|---|---|---|
| `runs` | one collection (a daemon session or a traced command) | `id`, `started_ns`, `ended_ns`, `workspace`, `collector` (`ebpf-native`, `ebpf-bcc`, `etw-native`, `preload`) |
| `processes` | one process instance per run | `pid` = per-run **process key**; `os_pid`; `ppid`; `parent_key`; `exe`; `cwd`; `command` (redacted); `first_seen_ns`; `source` |
| `events` | one observation | `ts_ns` (wall clock, ns); `pid` (process key); `os_pid`; `kind`; `path`; `path2`; `is_read`; `is_write`; `flags`; `api` (evidence type); `source` |
| `collector_stats` | final counters of a run | received, filtered, drops, lost, unresolved, … |

**Process identity.** The **process key** identifies a process instance for the length of a run. A reused OS pid never merges two processes.
- Linux: `seq << 22 | pid`, assigned at fork.
- Windows: `seq << 32 | pid`, assigned at process start.

`parent_key` links a process to its parent instance.

## Record kinds

| Kind | Meaning | Fields |
|---|---|---|
| `process` | a process instance and its latest known image | `exe`, `command`, `cwd`, `ppid`, `parent_key` |
| `exec` | a program-image boundary in a process | `path` = the new image |
| `open` | a file was opened; access intent, **not** data flow | `flags` (Linux: open flags; Windows: create disposition) |
| `io` | bytes were read or written | `path`, `read` / `write` |
| `rename` | a move or rename | `path` → `path2` |
| `unlink` | a delete | `path` |

## Evidence types (`api`)

Evidence says *how* something was observed. Weaker evidence is never presented as stronger.

| Class | `api` values | Strength |
|---|---|---|
| observed I/O | `ebpf:rw`, `etw:rw` (+ `:derived-temp`) | data actually read or written |
| mapped I/O | `ebpf:mmap`, `etw:mmap` (+ `:derived-temp`) | a file mapping. A writable shared mapping counts as a write; any other mapping counts as a read. |
| open | `ebpf:open` | access intent only (Linux: successful opens only). **Windows records no opens**: Kernel-File logs a Create when it is issued, so a successful open cannot be told apart from a failed probe (runtimes probing for `*.pdb`). |
| open-only tracer | `source = preload` (`api` = the libc call) | opens with modes, **no** reads or writes. `why` bounds its inputs by the end of the process instead of by the write, and says so via `collector`. |
| rename / delete | `ebpf:rename`, `etw:rename`, `ebpf:unlink`, `etw:delete`, `etw:delete-on-close` | namespace operations (Linux: success checked) |
| image boundary | `ebpf:exec`, `etw:exec` | program image change or process start |

## Shared semantics

These hold on every platform.

- **First read / first write per open.** Each open file reports its first read and its first write per process. Every reopen reports again.
- **Open-file identity.** I/O is attributed through the kernel's open-file object: `struct file` on Linux, the `FileObject` on Windows.
  - On Windows the object is retired at `IRP_MJ_CLOSE`.
  - It is honoured only in the process that opened it, or in a descendant that inherited the handle. In an unrelated process a reused pointer (a pipe, a socket, a failed create) is counted as `foreign_file_object`, never attributed.
- **Mapped writes.** A writable mapping can take data read after the view was created: its inputs are bounded by the end of the writing process's observed activity, not by the map time.
- **Shared inputs.** When a process writes several outputs and file I/O cannot tell which input fed which output, `why` reports `shared_by_outputs` and `impact` marks the edge `shared`. This happens in two cases:
  - it read everything before its first output (one MSVC `cl` compiling several files, a bundler);
  - another output was written in between.

  Such inputs are never presented as exact.
- **Self-produced reads.** A process reading back a file it wrote itself is not consuming an input. That covers MSVC re-reading its objects and a linker's scratch files. Scratch outputs a process deletes itself are hidden in the default view.
- **Workspace scope.** Only paths inside the workspace are stored, plus *derived temporaries*: out-of-workspace temp files written by a process that read workspace data, and later reads of them.
- **State directory.** `<workspace>/.whyfs` is never evidence.
- **Privacy.**
  - A process's command line is stored only if the process, or up to 8 of its descendants, produced stored evidence.
  - Secret-shaped arguments are replaced by `<redacted>`. That covers `--password X`, `/token:X`, `API_KEY=X`, `*secret*`, `*credential*`, `*access_key*`, `*private_key*`, and `Authorization`.
  - File contents are never read.
- **Human view.** The default `why` / `impact` output hides:
  - system and runtime reads;
  - dependency trees;
  - the program's own image;
  - files the process wrote itself before reading them;
  - scratch files it deleted.

  `--all` / `--raw` show the raw evidence.

## Platform semantics (where the OSes differ)

| | Linux (eBPF) | Windows (ETW) | preload tracer |
|---|---|---|---|
| Path comparison | case-sensitive | **case-insensitive** (ASCII folding, SQLite `COLLATE NOCASE`) | case-sensitive |
| Path form | canonical physical path (`d_path`) | drive-letter path; NT device paths mapped; 8.3 short names expanded; UNC as `\\server\share` | as opened |
| Process working directory | yes | **not observable** (`cwd` is NULL) | yes |
| Images per process | many (`exec`) | one (the process start is its `exec`) | one |
| Whose processes are recorded | every process touching the workspace (root daemon) | **only the requesting user's** (the service filters by user SID) | the traced command tree |
| Memory-mapped I/O | yes (`security_mmap_file`) | yes (VAMAP MapFile events; e.g. MSVC `link.exe` inputs and output) | no |
| Async / ring I/O | io_uring (VFS hooks) | I/O rings and overlapped I/O appear as IRPs | no |
| Static binaries | yes | n/a (kernel observation) | **no** |
| Delivery | ordered ring buffer | two ETW sessions merged by timestamp (5 s window); late records counted, never silent | synchronous log |
| Pipes between processes | not linked (file lineage only) | not linked | not linked |

**Loss accounting.** Loss is always counted and stored in `collector_stats`, never hidden:
- kernel drops;
- userspace queue drops;
- ETW events and buffers lost;
- records arriving after the reorder window;
- evidence of processes whose user could not be determined.
