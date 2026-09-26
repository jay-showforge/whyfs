# ETW probe findings (Windows 11 26200, x64, elevated)

Probe: `etw_probe.c`. It launches the workload itself (`workload.ps1`), so the root PID is known, then follows the process tree and dumps the TDH-decoded fields.

The workload covers:
- `cmd` redirection;
- Python read/write;
- Python `mmap`;
- reopening a file;
- `Rename-Item`, `Move-Item` and `os.replace`;
- delete, then recreate;
- an MSVC `cl` + `link` build.

Raw outputs: `probe_out*.txt`. Analyzers: `analyze.py`, `anmap.py`, `order.py`.

## Verified

| Need | Source | Evidence |
|---|---|---|
| Process start, stop, parent | Microsoft-Windows-Kernel-Process: `ProcessStart` (id 1, v4) and `ProcessStop` (id 2) | `ProcessSequenceNumber` and `ParentProcessSequenceNumber` are boot-unique process identities. Also carries PID, `CreateTime` and `ImageName` (NT path). |
| Command line | System logger (SYSTEM_LOGGER_MODE session, `EVENT_TRACE_FLAG_PROCESS`): Process opcode 1 | `CommandLine` is present for every process. Kernel-Process v4 has **no** command line. |
| Open with path | Kernel-File `Create` (id 12, v1) | Payload: `FileObject`, `CreateOptions` (bits 24–31 = disposition, bit 0 = directory), `FileName` (NT device path, the name as opened). |
| Read, write | Kernel-File `Read` (15) and `Write` (16), v1 | Emitted in the issuing process's context. Carry `FileObject`, `FileKey`, `IOSize`, `IOFlags`. Every reopen reports its reads. |
| Rename / move | Kernel-File `RenamePath` (27) | `FilePath` is the **new** path; the old path comes from the `FileObject`. |
| Delete | Kernel-File `DeletePath` (26), preceded by `SetDelete` (18) | `FilePath` is the deleted path. |
| Memory-mapped I/O | System logger `EVENT_TRACE_FLAG_VAMAP`: FileIo GUID `{90CBDC39-…}`, opcode 37 (MapFile) and 38 (UnmapFile) | See the 44-byte layout below. The Python mmap reader maps `in.txt` (protection 1). **`link.exe` maps its `.obj` inputs (1) and writes `app.exe` through a read-write view (4).** Without VAMAP, MSVC link lineage is invisible. |
| FileKey → path | any event carrying both `FileObject` and `FileKey` (QueryInformation, Read, Write, Cleanup, Close) | Each `FileObject` is resolved by its `Create`. `NameDelete` (id 11) retires a `FileKey`. |

MapFile payload (44 bytes, little-endian):

| Offset | Field | Type |
|---|---|---|
| 0 | ViewBase | u64 |
| 8 | FileKey | u64 |
| 16 | MiscInfo | u64 (protection in bits 48–50) |
| 24 | ViewSize | u64 |
| 32 | ByteOffset | u64 |
| 40 | ProcessId | u32 |

## Negative results (do not rely on these)

- Kernel-File delivers **nothing** when enabled inside a SYSTEM_LOGGER_MODE session. Use two sessions.
- `ProcessTrace` cannot consume two real-time sessions in one call (error 87). Use one consumer thread per session, then merge.
- `NameCreate` (id 10) is **not** emitted for ordinary new files, so it cannot be used to name a FileKey.
- A `FileKey` is reused across files. Mapping a key to a name without lifetime handling attributed reads to the wrong files.
- TDH has no schema for the VAMAP FileIo events; parse them by the layout above.

## Order

- Per session, timestamps arrived monotonic: 0 inversions in 15,186 tracked I/O events.
- No `Create` arrived after a use of its `FileObject`.
- This is not a documented guarantee across CPUs or sessions, so the collector merges through a timestamp reorder window.

## Known platform differences (see the schema doc)

- **cwd:** not observable from ETW.
- **Paths:** case-insensitive, and may be 8.3 short names. Normalize with `GetLongPathNameW` when a `~` appears; compare case-insensitively.
- **Lazy-writer writes** (PID 4, paging I/O) are not user-attributable. The user's own write IRP is attributed correctly.
