# WhyFS on macOS (development: branch `macos-support`)

**Status: in development, not released.**  WhyFS 1.0.0 (`v1.0.0`) does not include macOS.
The macOS work builds, installs and passes every executed product gate on GitHub-hosted Intel and
Apple Silicon Macs.  Those Macs run with System Integrity Protection **disabled**.  On a standard
Mac (SIP enabled), the Endpoint Security client only starts if Apple's restricted entitlement is
present: see [External requirement](#external-requirement-apple-endpoint-security-entitlement).
The exact evidence is in [Validation status](#validation-status).

## Architecture

```
Endpoint Security (NOTIFY events)
  -> native/macos/whyfs-es.c        normalized message: the replay boundary (--es-record / --es-replay)
  -> native/whyfs-collect.c         the shared WhyFS event model and SQLite writer (the Linux collector's,
                                    built with -DWHYFS_MACOS; the Linux object code is byte-identical to v1.0.0)
  -> the machine store              the same schema as Linux and Windows
  -> query / label / API / UI / CLI unchanged shared code
```

- **Shared with Windows and Linux:** the whole product above the collector:
  - store and schema;
  - query, label, history, impact;
  - the observation and gap model, retention and redaction policy;
  - the scope rule language, agent sessions;
  - `whyfs-api/1`, the WhyFS window, the CLI.
- **Shared with Linux:** the event model itself (process keys and ancestry, first I/O per open,
  rename rewrites, derived temporaries, relevance, argv redaction) and the store writer.
- **macOS-specific:**
  - `native/macos/whyfs-es.c`, the Endpoint Security client and translation;
  - `whyfs/macos.py`: paths, file identity, on-disk path form, libproc process facts, socket
    peer credentials, the launchd-run supervisor;
  - `darwin` branches in the shared modules;
  - the macOS scope defaults;
  - `packaging/macos`.

## Endpoint Security semantics

The collector subscribes to these Endpoint Security NOTIFY events (no AUTH events: WhyFS never
blocks anything).

| Event | WhyFS evidence | Notes |
|---|---|---|
| `exec` | the program image, its arguments (redacted), its cwd | argv is bounded to 511 bytes, as on Linux |
| `fork` | process ancestry (child, parent, real user) | |
| `exit` | end of the process's facts | |
| `chdir` | the working directory | |
| `open` with read access | a **read**, `es:open-read` | Endpoint Security reports opens, not individual reads: a file opened for reading and never read counts as an input, timed at the open |
| `close` with `modified` | a **write**, `es:close-modified` | timed at the close, not the write |
| `mmap` | a read; `MAP_SHARED` + `PROT_WRITE` also a write, `es:mmap` | |
| `rename` | `es:rename` (to an existing file or a new path) | |
| `unlink` | `es:unlink` | |
| `clone` (`clonefile`, Finder copies on APFS) | source read, clone written, `es:clone` | |
| `copyfile` | source read, destination written, `es:copyfile` | |

- **Creating a file without writing data** (`touch`) produces no write evidence, as on Linux.
  Endpoint Security reports a new file's `open(O_CREAT)` as a create, not an open; WhyFS takes the
  write evidence from the close.
- **Not recorded:**
  - `truncate` and `link` (hard links), as on Linux;
  - `exchangedata` and `renamex_np(RENAME_SWAP)`.
- **Lost events:** Endpoint Security numbers every message it sends a client (`global_seq_num`). A
  gap is counted as loss (`kernel_drops`); a consumer that falls behind counts `queue_drops`.
  Both are reported by `whyfs status` and in labels, as on Linux and Windows.
- **Paths:**
  - Endpoint Security reports real paths: `/private/tmp`, `/private/var/...`, and `/Users/...`
    for the data volume.
  - The query layer turns what a user types into that form with `F_GETPATH`. This resolves
    symbolic links and keeps the stored case, because APFS is normally case-insensitive.

## Kernel-side scope (performance)

Endpoint Security delivers events for every process on the Mac; WhyFS asks the kernel not to
deliver what its scope rules would discard anyway:
- open, close and mmap under each literal exclude prefix that no include or temp rule reopens
  (and the excluded directories themselves, and opens of `/`) are muted by target path;
- a process running an image the rules exclude (Spotlight's indexers, WhyFS's own collector) is
  muted as a whole the first time it is seen.  Its children keep their own events; a child's
  parent link then comes from the process table (libproc), not from the muted fork.
exec, fork, exit, rename and unlink of everything else are never muted.

## File identity

- **Format:** `mac:DEV:INO`, the device and inode that Endpoint Security attaches to every file.
- **No generation number:** macOS has no inode generation (APFS reports `st_gen` 0), so this is
  not Linux's `(device, inode, generation)`.
- **Inode reuse:** APFS allocates inode numbers from a per-volume counter and does not reuse them.
  A regression test recreates a path 200 times and requires a new inode each time.
- **Different inode, same device:** the file is a different one. The label says the origin was
  not observed and names what the previous file at that path was; it never attaches old evidence
  (tested with real files).
- **Different device:** reported as unknown, not a mismatch. A remounted volume can be renumbered.
- **Rename:** keeps the identity.
- **Hard links:** share it; the label finds a hard-linked file through its identity.
- **New clones and copies:** a copy destination's identity comes from `lstat` when Endpoint
  Security does not provide one, and is otherwise left empty, never guessed.

## Service

- **launchd job:** `/Library/LaunchDaemons/org.tenzorpipe.whyfs.plist`, with
  - `RunAtLoad`: starts at boot and on install;
  - `KeepAlive`: restarted after any exit;
  - `ThrottleInterval` 5;
  - `ExitTimeOut` 120, so the collector drains at shutdown.
- **Program:** the collector app's binary in `--launchd` mode. It runs the supervisor
  `whyfs machine run`, as root, as its child. The supervisor:
  - restarts the collector with backoff;
  - writes a heartbeat every 10 s;
  - closes a crashed run at its last heartbeat (a recorded gap);
  - serves the local API;
  - applies retention.
- **Stopping** (uninstall, upgrade, shutdown) drains everything the collector received into the
  store; uninstall and upgrade wait until launchd has stopped the job.

## Local API and user isolation

- **Socket:** `whyfs-api/1` on `/var/run/whyfs/api.sock`, a Unix socket in a root-owned directory,
  never TCP.
- **Caller identity:** the kernel's `LOCAL_PEERCRED` / `LOCAL_PEERPID`.
- **Visibility:** a normal user sees evidence of their own processes; root sees all.

## Storage

- **Store:** `/Library/Application Support/WhyFS/machine`, mode 0700, root. The same SQLite schema
  and retention defaults as elsewhere.
- **Logs:** `/Library/Logs/WhyFS`.
- **Configuration:** `/Library/Application Support/WhyFS/config.json` and `scope.conf`.

## Scope

- **Defaults:** `python -m whyfs.scope macos`.
- **Temporaries:** `/private/tmp`, `/private/var/tmp` and each user's `/private/var/folders/*/*/T`.
- **Excluded:**
  - system and package locations: `/System`, `/usr`, `/bin`, `/sbin`, `/Library`,
    `/Applications`, `/opt/homebrew`;
  - the rest of `/private/var/folders` (caches) and system state in `/private/var`;
  - Spotlight, fseventsd and version stores on every volume;
  - in every home: `Library/Caches`, `Logs`, `Saved Application State`, `HTTPStorages`,
    `Cookies`, `WebKit`, `Metadata`, `Biome`, `Preferences`, Safari and browser profiles,
    `.Trash`, `.cache`;
  - processes: Spotlight indexers, `backupd`, `fseventsd`, and WhyFS's own collector.
- **Everything else is in scope, wherever it is.** That includes Desktop, Documents, projects,
  `/Users/Shared`, external volumes, iCloud Drive (`Library/Mobile Documents`) and application
  documents in `Library/Application Support`.
- **Vectors:** `tests/scope_vectors.json` (`macos`); the Python reference and the native collector
  agree on every one.

## Human workflow

- **Finder Quick Actions** (`/Library/Services`: right-click > Quick Actions, and the Services
  menu). Each runs the installed `whyfs ui` exactly as the Windows and Linux menus do:
  - *Why does this file exist?*
  - *What created this file?*
  - *What depends on this file?*
  - *Show WhyFS history*
  - *Search WhyFS in this folder*
- **WhyFS.app** in `/Applications` (Launchpad, Spotlight) opens the WhyFS window, the same local
  page on `127.0.0.1` as elsewhere.
- **Not built: a Finder Sync extension** (badges, a top-level menu). An app extension must be
  signed and must be enabled by the user; Quick Actions are Apple's supported mechanism that needs
  neither.

## Install and uninstall

- **Install:** a per-architecture `.pkg`, built by `packaging/macos/build_pkg.py`. It refuses the
  other architecture.
- **Uninstall:** `sudo /Library/WhyFS/uninstall.sh` stops the service and removes the program. The
  provenance store is kept unless `--purge` is given.

## Signing and notarization

- **Development packages:** the CI packages are **UNSIGNED DEVELOPMENT ARTIFACTS — NOT FOR PUBLIC
  RELEASE**, as their file names and installer titles say. The collector carries an ad hoc
  signature with the Endpoint Security entitlement.
- **Signed build (not yet possible):** it is the same layout, built by `build_pkg.py
  --codesign-identity --provisioning-profile --installer-identity`:
  - the collector is in an app bundle, so a provisioning profile can be embedded;
  - it is signed with the hardened runtime.
- **Notarization:** would then use `xcrun notarytool submit` and `xcrun stapler`.
- **No credentials** are stored in the repository.

## External requirement: Apple Endpoint Security entitlement

- **The entitlement:** `com.apple.developer.endpoint-security.client` is granted by Apple to a
  Developer Team on request. A binary carrying it runs on a standard Mac only when signed with that
  team's Developer ID and shipped with the matching provisioning profile.
- **Observed on the runners** (`results/macos/36514213130`, the probe):
  - an unsigned client, as root: `ERR_NOT_ENTITLED`;
  - ad hoc signed with the entitlement: `amfid` logs "Restricted entitlements not validated", and
    because SIP is disabled on those Macs, the client starts.
- **Consequence:** the development package's collector will not start on a standard Mac. That is
  **BLOCKED_EXTERNAL — APPLE ENDPOINT SECURITY ENTITLEMENT REQUIRED**. It is not a product result,
  and it is not testable on hosted runners either way.
- **Full Disk Access:** Apple requires the user to grant it to an Endpoint Security client. The
  launchd program is the collector app, so the grant names WhyFS's collector, not a Python
  interpreter. On the SIP-disabled runners the client started without a grant; the grant step is
  not observable there. `whyfs doctor` and `whyfs status` report a refused client
  (`ERR_NOT_PERMITTED` / `ERR_NOT_ENTITLED`).

## Validation status

See [PLATFORM_VALIDATION.md](PLATFORM_VALIDATION.md#macos-development-branch-macos-support) for
runs, commits and hashes.

| | Intel (`macos-15-intel`, x86_64) | Apple Silicon (`macos-15`, `macos-14`, `macos-26`, arm64) |
|---|---|---|
| Build (warnings on) | BUILD PASS | BUILD PASS |
| Shared and macOS tests | SHARED TESTS PASS (140; 38 skips, all Linux/Windows-only) | SHARED TESTS PASS |
| Replay (translation, model, store, label) | REPLAY PASS | REPLAY PASS |
| Live Endpoint Security (WhyFS's own client, real events) | LIVE ENDPOINT SECURITY PASS (SIP disabled, ad hoc) | LIVE ENDPOINT SECURITY PASS (SIP disabled, ad hoc) |
| Package: install, upgrade, uninstall, purge | PACKAGE PASS (34/34) | PACKAGE PASS (34/34 on each) |
| Service (launchd start, restart, drain) | PASS | PASS |
| Product gate (CLI, API, UI, agents, privacy) | PASS 49/49 | PASS 49/49 |
| Behavioural corpus | PASS 79/79, lost 0 | PASS 79/79, lost 0 |
| Secret redaction | PASS 22/22 | PASS 22/22 |
| Observation integrity (outage) | PASS 13/13 | PASS 13/13 |
| Finder Quick Actions | PASS (run by Automator, observed by Endpoint Security) | PASS |
| Performance | see PLATFORM_VALIDATION.md | see PLATFORM_VALIDATION.md |
| Standard Mac (SIP on), Developer ID | BLOCKED_EXTERNAL — entitlement | BLOCKED_EXTERNAL — entitlement |

Tested macOS versions: 15.7.9 (Intel and Apple Silicon), 14.8.9 and 26.6.2 (Apple Silicon).
Intel on macOS 14 and 26 was not tested: hosted Intel runners are macOS 15 only.

## Known limitations (macOS)

- Reads are opens with read access; writes are timed at close (see the table above).
- An `exec`'s argument list is bounded to 511 bytes, and paths longer than 511 bytes are counted,
  not recorded, as on Linux.
- Workspace mode (`whyfs init`, `whyfs daemon`) is Linux and Windows only; macOS is machine-wide.
- Paths are matched case-sensitively in scope rules, in the stored case.
- The development packages are not reproducible bit for bit across runners.
