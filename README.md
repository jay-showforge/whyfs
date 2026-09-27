# whyfs

**whyfs automatically labels files with their provenance: where, when, how, and what or who
caused them to exist. People and software agents can then understand the files they
encounter.**

Install it once.  From then on, whenever a file is created or changed anywhere you work,
whyfs attaches an external provenance label to it.  It records:
- when the file was created;
- by which user;
- which process wrote it, and the chain of programs that led to that process;
- which files went into it;
- what happened to it afterwards;
- when a known AI agent session caused it, which session.

The file itself is never touched.  No metadata is embedded, and no sidecar files, extended
attributes or Git changes are added.  The label lives in whyfs's own local store.  There is
nothing to initialize and no folder to register.

> **Status: pre-1.0 (0.9.0.dev1), not yet released.**  Validated platforms are listed below.

```text
$ whyfs label dist/app.js
File:     C:\Projects\App\dist\app.js
Created:  2026-09-27T14:43:10-07:00
User:     HOST\jay
Created by: C:\Program Files\nodejs\node.exe  (pid 4121)
  command: node node_modules/vite/bin/vite.js build
Process chain: explorer.exe → claude.exe → powershell.exe → npm → node.exe
Agent:    Claude Code 2.1.281   (registered: the local service verified the session's root process)
Session:  7f3c…
Task:     Build checkout redesign   [supplied by the agent session when it registered (not verified by whyfs)]
Why:      app.js exists because node.exe wrote it after reading main.ts, api.ts, vite.config.ts.
Inputs:
  C:\Projects\App\src\main.ts
  C:\Projects\App\src\api.ts
  C:\Projects\App\vite.config.ts
History:
  2026-09-27T14:43:10-07:00  written    by node.exe
  2026-09-27T14:45:02-07:00  read       by deploy.exe
Evidence: OS-observed + registered agent context; identity match
```

Two kinds of *why* are kept apart:
- **Causal why** is what whyfs observed: this process wrote the file after reading those files.
- **Intent** ("the user asked the agent to fix the checkout page") appears only when an agent
  session supplied it, and says so.  whyfs never infers intent.

## How it works

The collector, in the OS kernel's event stream, runs as a service from boot:
- Linux: eBPF programs with a native C collector;
- Windows: ETW with a native collector behind the `whyfs` service.

It sees which processes read, write, map, rename and delete files, and how processes descend
from each other.  A **scope policy** decides what gets a label:
- everything a user works with, wherever it is;
- *not* OS internals, application caches or browser profiles;
- temp files, only when they carry data into real files.

Each label is keyed to the file's **native identity** (Linux inode/device/generation, NTFS
file ID) as well as its path.  So it follows renames and moves, and an old record is never
attached to a new file that happens to reuse a path.

**Agents.**  whyfs distinguishes what the OS proves (process A started process B, which
wrote the file) from agent context:
- **Registered session:** an AI agent registers its session with the local service.  Every
  descendant process and every file they produce carries that session.
- **Detected agent:** Claude Code, Codex CLI and Gemini CLI are also recognized from their
  installed program layout and command line.  A file name alone is never enough.
- The real process chain is always kept; "the agent created it" never replaces "vite.exe
  wrote it".

See [docs/MACHINE_MODE.md](docs/MACHINE_MODE.md) and [docs/AGENT_PROTOCOL.md](docs/AGENT_PROTOCOL.md).

## Asking

```bash
whyfs label FILE [--json]     # the provenance label (human or JSON)
whyfs why FILE                # creator and inputs      whyfs history FILE   # what happened to it
whyfs impact FILE             # what was built from it  whyfs recent         # recent changes and their causes
whyfs agent files --session-id S                        # everything an agent session changed
whyfs status [--scope]        # what whyfs records, store size, loss counters, retention
```

Agents do not need to scrape text.  A local API speaks one JSON request/reply per line:
- Linux: `/run/whyfs/api.sock`;
- Windows: `\\.\pipe\whyfs-api`.

It offers `get_file_provenance`, `explain_file`, `get_file_history`, `get_file_inputs`,
`get_file_dependents`, `get_recent_changes`, `get_agent_session`, `get_files_by_agent`,
`session_start` and `session_end`.  From any language, `whyfs api OP '{"path": "..."}'` returns
the same JSON.

## Platforms

| Platform | Collector | Package | Status |
|---|---|---|---|
| Linux x86-64 | eBPF + native collector, `whyfs.service` | `.deb` | **Validated natively** |
| Linux ARM64 | the same, built for arm64 | `.deb` (arm64) | **Native validation pending** |
| Windows x64 | ETW + native collector, `whyfs` service | MSI | **Validated natively** |
| Windows ARM64 | the same, built for ARM64 | MSI (ARM64) | MSI built and verified ARM64; **native validation pending** |
| WSL2 | the Linux collector inside WSL2 | `.deb` | **Validated** |

Not currently supported: **macOS** (a future/community target; contributions are welcome).

Evidence and what remains: [docs/PLATFORM_VALIDATION.md](docs/PLATFORM_VALIDATION.md).

## Install

- **Linux (Debian/Ubuntu):** `sudo apt install ./whyfs_<version>_<arch>.deb`.  The labelling
  service (`whyfs.service`) starts immediately and at every boot.  Check the kernel with
  `whyfs doctor`.
- **WSL2:** the same package inside the distribution.
  - With `systemd=true` in `/etc/wsl.conf` the service starts by itself.  Otherwise, run
    `sudo whyfs machine run` in the background.
  - Linux-side tools are labelled.  For Windows-side tools, install the MSI on Windows.
- **Windows:** run `whyfs-<version>-<arch>.msi` once as an administrator.  The `whyfs`
  service starts labelling immediately; everything after that runs as a normal user.

Upgrades keep the store.
- **Windows:** uninstalling removes the program; the provenance store stays in
  `%ProgramData%\whyfs` until you delete it.
- **Linux:** `apt remove` keeps it; `apt purge` deletes it.

## Privacy and storage

- **Local only.**  No cloud, account or telemetry, and no network listener.  File contents
  are never read.
- **Per-user visibility.**  The store is readable only by the service.  Through the API each
  user sees the records of their own processes; only root or an elevated administrator sees
  everyone's.
- **Secrets on command lines are redacted before storage**, including inside shell wrappers
  (`--token x`, `/password:x`, `API_KEY=x`, `sh -c '…'`, `cmd /c "…"`, PowerShell
  `$env:KEY=…`, `Authorization: Bearer x`).  Agent task text goes through the same redaction.
- **Scope, retention and reset:**
  - exclude paths or programs in `scope.conf`;
  - retention defaults to 365 days for creation records and 30 days for pure reads, with a
    store cap of 2 GiB;
  - `whyfs forget PATH | --everything` deletes records;
  - `whyfs status` shows what is recorded.

See [SECURITY.md](SECURITY.md) and [docs/MACHINE_MODE.md](docs/MACHINE_MODE.md).

## Explicit workspace captures

`whyfs init` plus `whyfs daemon start|stop` still record one directory into its own
`.whyfs` store: an isolated capture for CI or for tests, e.g. of a single build.  It is
optional; labels never require it.

## Development

```bash
make test                                        # Linux (as root it also runs the live eBPF tests)
python -m unittest discover -s tests             # Windows (PYTHONPATH=src;tests)
sudo python3 scripts/product_gate.py --user $USER --out DIR   # install-once product behaviour (Tests A-H)
python scripts/run_corpus.py --out DIR           # shared A–H behavioural corpus
python scripts/machine_perf.py --out DIR         # machine-wide performance and resource cost
```

## License

whyfs is **source available under the Business Source License 1.1** (see [LICENSE](LICENSE)).
It is not OSI-approved open source.

- Non-production use (testing, evaluation, personal, educational, research) is permitted.
- Production use is free for individuals and organizations (together with their affiliates)
  whose aggregate annual gross revenue is below US$100,000.
- Other production use, and commercial embedding, bundling or distribution, require a
  commercial license: licensing@tenzorpipe.org.
- Each version converts to the Apache License 2.0 on its Change Date, four years after its
  first public release.
