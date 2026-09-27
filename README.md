# whyfs

**Ask your filesystem why a file exists.**

`whyfs` records local process→file provenance in the workspaces you choose and answers three
questions:

```bash
whyfs why dist/app          # which process wrote it, with what command, from which inputs
whyfs impact src/parser.c   # everything downstream that consumed it
whyfs history dist/app      # every observed write, rename and delete
```

It observes what the operating system already sees: eBPF on Linux, ETW on Windows.  You work
normally, and there is no wrapper command.  Everything stays local.

> **Status: pre-1.0 (0.9.0.dev1), not yet released.**  The platform matrix below shows
> exactly what has been validated.

```text
/work/app/dist/app
└── created by /usr/bin/ld  (pid 4217)
    run: ld -o dist/app main.o util.o
    parent: /usr/bin/make  (pid 4190)  · make -j8
    evidence: ebpf-native
    inputs:
      ├── /work/app/main.o
      ├── /work/app/util.o
```

## Platforms

| Platform | Collector | Package | Status |
|---|---|---|---|
| Linux x86-64 | eBPF (native C collector + BCC programs) | `.deb` (prebuilt collector) | **Validated natively** |
| Linux ARM64 | same sources, built natively for arm64 | `.deb` (arm64) | **Native validation pending** |
| Windows x64 | ETW (native collector + `whyfs` service) | MSI | **Validated natively** ([docs/WINDOWS.md](docs/WINDOWS.md)) |
| Windows ARM64 | same sources, built for ARM64 | MSI (ARM64) | MSI built and verified ARM64; **native validation pending** |
| WSL2 | the Linux collector inside WSL2 | `.deb` | **Validated** (the Linux x86-64 host above is WSL2) |

Not currently supported: **macOS**.  macOS is a future/community target; contributions are
welcome.

"Validated natively" means real runtime evidence on that platform: installer, collector, the
shared A–H behavioural corpus, why/impact/history, zero event loss, privacy and performance
gates.  Cross-compilation alone is never counted as support.  For the current evidence and
what is still needed, see [docs/PLATFORM_VALIDATION.md](docs/PLATFORM_VALIDATION.md).

## Install

### Linux (Debian/Ubuntu, x86-64 or arm64)

```bash
sudo apt install ./whyfs_<version>_<arch>.deb
whyfs doctor                      # kernel BTF / BPF / ring buffer checks
```

The package ships a prebuilt collector (`/usr/lib/whyfs/whyfs-collect`) for its architecture.
Nothing is compiled on the normal path.  The collector is used only if it matches the
package's recorded source hash and only root can modify it; otherwise it is refused.

```bash
cd ~/project && whyfs init
sudo whyfs daemon start --workspace ~/project      # or, always on, with systemd:
sudo systemctl enable --now "whyfs@$(systemd-escape --path ~/project).service"
```

The eBPF programs need root.  The daemon writes each store as the workspace owner
(privilege-separated).

### WSL2

Install the Linux `.deb` inside the WSL2 distribution; check the kernel with `whyfs doctor`.
Watch workspaces on the Linux filesystem (`/home/...`).  Files under `/mnt/c` are served by
the Windows file bridge, and Windows programs that write them are invisible to the Linux
kernel.  For Windows-side tools, install the Windows MSI.  With `systemd=true` in
`/etc/wsl.conf` the `whyfs@` unit works; without it, use `sudo whyfs daemon start`.

### Windows (x64, ARM64)

Run `whyfs-<version>-<arch>.msi` once as an administrator.  It installs the `whyfs` service
and puts `whyfs` on PATH.  After that, everything runs as a normal user:

```powershell
cd C:\src\project
whyfs init
whyfs daemon start
# ... build, test, edit as usual ...
whyfs why dist\app.exe
whyfs daemon stop
```

Upgrades replace the older version in place.  Uninstalling removes the program, service and
PATH entry.  Workspace histories (`<workspace>\.whyfs`) belong to their users and are kept.

## Raw evidence vs. human view

`whyfs` never deletes evidence because it looks noisy.  The default view hides
system/runtime reads (`/usr/lib`, `C:\Windows`, …) and dependency trees (`node_modules`,
`site-packages`), and says how many inputs it hid:

```bash
whyfs why FILE --all      # include system/library reads
whyfs why FILE --raw      # unfiltered inputs plus the creator's raw stored events
whyfs impact FILE --all   # include system/runtime outputs
whyfs why FILE --json     # machine-readable
```

When one compiler process builds many files (e.g. `cl.exe a.c b.c c.c`), its outputs are
labelled **shared** instead of being given a lineage that was never observed.  Every lost event
is counted (`whyfs stats`), never hidden.

## Privacy

- Local only: `<workspace>/.whyfs/whyfs.db`.  Nothing is uploaded.  File contents are never
  captured.
- Only files inside the workspace (and derived temporaries) are stored.  Only processes that
  touched the workspace, and a bounded chain of their ancestors, are stored.
- **Secret values on command lines are redacted before storage** on every platform, including
  inside shell wrappers: `--token x`, `--password=x`, `/token:x`, `-Password x`,
  `API_KEY=x`, `ACCESS_TOKEN=x`, `sh -c '… --api-key x'`, `cmd /c "… PRIVATE_KEY=x"`,
  PowerShell `$env:API_KEY='x'`, `Authorization: Bearer x`.  There is one policy and one set
  of shared test vectors, with three implementations (`src/whyfs/redact.py` is the reference).
- See [SECURITY.md](SECURITY.md).

## What is recorded

| | Linux (eBPF) | Windows (ETW) |
|---|---|---|
| process start/exit, parent, command line | yes | yes |
| opens | every successful open | not recorded (Windows reports probes as creates) |
| first read / first write per file and process | yes (incl. io_uring, sendfile, splice) | yes |
| memory-mapped files | yes | yes |
| rename, delete | yes | yes (incl. delete-on-close) |
| path comparison | case-sensitive | case-insensitive |

Not covered: metadata-only operations (chmod, timestamps, links), and files already open before
collection started.  The canonical record format is in [docs/SCHEMA.md](docs/SCHEMA.md).

## Development

```bash
make test                                  # Linux (as root it also runs the live eBPF tests)
python -m unittest discover -s tests       # Windows (PYTHONPATH=src;tests)
python scripts/run_corpus.py --out DIR     # shared A–H corpus (Linux: sudo … --user USER)
python scripts/secret_gate.py --out DIR    # live redaction gate
```

Windows binaries and the MSI: `native\windows\build.ps1`, `native\windows\make_msi.py`.  Linux
package: `packaging/linux/build_deb.sh`.

## Positioning

File provenance is not new.  PASS/CamFlow, security provenance systems, build provenance, data
lineage, ReproZip-style capture and language-specific lineage tools all cover parts of the
space.  The bet here is narrower: make host-observed process→file causality feel like an
ordinary filesystem query.

Non-goals: storing file contents, replacing Git, claiming an inferred dependency was observed,
uploading provenance anywhere, hiding dropped-evidence counters.

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
