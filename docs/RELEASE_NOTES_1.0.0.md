# WhyFS 1.0.0: release notes (draft for the release review; not published)

> **Status: not releasable as is.**  The authoritative run failed one check of the 1.0
> performance contract: Windows ARM64 MSVC +5.18 % (< 5 % required).  See BENCHMARK.md
> section 7.  Every other gate passed.

**Know why a file exists.**  WhyFS automatically labels files with their provenance: what
created them, when, how, which inputs contributed and, when it is reliably known, which person
or software agent caused the activity.  It is local-first: no cloud, no telemetry, file contents
are never read, files are never modified, and every gap in observation is stated.

Source available under the Business Source License 1.1 (see *License* below).

## Supported platforms

Windows x64, Windows ARM64, Linux x86-64, Linux ARM64, WSL2.  Each was validated natively
([PLATFORM_VALIDATION.md](PLATFORM_VALIDATION.md)).  macOS is not supported.

## What is in 1.0

- **Automatic, machine-wide labels.**  A native collector (Windows ETW, Linux eBPF) runs as an
  OS service from boot.  No folder needs to be initialized.  A scope policy labels user files,
  not OS internals or caches.
- **One canonical label**, the same from Explorer, the WhyFS window, the CLI and the API:
  - the creator and its process chain, the user, and the inputs (also through temporary
    files);
  - history, dependents and impact (never "safe to delete");
  - the agent session, and the task only when a session supplied it;
  - whether WhyFS was watching the whole time.
- **For people:**
  - **WhyFS** in the Explorer right-click menu (Windows) and in Files, Dolphin and Nemo
    (Linux);
  - a **WhyFS** Start/application-menu entry;
  - a local, read-only search window on `127.0.0.1`, token-protected.
  - No terminal is needed.
- **For agents:**
  - the local API `whyfs-api/1`, covering provenance, inputs, dependents, history, search and
    sessions;
  - registered agent sessions;
  - detection of Claude Code, Codex CLI and Gemini CLI.
- **For power users:** the `whyfs` CLI.
- **Observation integrity:**
  - the service auto-starts and restarts after a crash;
  - heartbeats, recorded gaps and loss counters;
  - a file that appeared while WhyFS was down gets no invented creator; its label names the
    gap.

## Installing

| Package | Platform |
|---|---|
| `whyfs-1.0.0-x64.msi` | Windows x64 (run once as an administrator) |
| `whyfs-1.0.0-arm64.msi` | Windows ARM64 |
| `whyfs_1.0.0_amd64.deb` | Linux x86-64 and WSL2: `sudo apt install ./whyfs_1.0.0_amd64.deb` |
| `whyfs_1.0.0_arm64.deb` | Linux ARM64 |
| `whyfs-1.0.0-src.tar.gz` | source |

Check each file against `SHA256SUMS` ([RELEASE_ARTIFACTS.md](RELEASE_ARTIFACTS.md)).  The
packages are not code-signed.

## Measured cost

Median paired overhead on native runners:
- builds: +0.1 to +2.8 %;
- process spawn ×300 (a stress test): −0.7 % on a 10-core desktop; +4.2 % to +6.5 % on a
  1-core hosted runner, where the required kernel events alone cost up to +5.9 %;
- idle: ≤ 0.12 % of one core;
- events lost: 0;
- CLI queries: 23–92 ms.

Details: [PLATFORM_VALIDATION.md](PLATFORM_VALIDATION.md#performance-20-counterbalanced-pairs-threshold-median-paired-overhead--5-).

## Known limitations

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).  In short:
- WhyFS knows only what it observed while running.
- Lineage is per process, not per byte.
- Intent is never inferred.
- Network file systems are not validated.
- The Windows 11 compact menu is not supported (**Show more options** is).
- Windows 10 is not validated separately.

## License

- Business Source License 1.1, Licensor Jonathan Tyler Montgomery, Change License Apache 2.0.
- The Additional Use Grant covers:
  - personal non-commercial use;
  - non-commercial educational or research use.
- Commercial production use and embedding need a commercial license (licensing@tenzorpipe.org).
- Evaluation is covered by the base BSL rights.

WhyFS is not OSI open source.

**Before the first public distribution** (open items for the human release review):
1. The **Change Date** in `LICENSE` is a placeholder and must be set to a fixed calendar date.
2. The Additional Use Grant wording should get a final legal review.
3. Contributor terms: outside code contributions wait until the maintainer publishes them;
   no CLA is required today ([CONTRIBUTING.md](../CONTRIBUTING.md)).
