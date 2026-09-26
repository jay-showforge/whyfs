# whyfs project status — v0.2.0-alpha

## Working now

- v0.1 explicit `LD_PRELOAD` capture remains functional.
- `why`, `impact`, `history`, JSON output, local SQLite, redaction, workspace filtering.
- v0.2 schema migration supports per-process commands and evidence-source tags.
- v0.2 BCC/eBPF collector source uses a BPF ring buffer and first-I/O-per-fd deduplication.
- user-space fd/path resolution and bounded queue are implemented.
- SQLite persistence is moved off the capture callback and batched on one writer thread.
- daemon foreground/background lifecycle and `whyfs doctor` are implemented.
- kernel/user-space evidence drop accounting is exposed in `whyfs stats`.
- authoritative v0.2 real-workload gate exists.

## Tests in this build environment

- 8/8 local tests pass.
- v0.1 end-to-end multi-process lineage remains green.
- the suite confirms a statically linked binary is *not* falsely explained by v0.1.
- v0.2 user-space fd resolution/filtering/batched-ingestion tests pass.
- capability doctor correctly reports this container as unable to run the eBPF gate.

## Environment blocker here

This ChatGPT execution container lacks `CAP_BPF`/`CAP_PERFMON`, BCC, kernel BTF, and a Clang BPF target. Package repositories are not reachable from the container. Therefore the kernel program cannot be loaded or verifier-tested here.

That is an environment block, not a pass. `scripts/v02_gate.py` returns `BLOCKED_ENVIRONMENT` on this machine and refuses to substitute LD_PRELOAD.

## Real-workload finding from the fallback backend

A parallel GCC build exposed exactly why v0.2 matters: the preload backend can identify the final linker process but misses enough compiler/linker internal file access that header→object→binary impact is incomplete. A Node file build is captured cleanly. This is recorded as a fallback limitation, not massaged into a success.

## Next authoritative action

Run `sudo -E python scripts/v02_gate.py` on a BPF-capable Linux/WSL machine with BCC installed. The output JSON is the v0.2 graduation evidence. Do not call the always-on backend release-ready until it passes or its failures are fixed.
