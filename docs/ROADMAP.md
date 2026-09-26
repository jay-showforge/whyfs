# Roadmap

## v0.1 — query experience (complete)
- explicit Linux `LD_PRELOAD` capture boundary
- workspace-only provenance by default
- `why`, `impact`, `history`
- local SQLite store
- measured native collector overhead

## v0.2 — always-on Linux collector (current alpha)
- eBPF/BCC ring-buffer backend
- process lifecycle + actual fd read/write evidence
- daemon lifecycle + capability doctor
- batched asynchronous SQLite persistence
- visible dropped-evidence counters
- static-binary graduation test
- real parallel C + Node workload gate
- retain v0.1 as honest fallback

### v0.2 blockers before release
- [x] execute the authoritative kernel gate on BPF-capable Linux/WSL (WSL2 6.6, 2026-09-25)
- [x] close BCC/kernel compatibility failures found there (stack limit, PID namespaces, io_uring blind spot)
- [x] <5% median slowdown on real builds (make -j8 0.9–3.1%, Vite −1.8–1.1% across 4 runs)
- [x] zero drops under parallel workload
- [x] extend coverage where the gate exposed gaps (VFS/LSM hooks cover io_uring, openat2, sendfile/splice)
- [ ] **<5% median slowdown on exec-heavy work**: the static-binary ×300 loop measured 7.6 / 4.3 / 7.9 / 5.6%.
  This blocks graduation. See PROJECT_STATUS.md, "What is needed to graduate".

## v0.3 — useful causal compression
- separate direct data inputs from incidental runtime/config reads
- evidence confidence labels
- version-aware lineage (the file consumed then, not merely the path now)
- stale-output detection
- bounded retention/compaction policy

## v0.4 — production distribution + interoperability
- CO-RE/libbpf collector (no runtime BCC compiler dependency)
- W3C PROV export
- SLSA/in-toto attestation bridge
- OpenLineage adapter
- machine-readable local API for IDEs and agents

## Non-goals
- storing file contents
- replacing Git
- pretending inferred edges are observed edges
- cloud upload by default
