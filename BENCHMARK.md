# v0.1 development benchmark

This is an engineering checkpoint, not a universal performance claim.

Environment: Linux x86-64 container, Python 3.13.5, local filesystem.
Workload: create 3,000 small workspace files, then read all 3,000. Seven paired runs after warmup, alternating baseline/capture order. The measurement isolates the native capture backend and deliberately excludes Python CLI startup and SQLite post-run import.

```
baseline median: 0.6932s
capture median:  0.7076s
median paired native-capture overhead: 3.59%
paired overheads: 8.8%, 3.6%, 3.7%, -1.3%, -4.5%, -2.6%, 7.4%
```

The collector records only workspace paths by default. Real workloads, storage devices, languages, and filesystem patterns will differ; rerun with `python scripts/benchmark.py` on target hardware.

---

## v0.2 always-on graduation benchmark

v0.2 adds `scripts/v02_gate.py`. It deliberately refuses to use the preload backend when BPF is unavailable.

The gate measures three kinds of real workload:

1. **Static ELF copy program** — proves the kernel backend sees a program that `LD_PRELOAD` cannot interpose.
2. **Parallel C build** — generated multi-file project compiled with `make -j4`, then checks header → object → executable transitive impact.
3. **Node build** — reads a config plus multiple source files and writes one bundle.

It also runs paired baseline/daemon timings for the parallel C build and requires median slowdown below 5%, plus zero reported kernel ring-buffer drops.

### Status in the ChatGPT build environment

`BLOCKED_ENVIRONMENT`.

The container used to build this alpha lacks BCC, `CAP_BPF`, `CAP_PERFMON`, kernel BTF, and a Clang BPF target. Package repositories are unreachable from the container, so the kernel verifier/load test cannot be executed honestly here.

This is recorded as an environment block, **not** as a performance or correctness pass. The exact gate is included so the next BPF-capable Linux/WSL run produces an authoritative JSON verdict instead of an ad-hoc demo.

### Fallback real-workload observation

The v0.1 backend was also exercised on a parallel GCC build and a Node file-build workload while developing v0.2.

- Node's workspace inputs were reconstructed cleanly (`build.js`, `config.json`, and both source files).
- The GCC/linker path exposed a v0.1 blind spot: the final writer could be identified, but enough internal compiler/linker file access bypassed preload interposition that header → object → executable impact was incomplete.

That failure is one of the reasons the v0.2 gate centers kernel-observed file descriptors rather than adding more libc wrappers.
