# whyfs v0.2 graduation: native collector (frozen 04a62870ca8f)

**Verdict: V0.2 GRADUATES.**

Every criterion was met on one frozen commit, with the pre-committed protocol and harnesses. Nothing was averaged across campaigns, no run was discarded, and no threshold or workload changed.

## Frozen build

- Commit `04a62870ca8f23243d56b6a2ce4467981b6bb43d`, with a clean tree when frozen. The full inventory is in `FREEZE.txt`.
- Host: Windows 10.0.26200.9457, WSL 2.5.10.0, kernel 6.6.87.2-microsoft-standard-WSL2, Ubuntu 24.04.3.
- Hardware: i5-14400F with 16 vCPU and 16 GB RAM.
- Toolchain: gcc 13.3, clang 18.1.3, libbpf 1.3.0, SQLite 3.45.1, BCC 0.29.1, Python 3.12.3, Node 18.19.1.
- BTF: present. BPF features: tracing, lsm and ringbuf available.

## Results

Harness: `scripts/v02_graduation.py --pairs 20 --warmups 2`. Each campaign ran on its own, starting a fresh daemon for every monitored pair; the first build after each start is recorded separately.

| Check | Campaign 1 | Campaign 2 |
|---|---|---|
| static ×300 median paired overhead (< 5%) | **+1.22%** | **+2.90%** |
| make -j8, 36 units (< 5%) | −0.55% | +1.75% |
| Vite build (< 5%) | −0.45% | −0.20% |
| kernel / userspace drops | 0 / 0 on all workloads | 0 / 0 on all workloads |
| creator attribution (≥ 99%) | 100% (44/44) | 100% (44/44) |
| useful-input recall (≥ 95%) | 100% (118/118) | 100% (118/118) |
| `why` median, in-process (< 100 ms) | 0.32 ms | 0.30 ms |
| `why` median, CLI end to end (reported) | 50 ms | 50 ms |
| functional + noise checks | 39/39 | 39/39 |
| verdict | PASS (47/47) | PASS (47/47) |

Further checks on the same frozen tree:

- **Unmodified `scripts/v02_gate.py`:** PASS (sha256 `bd70f255…`; unchanged since import 7d0a9b1). Overhead +1.20%, zero kernel drops, and the static, Node and parallel-make lineage checks all pass.
- **Full test suite:** 143 tests OK as root and 143 OK as user (53 root-only tests skip for the user).

## What changed to get here

Per-event ingestion moved from Python to `whyfs-collect`, a native C collector:

- It consumes the same BPF programs and the same ring buffer through libbpf.
- Its event model is a line-for-line port of `BCCCollector._process_event`, which remains the executable specification. Every resolver and privacy test runs on both collectors.
- A differential fuzz requires identical records and counters, and it caught 4 of 4 deliberate mutations. Writer rows equal `ingest_events()` output.
- A forked writer drops to the workspace owner's privileges before it opens SQLite.

Evidence for the change: `results/v02-native-spike`, `v02-native-integrated`, `v02-native-ab`, `v02-native-decomp` and `v02-native-defer`.

## Caveats (read before quoting numbers)

1. **The two harnesses measure differently.** In same-session rotated A/B rounds, timed inside the workload shell, the native collector costs +5.64 ms (4.41%) on static ×300, against +7.32 ms (5.74%) for the Python collector. The kernel evidence floor alone is about 4.7 ms (3.6%). The graduation harness reads lower (1.2–2.9%) for two reasons:
   - it times the whole `runuser … bash` invocation, a slightly larger denominator;
   - persistence is deferred while the workload runs (see caveat 2).

   Both harnesses are pre-existing and neither was modified to be favourable. The Python collector scored 5.80% and 7.19% on this same harness (`results/v02-graduation-final`).
2. **Deferred persistence is product behaviour, not a benchmark trick.**
   - Evidence reaches SQLite once the workspace has been quiet for 200 ms, or 2 s after it was queued, or when 65,536 records are waiting.
   - Live tests enforce visibility under 1 s after activity stops and under 2.5 s during continuous activity.
   - Its separate wall-time benefit was *not* statistically significant (NI−NF +0.51 ms, CI −1.04..+1.21).
   - On long builds persistence interleaves with the build, and it is included in the make and Vite results.
3. **Collector CPU** reads 0.000 s in both campaigns because the field counts only the measured build window, at 10 ms tick resolution, and persistence falls after that window. A direct probe of the daemon's process tree shows 0.02 s for a 300-process loop, persistence included.
4. **Single host.** All of this is WSL2 on one machine. Other kernels or distributions have not been measured.
5. **Paired medians over 20 pairs are noisy,** about ±2 percentage points per pair. Both campaigns pass independently, and the A/B estimate (4.4%) leaves less margin than the campaign figures suggest.

## Files

- `FREEZE.txt`: the freeze inventory.
- `campaigns.log`: start and end times of each campaign.
- `campaign-1/`, `campaign-2/`: `graduation.json` with every raw run, plus `graduation.log`.
- `campaign-*.stdout`: console output of each campaign.
- `gate.json`, `gate.stderr`: the unmodified gate.
- `suite-root.txt`, `suite-user.txt`: the test suites.
