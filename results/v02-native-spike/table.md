| Metric | Python collector (E) | Native spike (N1) |
|---|---|---|
| workload wall time (ms) | 132.05 | 131.31 |
| added overhead vs A (ms, CI90) | +5.49 (+4.83..+6.69) | +4.74 (+3.57..+5.81) |
| added overhead vs A (%) | +4.39 | +3.78 |
| collector CPU (ms/run) | 150.0 | 18.0 |
| collector context switches/run | 637 | 47 |
| events received/run | 3748 | 3751 |
| events persisted/run | 3014 | 2113 (lower bound: open/io/exec only) |
| kernel drops (sum) | 0 | 0 |
| userspace drops (sum) | 0 | 0 (no userspace queue) |
| store/ingest time (ms/run) | 33.09 | 5.22 (commit only) |
| query-visible records/run | 3014 | 2113 |

Paired differences (median ms, CI90):
- B_minus_A: +5.41 (+4.06..+6.47)
- N0_minus_A: +3.88 (+2.55..+4.87)
- E_minus_B: +0.04 (-0.95..+1.78)
- N1_minus_N0: +0.79 (-0.23..+1.65)
- N0_minus_B: -1.93 (-2.29..-0.61)
- E_minus_N1: +1.09 (+0.33..+1.58)
