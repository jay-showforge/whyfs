| Metric | Python collector (E) | Native collector (NF) |
|---|---|---|
| workload wall time (ms, median) | 132.55 | 131.71 |
| added overhead vs A (ms, CI90) | +7.23 (+6.03..+8.61) | +5.91 (+5.14..+7.08) |
| added overhead vs A (%) | +5.75 | +4.76 |
| collector CPU (ms/run, all collector processes) | 150.0 | 90.0 |
| collector context switches/run | 494 | 136 |
| events received/run | 3748 | 3748 |
| events persisted/run | 3014 | 3014 |
| kernel drops (sum over runs) | 0 | 0 |
| userspace drops (sum over runs) | 0 | 0 |
| store/ingest time (ms/run) | 37.26 (ingest calls) | 20.0 (writer CPU) |
| query-visible records/run | 2714 | 2714 |

Paired differences (median ms, CI90):
- B-A: +4.33 (+3.25..+5.03)
- E-A: +7.23 (+6.03..+8.61)
- NF-A: +5.91 (+5.14..+7.08)
- E-B: +2.78 (+1.98..+3.94)
- NF-B: +2.64 (+0.48..+3.12)
- E-NF: +1.03 (-0.08..+1.98)
- K-A: +4.65 (+3.13..+5.20)
- NP-K: +0.65 (-1.54..+2.47)
- NF-NP: +1.31 (+0.12..+1.97)
- NF-K: +3.07 (+1.41..+4.03)
- B-K: -0.54 (-1.02..+0.82)
