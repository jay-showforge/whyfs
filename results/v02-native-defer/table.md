| Metric | Python collector (E) | Native collector (NF) |
|---|---|---|
| workload wall time (ms, median) | 134.44 | 132.58 |
| added overhead vs A (ms, CI90) | +7.32 (+5.48..+8.19) | +5.64 (+4.56..+6.49) |
| added overhead vs A (%) | +5.74 | +4.41 |
| collector CPU (ms/run, all collector processes) | 130.0 | 60.0 |
| collector context switches/run | 598 | 152 |
| events received/run | 3748 | 3748 |
| events persisted/run | 3014 | 3014 |
| kernel drops (sum over runs) | 0 | 0 |
| userspace drops (sum over runs) | 0 | 0 |
| store/ingest time (ms/run) | 38.79 (ingest calls) | 20.0 (writer CPU) |
| query-visible records/run | 2714 | 2714 |

Paired differences (median ms, CI90):
- B-A: +5.38 (+4.35..+6.68)
- E-A: +7.32 (+5.48..+8.19)
- NF-A: +5.64 (+4.56..+6.49)
- E-B: +2.03 (+0.50..+3.24)
- NF-B: -0.71 (-1.71..+0.97)
- E-NF: +2.18 (+1.49..+2.83)
- K-A: +4.67 (+3.52..+6.08)
- NP-K: +0.91 (-1.48..+1.64)
- NF-NP: -0.01 (-1.88..+1.93)
- NF-K: +0.69 (-0.28..+1.45)
- B-K: +0.96 (-0.71..+2.13)
- NI-A: +5.38 (+3.76..+7.20)
- NI-NP: -0.05 (-1.30..+1.29)
- NI-NF: +0.51 (-1.04..+1.21)
