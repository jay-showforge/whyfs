| Metric | Python collector (E) | Native collector (NF) |
|---|---|---|
| workload wall time (ms, median) | 133.53 | 132.72 |
| added overhead vs A (ms, CI90) | +7.77 (+6.11..+8.87) | +6.38 (+5.65..+7.17) |
| added overhead vs A (%) | +6.17 | +5.15 |
| collector CPU (ms/run, all collector processes) | 150.0 | 90.0 |
| collector context switches/run | 518 | 154 |
| events received/run | 3748 | 3748 |
| events persisted/run | 3014 | 3014 |
| kernel drops (sum over runs) | 0 | 0 |
| userspace drops (sum over runs) | 0 | 0 |
| store/ingest time (ms/run) | 37.83 (ingest calls) | 20.0 (writer CPU) |
| query-visible records/run | 2714 | 2714 |

Paired differences (median ms, CI90):
- B-A: +6.65 (+3.75..+7.35)
- E-A: +7.77 (+6.11..+8.87)
- NF-A: +6.38 (+5.65..+7.17)
- E-B: +1.28 (+0.74..+2.99)
- NF-B: +1.68 (-0.71..+3.00)
- E-NF: +0.98 (-0.52..+2.66)
