## Timing (production build, shell-timed loop)

| | value |
|---|---|
| alternating pairs | 20 (after 2 warm-up pairs) |
| baseline / monitored median | 135.0 ms / 143.5 ms |
| median paired overhead | 6.24% (90% CI 4.37..12.35; IQR 2.05..12.78) |
| median paired delta | 8.49 ms/run = 28.3 µs/process |
| same pairs, Python-side timing | 0.00% |
| first build after load | 138.8 ms |
| events received / filtered per run | 2980 / 268 |
| collector CPU / store-worker CPU per run | 89 ms / 20 ms |
| kernel drops / queue drops | 0 / 0 |
| BPF run time (production, bpf_stats) | 2.90 ms/run = 9.68 µs/process |

## Per-hook (per 300-process run; counts from WF_PROFILE build, run time from production build)

| hook | calls (window) | calls (idle-adj.) | early exits | lookups | updates | deletes | rb records | rb bytes | upid walks | BPF µs | ns/call | % BPF | ablation body ms (90% CI) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| security_file_open | 1358 | 1344 | 307 | 0 | 0 | 1037 | 1037 | 613904 | 306 | 1190 | 887 | 41.0% | +0.91 (90% CI -0.14..+1.93) inconclusive |
| security_file_permission | 3422 | 3392 | 2116 | 3332 | 970 | 0 | 970 | 77600 | 308 | 869 | 293 | 29.9% | -0.10 (90% CI -1.35..+1.33) inconclusive |
| sched_process_fork | 303 | 303 | 0 | 0 | 0 | 0 | 303 | 24240 | 303 | 288 | 950 | 9.9% | +0.62 (90% CI -0.29..+1.46) inconclusive |
| sched_process_exec | 304 | 304 | 0 | 0 | 0 | 0 | 304 | 335616 | 304 | 250 | 822 | 8.6% | +2.44 (90% CI -0.57..+4.06) inconclusive |
| security_mmap_file | 1408 | 1408 | 1347 | 1389 | 61 | 0 | 61 | 4880 | 0 | 204 | 145 | 7.0% | -1.05 (90% CI -1.65..-0.11) |
| sched_process_exit | 303 | 303 | 0 | 0 | 0 | 0 | 303 | 24240 | 0 | 86 | 282 | 2.9% | -1.32 (90% CI -1.92..-0.59) |
| sys_exit_chdir | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 11 | 5563 | 0.4% | — |
| sys_enter_chdir | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 7 | 3533 | 0.2% | — |

## Hook-body ablation (WF_NULL_MASK; rotated baseline/normal/nulled rounds, shell-timed)

| variant | normal − base ms | normal − nulled ms | nulled − base ms | calls/run | body ns/call (90% CI) | conclusive |
|---|---|---|---|---|---|---|
| null_all (n=40) | +2.96 (90% CI +1.93..+3.59) | +3.11 (90% CI +2.49..+4.91) | +0.18 (90% CI -1.12..+0.63) | all | n/a | yes |
| security_file_open (n=40) | +3.24 (90% CI +2.21..+4.68) | +0.91 (90% CI -0.14..+1.93) | +2.50 (90% CI +1.57..+3.36) | 1344.0 | 677 (-103..1434) | no |
| security_file_permission (n=40) | +3.18 (90% CI +1.67..+4.78) | -0.10 (90% CI -1.35..+1.33) | +2.06 (90% CI +1.39..+4.56) | 3391.5 | -31 (-398..391) | no |
| security_mmap_file (n=40) | +2.75 (90% CI +1.89..+3.39) | -1.05 (90% CI -1.65..-0.11) | +3.21 (90% CI +2.34..+4.62) | 1408.0 | -749 (-1169..-80) | yes |
| sched_process_exec (n=40) | +4.47 (90% CI +3.65..+6.20) | +2.44 (90% CI -0.57..+4.06) | +2.70 (90% CI +1.57..+6.13) | 304.0 | 8040 (-1864..13371) | no |
| sched_process_fork (n=40) | +3.49 (90% CI +2.66..+4.17) | +0.62 (90% CI -0.29..+1.46) | +2.91 (90% CI +1.53..+3.46) | 303.0 | 2039 (-974..4810) | no |
| sched_process_exit (n=40) | +2.62 (90% CI +1.36..+4.34) | -1.32 (90% CI -1.92..-0.59) | +4.73 (90% CI +2.79..+5.20) | 303.0 | -4342 (-6330..-1941) | yes |

## Consistency checks

| check | result |
|---|---|
| open: records == deletes | True |
| open: calls == early_exits + records | True |
| perm: updates == records | True |
| mmap: updates == records | True |
| fork/exec/exit ~ processes | True |
| production timing built without WF_PROFILE | True |
| idle windows subtracted | True |
| ablation rounds per variant | {'null_all': 40, 'security_file_open': 40, 'security_file_permission': 40, 'security_mmap_file': 40, 'sched_process_exec': 40, 'sched_process_fork': 40, 'sched_process_exit': 40} |
| timing pairs (excluding warm-up) | 20 |
| kernel drops | 0 |
| queue drops | 0 |
