## Timing (production build, shell-timed loop)

| | value |
|---|---|
| alternating pairs | 20 (after 2 warm-up pairs) |
| baseline / monitored median | 127.9 ms / 135.0 ms |
| median paired overhead | 5.52% (90% CI 3.37..7.25; IQR 1.93..9.81) |
| median paired delta | 7.06 ms/run = 23.5 µs/process |
| same pairs, Python-side timing | 5.27% |
| first build after load | 131.9 ms |
| events received / filtered per run | 3064 / 346 |
| collector CPU / store-worker CPU per run | 96 ms / 20 ms |
| kernel drops / queue drops | 0 / 0 |
| BPF run time (production, bpf_stats) | 2.99 ms/run = 9.96 µs/process |

## Per-hook (per 300-process run; counts from WF_PROFILE build, run time from production build)

| hook | calls (window) | calls (idle-adj.) | early exits | lookups | updates | deletes | rb records | rb bytes | upid walks | BPF µs | ns/call | % BPF | ablation body ms (90% CI) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| security_file_open | 1398 | 1384 | 306 | 0 | 0 | 1077 | 1077 | 637584 | 305 | 1258 | 910 | 42.1% | -0.08 (90% CI -0.76..+0.85) inconclusive |
| security_file_permission | 3992 | 3963 | 2676 | 3914 | 980 | 0 | 980 | 78400 | 305 | 890 | 277 | 29.8% | +0.53 (90% CI -0.51..+1.77) inconclusive |
| sched_process_fork | 305 | 305 | 0 | 0 | 0 | 0 | 305 | 24400 | 305 | 287 | 942 | 9.6% | +0.30 (90% CI -1.49..+1.47) inconclusive |
| sched_process_exec | 306 | 306 | 0 | 0 | 0 | 0 | 306 | 337824 | 306 | 248 | 812 | 8.3% | -0.27 (90% CI -1.30..+2.22) inconclusive |
| security_mmap_file | 1466 | 1466 | 1377 | 1441 | 89 | 0 | 89 | 7120 | 0 | 198 | 135 | 6.6% | -1.00 (90% CI -2.39..+0.82) inconclusive |
| sched_process_exit | 305 | 305 | 0 | 0 | 0 | 0 | 305 | 24400 | 0 | 92 | 301 | 3.1% | -0.90 (90% CI -1.71..+0.33) inconclusive |
| sys_exit_chdir | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 9 | 4718 | 0.3% | — |
| sys_enter_chdir | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 7 | 3263 | 0.2% | — |

## Section times inside programs (WF_PROFILE_TIME build; approximate, per run)

| hook | namespace translation | bpf_d_path | io_seen map ops | ring buffer | exec copies |
|---|---|---|---|---|---|
| security_file_open | 214 µs (155 ns × 1383) | 260 µs (241 ns × 1077) | 453 µs (421 ns × 1077) | 299 µs (278 ns × 1077) | — |
| security_file_permission | 108 µs (84 ns × 1286) | — | 643 µs (116 ns × 5555) | 128 µs (130 ns × 980) | — |
| security_mmap_file | 4 µs (43 ns × 89) | — | 106 µs (69 ns × 1530) | 11 µs (123 ns × 89) | — |
| sched_process_exec | 91 µs (298 ns × 306) | — | — | 76 µs (247 ns × 306) | 84 µs (276 ns × 306) |
| sched_process_fork | 92 µs (302 ns × 305) | — | — | 145 µs (475 ns × 305) | — |
| sched_process_exit | 23 µs (75 ns × 305) | — | — | 40 µs (131 ns × 305) | — |

## Foreign-task (out-of-namespace) invocations

| hook | invocations/run | upid walks/run | est. ns/call | est. µs/run | events emitted |
|---|---|---|---|---|---|
| security_file_open | 306 | 306 | 436 | 133 | 0 |
| security_file_permission | 306 | 306 | 230 | 70 | 0 |

Total ≈ 204 µs/run = 6.8% of BPF run time, 2.9% of the measured wall overhead.

## Hook-body ablation (WF_NULL_MASK; rotated baseline/normal/nulled rounds, shell-timed)

| variant | normal − base ms | normal − nulled ms | nulled − base ms | calls/run | body ns/call (90% CI) | conclusive |
|---|---|---|---|---|---|---|
| null_all (n=40) | +2.18 (90% CI +1.41..+3.62) | +2.83 (90% CI +1.53..+3.93) | -0.23 (90% CI -1.71..+0.97) | all | n/a | yes |
| security_file_open (n=40) | +3.00 (90% CI +2.10..+4.36) | -0.08 (90% CI -0.76..+0.85) | +2.71 (90% CI +1.93..+4.02) | 1383.5 | -60 (-549..616) | no |
| security_file_permission (n=40) | +3.87 (90% CI +2.11..+4.49) | +0.53 (90% CI -0.51..+1.77) | +2.05 (90% CI +1.39..+2.74) | 3963.0 | 133 (-129..446) | no |
| security_mmap_file (n=40) | +3.87 (90% CI +3.46..+5.08) | -1.00 (90% CI -2.39..+0.82) | +3.97 (90% CI +3.37..+5.68) | 1466.0 | -683 (-1631..563) | no |
| sched_process_exec (n=40) | +3.38 (90% CI +2.46..+4.34) | -0.27 (90% CI -1.30..+2.22) | +1.72 (90% CI +0.98..+3.50) | 306.0 | -889 (-4253..7256) | no |
| sched_process_fork (n=40) | +2.50 (90% CI +1.58..+4.47) | +0.30 (90% CI -1.49..+1.47) | +2.71 (90% CI +1.35..+3.97) | 305.0 | 969 (-4876..4803) | no |
| sched_process_exit (n=40) | +4.59 (90% CI +2.11..+5.28) | -0.90 (90% CI -1.71..+0.33) | +3.50 (90% CI +2.35..+5.18) | 305.0 | -2950 (-5593..1068) | no |

## Userspace split (phase U; rotated rounds, shell-timed)

| comparison | ms per run |
|---|---|
| kernel − base | +4.64 (90% CI +3.63..+5.94) |
| nostore − kernel | +4.73 (90% CI +4.29..+5.28) |
| full − nostore | +1.12 (90% CI +0.43..+1.96) |
| full − kernel | +5.37 (90% CI +4.42..+6.35) |
| full − base | +10.72 (90% CI +9.84..+11.81) |
| collector CPU per run (base/kernel/no_store/full) | 2 ms / 48 ms / 193 ms / 147 ms |

## Mechanism (phase V; burn = callback discards, a Python thread spins during the run)

| comparison | ms per run |
|---|---|
| kernel − base | +3.82 (90% CI +3.24..+4.34) |
| nostore − kernel | +5.44 (90% CI +3.00..+6.52) |
| burn − kernel | +0.50 (90% CI -0.45..+1.85) |
| nostore − burn | +4.25 (90% CI +3.34..+5.35) |

Callback time per event type (no_store mode):

| event | per run | µs/event | ms/run |
|---|---|---|---|
| exec | 310 | 108.1 | 33.55 |
| open | 1264 | 24.4 | 30.84 |
| unlink | 300 | 84.7 | 25.40 |
| read | 793 | 14.5 | 11.47 |
| write | 300 | 14.4 | 4.33 |
| fork | 307 | 6.9 | 2.12 |
| exit | 307 | 4.1 | 1.25 |
| mmap_read | 156 | 2.2 | 0.34 |
| chdir | 4 | 32.0 | 0.13 |

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
