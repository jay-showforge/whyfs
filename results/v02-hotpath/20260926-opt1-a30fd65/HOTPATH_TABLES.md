## Timing (production build, shell-timed loop)

| | value |
|---|---|
| alternating pairs | 20 (after 2 warm-up pairs) |
| baseline / monitored median | 125.8 ms / 131.0 ms |
| median paired overhead | 3.86% (90% CI 2.00..6.46; IQR -0.47..6.83) |
| median paired delta | 4.77 ms/run = 15.9 µs/process |
| same pairs, Python-side timing | 2.24% |
| first build after load | 129.9 ms |
| events received / filtered per run | 3064 / 346 |
| collector CPU / store-worker CPU per run | 86 ms / 20 ms |
| kernel drops / queue drops | 0 / 0 |
| BPF run time (production, bpf_stats) | 2.93 ms/run = 9.77 µs/process |

## Per-hook (per 300-process run; counts from WF_PROFILE build, run time from production build)

| hook | calls (window) | calls (idle-adj.) | early exits | lookups | updates | deletes | rb records | rb bytes | upid walks | BPF µs | ns/call | % BPF | ablation body ms (90% CI) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| security_file_open | 1398 | 1383 | 306 | 0 | 0 | 1077 | 1077 | 637584 | 305 | 1259 | 912 | 43.0% | +2.63 (90% CI +1.43..+3.26) |
| security_file_permission | 3992 | 3962 | 2674 | 3914 | 980 | 0 | 980 | 78400 | 305 | 838 | 240 | 28.6% | +0.15 (90% CI -0.65..+1.90) inconclusive |
| sched_process_fork | 305 | 305 | 0 | 0 | 0 | 0 | 305 | 24400 | 305 | 278 | 912 | 9.5% | +1.54 (90% CI -0.15..+2.47) inconclusive |
| sched_process_exec | 306 | 306 | 0 | 0 | 0 | 0 | 306 | 337824 | 306 | 248 | 809 | 8.5% | +1.11 (90% CI -0.20..+2.49) inconclusive |
| security_mmap_file | 1466 | 1466 | 1377 | 1441 | 89 | 0 | 89 | 7120 | 0 | 199 | 136 | 6.8% | -0.33 (90% CI -1.23..+1.51) inconclusive |
| sched_process_exit | 305 | 305 | 0 | 0 | 0 | 0 | 305 | 24400 | 0 | 89 | 291 | 3.0% | -0.21 (90% CI -1.72..+0.79) inconclusive |
| sys_exit_chdir | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 11 | 5697 | 0.4% | — |
| sys_enter_chdir | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 8 | 3924 | 0.3% | — |

## Section times inside programs (WF_PROFILE_TIME build; approximate, per run)

| hook | namespace translation | bpf_d_path | io_seen map ops | ring buffer | exec copies |
|---|---|---|---|---|---|
| security_file_open | 203 µs (147 ns × 1384) | 276 µs (256 ns × 1077) | 431 µs (400 ns × 1077) | 314 µs (292 ns × 1077) | — |
| security_file_permission | 109 µs (84 ns × 1288) | — | 601 µs (108 ns × 5542) | 130 µs (133 ns × 980) | — |
| security_mmap_file | 5 µs (51 ns × 89) | — | 112 µs (73 ns × 1530) | 12 µs (139 ns × 89) | — |
| sched_process_exec | 91 µs (298 ns × 306) | — | — | 79 µs (259 ns × 306) | 87 µs (285 ns × 306) |
| sched_process_fork | 91 µs (298 ns × 305) | — | — | 132 µs (432 ns × 305) | — |
| sched_process_exit | 24 µs (78 ns × 305) | — | — | 39 µs (129 ns × 305) | — |

## Foreign-task (out-of-namespace) invocations

| hook | invocations/run | upid walks/run | est. ns/call | est. µs/run | events emitted |
|---|---|---|---|---|---|
| security_file_open | 307 | 307 | 387 | 119 | 0 |
| security_file_permission | 308 | 308 | 212 | 65 | 0 |

Total ≈ 184 µs/run = 6.3% of BPF run time, 3.9% of the measured wall overhead.

## Hook-body ablation (WF_NULL_MASK; rotated baseline/normal/nulled rounds, shell-timed)

| variant | normal − base ms | normal − nulled ms | nulled − base ms | calls/run | body ns/call (90% CI) | conclusive |
|---|---|---|---|---|---|---|
| null_all (n=40) | +2.75 (90% CI +1.29..+4.18) | +4.24 (90% CI +2.28..+4.96) | -0.90 (90% CI -1.72..+0.90) | all | n/a | yes |
| security_file_open (n=40) | +4.94 (90% CI +3.87..+5.55) | +2.63 (90% CI +1.43..+3.26) | +2.52 (90% CI +1.79..+2.97) | 1383.0 | 1900 (1032..2354) | yes |
| security_file_permission (n=40) | +3.97 (90% CI +1.60..+4.64) | +0.15 (90% CI -0.65..+1.90) | +2.83 (90% CI +1.59..+4.11) | 3962.5 | 38 (-164..478) | no |
| security_mmap_file (n=40) | +3.82 (90% CI +2.82..+4.19) | -0.33 (90% CI -1.23..+1.51) | +3.01 (90% CI +1.66..+4.23) | 1466.0 | -224 (-840..1027) | no |
| sched_process_exec (n=40) | +4.58 (90% CI +3.26..+6.63) | +1.11 (90% CI -0.20..+2.49) | +2.96 (90% CI +1.56..+3.84) | 306.0 | 3642 (-641..8139) | no |
| sched_process_fork (n=40) | +4.30 (90% CI +3.19..+6.41) | +1.54 (90% CI -0.15..+2.47) | +3.53 (90% CI +1.37..+5.72) | 305.0 | 5053 (-488..8094) | no |
| sched_process_exit (n=40) | +4.33 (90% CI +2.22..+5.50) | -0.21 (90% CI -1.72..+0.79) | +3.57 (90% CI +2.04..+4.87) | 305.0 | -690 (-5648..2577) | no |

## Userspace split (phase U; rotated rounds, shell-timed)

| comparison | ms per run |
|---|---|
| kernel − base | +4.55 (90% CI +3.39..+6.00) |
| nostore − kernel | +2.13 (90% CI +1.08..+2.87) |
| full − nostore | +1.26 (90% CI +0.30..+2.90) |
| full − kernel | +3.32 (90% CI +2.07..+5.16) |
| full − base | +7.72 (90% CI +6.58..+8.41) |
| collector CPU per run (base/kernel/no_store/full) | 2 ms / 46 ms / 159 ms / 128 ms |

## Mechanism (phase V; burn = callback discards, a Python thread spins during the run)

| comparison | ms per run |
|---|---|
| kernel − base | +4.30 (90% CI +2.76..+5.37) |
| nostore − kernel | +2.57 (90% CI +2.00..+4.32) |
| burn − kernel | +1.39 (90% CI -0.17..+3.24) |
| nostore − burn | +1.35 (90% CI +0.42..+2.89) |

Callback time per event type (no_store mode):

| event | per run | µs/event | ms/run |
|---|---|---|---|
| open | 1214 | 24.2 | 29.33 |
| exec | 310 | 53.1 | 16.47 |
| read | 749 | 15.1 | 11.31 |
| unlink | 300 | 19.1 | 5.73 |
| write | 300 | 14.4 | 4.32 |
| fork | 307 | 6.9 | 2.11 |
| exit | 307 | 4.1 | 1.25 |
| mmap_read | 150 | 2.1 | 0.31 |
| chdir | 4 | 69.3 | 0.28 |

## realpath/lstat mechanism (phase X; rotated rounds, shell-timed)

| comparison | ms per run |
|---|---|
| kernel − base | +4.04 (90% CI +2.49..+6.89) |
| nostore − kernel | +2.07 (90% CI +1.57..+2.97) |
| canon_only − kernel | +0.37 (90% CI -1.61..+1.76) |
| nostore_nocanon − kernel | +1.50 (90% CI +0.07..+3.30) |
| nostore − nostore_nocanon | -0.11 (90% CI -1.57..+0.53) |

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
