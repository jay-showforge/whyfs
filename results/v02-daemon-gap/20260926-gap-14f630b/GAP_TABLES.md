## R: steady-state topology split (40 rotated rounds; per 300-process run)

| mode | configuration | wall ms | overhead % vs A (90% CI) |
|---|---|---|---|
| A | baseline | 125.5 | — |
| B | kernel only (separate agent, callback discards) | 128.9 | +3.05 (+1.23..+4.20) |
| C | in-process full collector | 131.1 | +4.45 (+3.32..+5.88) |
| D | separate process, processing, no SQLite | 131.3 | +5.10 (+3.57..+6.36) |
| E | separate process, production path (processing + SQLite) | 132.0 | +5.09 (+4.51..+5.97) |

| difference | ms per run (90% CI) |
|---|---|
| B − A | +3.91 (+1.55..+5.26) |
| D − B | +3.34 (+2.36..+4.01) |
| E − D | +0.95 (+0.11..+1.78) |
| E − A | +6.33 (+5.67..+7.54) |
| C − A | +5.59 (+4.14..+7.39) |
| E − C | +1.33 (-0.49..+2.54) |

Reconciliation: (B−A) + (D−B) + (E−D) = 8.21 ms vs measured E−A 6.33 ms → unexplained -1.88 ms (medians of paired differences are not additive; each CI is ±1–2 ms).

### OS-level metrics per run (medians)

| metric | A | B | C | D | E |
|---|---|---|---|---|---|
| wl_vol_ctx | 356 | 365 | 358 | 357 | 360 |
| wl_invol_ctx | 5.000 | 4.500 | 6.500 | 8.500 | 7.000 |
| wl_minflt | 22,830 | 22,828 | 22,834 | 22,825 | 22,830 |
| loop_shell_migrations | 0.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| collector_user_s | — | 0.020 | 0.090 | 0.100 | 0.100 |
| collector_sys_s | — | 0.060 | 0.080 | 0.095 | 0.080 |
| collector_vol_ctx | — | 98 | 2,178 | 3,300 | 2,118 |
| collector_invol_ctx | — | 0.000 | 1.000 | 1.000 | 2.000 |
| collector_minflt | — | 0.000 | 79 | 30 | 110 |
| collector_migrations | — | 1.000 | 30 | 47 | 26 |
| store_cpu_s | — | 0.000 | 0.020 | 0.000 | 0.020 |
| store_write_bytes | — | 0.000 | 7,237,632 | 0.000 | 7,485,440 |
| events_received | — | 0.000 | 3,748 | 3,748 | 3,748 |
| records_submitted | — | 0.000 | 3,014 | 3,014 | 3,014 |
| sqlite_ingest_ms | — | 0.000 | — | 0.000 | 44 |
| sqlite_rows | — | 0.000 | — | 0.000 | 3,014 |
| resolve_calls | — | 0.000 | — | 617 | 617 |
| canon_calls | — | 0.000 | — | 18 | 18 |
| kernel_drops | — | 0 | 0 | 0 | 0 |
| queue_drops | — | 0 | 0 | 0 | 0 |

BPF run time (phase S, agent, idle-subtracted): +3.27 (+3.13..+3.39) ms per run.

## F1: persistent real daemon, 25 consecutive runs, no restart (bpf_stats off)

Baseline median 126.5 ms (before 125.8, after 126.9); daemon start 2.57 s.

| run | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| overhead % | +4.2 | +4.3 | +6.9 | +5.1 | +5.6 | +6.0 | +9.0 | +3.2 | +6.1 | +4.7 | +5.2 | +3.7 | +3.3 | +13.8 | +8.5 | +2.0 | +5.0 | +5.8 | +6.2 | +3.1 | +5.0 | +3.8 | +7.2 | +6.3 | +5.3 |
| daemon minflt | 448 | 36 | 43 | 133 | 14 | 147 | 3 | 91 | 16 | 120 | 17 | 139 | 6 | 75 | 15 | 145 | 23 | 92 | 19 | 106 | 14 | 142 | 4 | 107 | 11 |

Median overhead: runs 1–5 +5.14%, runs 6–15 +5.61%, runs 16–25 +5.15%, all +5.17% (+6.54 ms). Drops: kernel 0, queue 0.

## F2: persistent real daemon, 25 consecutive runs, no restart (bpf_stats on)

Baseline median 125.7 ms (before 125.8, after 125.4); daemon start 2.57 s.

| run | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| overhead % | +3.9 | +31.7 | +3.5 | +6.3 | +7.0 | +5.5 | +8.2 | +7.1 | +8.3 | +6.4 | +8.1 | +3.8 | +10.3 | +8.1 | +9.7 | +8.4 | +2.2 | +6.9 | +6.2 | +7.9 | +6.3 | +12.2 | +11.8 | +12.9 | +12.2 |
| daemon minflt | 447 | 26 | 107 | 34 | 138 | 2 | 45 | 121 | 2 | 136 | 13 | 124 | 7 | 85 | 20 | 140 | 8 | 47 | 137 | 9 | 131 | 6 | 128 | 3 | 96 |
| BPF ms | 3.34 | 5.31 | 3.31 | 3.70 | 3.43 | 3.46 | 3.49 | 3.48 | 3.99 | 3.66 | 3.69 | 3.53 | 3.70 | 3.56 | 3.60 | 3.67 | 3.53 | 3.74 | 3.69 | 3.54 | 3.35 | 3.63 | 3.61 | 3.65 | 3.75 |

Median overhead: runs 1–5 +6.28%, runs 6–15 +8.11%, runs 16–25 +8.14%, all +7.91% (+9.94 ms). Drops: kernel 0, queue 0.

## G: harness pattern: fresh daemon per measured build (20 alternating pairs)

Measured build: +7.80 (+6.81..+9.88) % (+9.78 (+8.59..+12.49) ms). First build after start: +6.39 (+5.18..+8.91) %.

Pairs (%): +6.6, +11.2, +11.6, +9.9, +10.6, +10.2, +7.1, +6.8, +5.3, +8.4, +8.4, +4.3, +5.5, +15.6, +5.9, +6.7, +6.8, +9.8, +7.2, +18.3

## K: lifecycle control: daemon stopped before the measured build (20 alternating pairs)

Measured build: +0.63 (-0.66..+1.94) % (+0.79 (-0.84..+2.45) ms). First build after start: +7.36 (+6.51..+8.45) %.

Pairs (%): +0.6, +2.1, -6.0, +1.1, +1.0, -0.0, -1.1, +3.9, +2.8, -0.7, -4.4, -17.8, -4.2, +9.6, +0.6, -2.4, +4.2, +1.9, -0.2, +2.7

perf stat -a calibration: +4.94 (+3.07..+8.92) ms on the baseline loop → disabled for all phases.

