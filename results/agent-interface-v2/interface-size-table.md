| case | task class | pilot: WhyFS commands / bytes | old equivalent: calls / bytes | new `whyfs ask`: calls / bytes | reduction vs old equivalent | reduction vs pilot bytes |
|---|---|---:|---:|---:|---:|---:|
| case01 | generated-artifact | 0 / 0 | 2 / 11,724 | 1 / 347 | 97.0 % | n/a |
| case02 | generated-intermediate | 3 / 9,238 | 3 / 12,841 | 1 / 459 | 96.4 % | 95.0 % |
| case03 | dependency-impact | 3 / 9,125 | 1 / 879,135 | 1 / 1,469 | 99.8 % | 83.9 % |
| case04 | stale-output | 3 / 11,842 | 3 / 12,645 | 2 / 720 | 94.3 % | 93.9 % |
| case05 | agent-produced-files | 5 / 95,078 | 2 / 81,624 | 1 / 499 | 99.4 % | 99.5 % |
| case06 | rename-lineage | 3 / 11,101 | 2 / 12,257 | 1 / 343 | 97.2 % | 96.9 % |
| case07 | observation-gap | 10 / 22,441 | 2 / 3,195 | 1 / 313 | 90.2 % | 98.6 % |
| case08 | multiple-generators | 3 / 6,180 | 2 / 11,995 | 1 / 804 | 93.3 % | 87.0 % |
| case09 | downstream-safety | 3 / 8,465 | 2 / 11,511 | 1 / 590 | 94.9 % | 93.0 % |
| case10 | recent-build | 3 / 7,944 | 1 / 16,211 | 1 / 1,220 | 92.5 % | 84.6 % |
| **total** | | 181,414 | 1,053,138 | 6,764 | 99.4 % | 96.3 % |
