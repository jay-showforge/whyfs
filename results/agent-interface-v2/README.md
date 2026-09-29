# Agent interface v2: evidence

Development branch `agent-interface-v2`, based on `main` 7c47434 (WhyFS 1.0.0 published as
`v1.0.0` = f6c6010; neither is changed here).  Separate from the macOS work.

- [DIAGNOSIS.md](DIAGNOSIS.md): why the frozen agent-efficiency pilot was NEGATIVE for WhyFS,
  from its own transcripts (`benchmark-whyfs-calls.json`, made by `scripts/profile_agent_benchmark.py`).
- `interface-size.json`, `interface-size-table.md`: the interface-output comparison below
  (`scripts/agent_interface_size.py`).

## Interface output on the pilot's own fixtures

**This measures bytes of WhyFS command output, not tokens and not agent efficiency.**  Whether
the smaller interface changes what a coding agent spends is for the frozen A/B benchmark to
measure; nothing here is a claim about it.

Method: one read-only copy of the WSL machine store that recorded the pilot (so old and new see
identical evidence; it also holds the pilot agents' own later activity), the benchmark user's
view (`uid:1001`), the pilot's scenario directories.  "Old equivalent": the existing JSON answers
for the task's question as the existing commands print them (`whyfs label/why/impact/recent
--json`, `whyfs api list_agent_sessions`).  "New": the `whyfs ask` answer(s) as `whyfs ask`
prints them.  "Pilot": the WhyFS calls and bytes the pilot's treatment transcripts actually show
(including `--help`).

| case | task class | pilot: WhyFS commands / bytes | old equivalent: calls / bytes | new `whyfs ask`: calls / bytes | reduction vs old equivalent | reduction vs pilot bytes |
|---|---|---:|---:|---:|---:|---:|
| case01 | generated-artifact | 0 / 0 | 2 / 11,724 | 1 / 347 | 97.0 % | n/a (WhyFS unused) |
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

Discovery: `whyfs --help` is 2,444 bytes (it now names `whyfs ask` first); `whyfs ask` lists the
questions in 724 bytes.

Caveats: the old-equivalent case 3 answer (`impact`) is large because the store now also holds
the pilot agents' own later activity (a Codex process read the file and wrote hundreds of its
own state files); the new answer counts those under `broad_readers` instead of listing them.
The pilot's own bytes were measured before that activity.  Both columns are shown for that
reason.

## Tests

- `PYTHONPATH=src:tests python3 -m unittest tests.test_ask` (21 tests: the ten task classes,
  identity mismatch, registered vs detected agents, visibility, determinism, bounded lists,
  broad readers, build grouping, API, CLI) -- Linux (WSL2) OK; Windows (CPython 3.13) OK.
- `PYTHONPATH=src:tests python3 -m unittest discover -s tests` -- Linux (as a normal user):
  275 tests OK, 80 skipped (root-only live eBPF and Windows-only tests); Windows: 135 tests OK,
  37 skipped (Linux-only tests).  The same suites on unmodified `main` 7c47434 give the same
  results for every existing test.
