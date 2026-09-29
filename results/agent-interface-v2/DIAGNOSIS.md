# Agent interface: diagnosis of the negative agent-efficiency pilot

Source (read-only, unchanged): `C:\Users\ftmon\Downloads\githubtestwhyfs\results\agent-efficiency-pilot`
(REPORT.md sha256 `44bfd9e1…821e9`, summary.json sha256 `38bc193a…d122af`).  Verdict there:
**NEGATIVE** (+31.71 % tokens, +28.57 % tool calls, +471.74 % command-output bytes, +24.25 %
wall time; correctness 10/10 in both conditions).  That verdict stands; nothing here re-grades it.

Derived data: `benchmark-whyfs-calls.json` (every WhyFS command in the ten treatment transcripts,
with the bytes it returned), produced by `scripts/profile_agent_benchmark.py`.

## What the agent had

The treatment prompt said only "WhyFS is installed and available as a local provenance tool if
you decide it is useful."  So everything the agent learned about how to ask came from WhyFS
itself: `whyfs --help`, then subcommand help, then trial calls.

## WhyFS bytes returned per treatment case

| case | WhyFS commands | bytes | what happened |
|---|---:|---:|---|
| 01 generated artifact | 0 | 0 | WhyFS not used |
| 02 multi-step generated | 3 | 9,238 | help 3.2 KB; `why` per hop by hand (two calls for a two-stage chain); `impact` of the source dominated by `.git/index` lines |
| 03 dependency impact | 3 | 9,125 | help 2.9 KB; **one** `impact` call answered the question (5.9 KB, mostly `.git` bookkeeping) |
| 04 stale output | 3 | 11,842 | help 3.1 KB; `why`+`history` for three files at once (7.1 KB); history lines repeat 250-byte setup command lines |
| 05 agent-produced files | 5 | **95,078** | help 2.4 KB; 3 subcommand helps; `api list_agent_sessions` **72.8 KB** (every detected Codex session on the machine); four full `label --json` **16.9 KB**; the decisive `recent --under work` 1.5 KB came last |
| 06 rename lineage | 3 | 11,101 | help 3.1 KB; `status`+`why`+`history`+`impact` stacked (6.8 KB) |
| 07 unknown origin | **10** | 22,441 | help 4.6 KB; `why --json` → `null`, `history --json` → `[]` (no reason given); the full label had the answer but its history was the agent's own reads (`xxd`, `sha256sum`); then time-window searches and a 13.6 KB `recent` of the agent's own `.git` churn |
| 08 multiple generators | 3 | 6,180 | help 3.3 KB; `why`+`history`: the answer was the writer's command line (`tools/…`) |
| 09 downstream safety | 3 | 8,465 | help 3.2 KB; `status`+`why`+`history`+`impact`+`label` stacked |
| 10 recent build | 3 | 7,944 | help 4.4 KB; `status`+`recent`+`why`×4, then `why`×3+`history`×2 |

Operations: why 26, history 12, --help 9, impact 7, recent 6, status 5, label 5, search 4, api 1.

## Causes

1. **Discovery costs a call per run.**  `whyfs --help` (2.4–4.6 KB, 19 subcommands including
   internal ones) ran in 9 of 10 runs, often followed by subcommand help.  Nothing in it says
   which command answers an agent's question.
2. **One decision = several operations.**  The questions were "what should I edit", "what
   depends on this", "who made these", "can I trust this".  The interface offers the
   evidence views (`why`, `history`, `impact`, `label`, `recent`, `search`), so the agent joins
   them itself, one hop at a time (case 2 walked a two-stage chain with two `why` calls; cases 4,
   6, 9 and 10 stacked 4–7 calls in one command).
3. **Negative answers carry no reason.**  `why --json` prints `null` and `history` `[]` for a
   file whose origin was not observed.  The decisive facts (not observed; incomplete; no
   attribution justified) existed only in the full label, so the agent kept searching (case 7:
   ten WhyFS commands for one "can this be trusted" decision).
4. **No task-level session query.**  To find "the files of the 'Dependency audit' task", the
   agent had to list every session on the machine (`search --session` needs an id) and read
   whole labels to see the task text (case 5: 90 KB of the 95 KB).
5. **The agent's own activity is the bulk of what comes back.**  History lists the agent's own
   reads (`sed`, `xxd`, `sha256sum`); `impact` and `recent` list `.git/index`, `.git/index.lock`
   and `COMMIT_EDITMSG` written by the agent's own `git status`/`git diff` after reading the
   file.  These are true observations, but they are not answers to the question.
6. **Every line repeats absolute paths and full command lines** (a 90-byte workspace prefix;
   setup command lines of 250 bytes), in human prose and in JSON.

## Why case 3 worked

Its question ("what may be affected") maps one-to-one to an existing operation (`impact`), which
answers it in one call, at the first attempt, and the answer (three outputs) matched what the
build script showed.  It still paid 2.9 KB of help and ~4 KB of `.git` lines.

## Why cases 5 and 7 did not

- **Case 5**: the task text is the stable key the agent had; no operation filters by it, and the
  only session listing is machine-wide and unfiltered (72.8 KB).  The smallest sufficient answer:
  the sessions whose supplied task matches, and the files each wrote under `work/` (plus which
  other writers touched `work/`): a few hundred bytes.
- **Case 7**: the smallest sufficient answer was known at the first call:
  `{"status": "unknown", "reason": "no observed write", "attributable": false}` with the recording
  window.  The interface returned `null`.

## Hypothesis to test (not yet proven)

A compact, task-oriented machine interface -- one question, one small structured answer that
keeps every qualifier -- removes causes 1-6 without changing the evidence.  Its size effect is
measured on the benchmark's fixtures (interface bytes only); agent efficiency is for the frozen
benchmark to judge.
