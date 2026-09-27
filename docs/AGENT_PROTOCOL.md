# whyfs local API and agent-session protocol (`whyfs-api/1`)

Software agents, and any other program, use one local interface to ask the whyfs service
about files and to tell it about agent sessions.  It is local only:
- no network listener;
- no account;
- no cloud;
- no telemetry.

## Transport

| Platform | Endpoint | Who is asking |
|---|---|---|
| Linux / WSL2 | Unix socket `/run/whyfs/api.sock` (directory root-owned) | the peer's uid (`SO_PEERCRED`) |
| Windows | named pipe `\\.\pipe\whyfs-api` | the client's token (impersonation) |

Each connection carries one or more requests, one JSON object per line; each reply is one
line.

```json
{"v": 1, "op": "explain_file", "params": {"path": "/home/jay/app/dist/app.js"}}
{"v": 1, "ok": true, "result": {"label": {...}, "text": "File: ..."}}
{"v": 1, "ok": false, "error": "path must be absolute (clients resolve it against their own working directory)"}
```

- `v` is the protocol version.  A service that does not speak it answers with an error; it
  never guesses.  New fields may appear in results within version 1, and clients ignore
  fields they do not know.
- Paths must be absolute: the client resolves relative paths against its own directory.

**Authentication and visibility.**  The service identifies the requester from the OS, never
from the request.
- A normal user sees the evidence of their own processes only.
- root, or an **elevated** Windows administrator, sees everything.  An unelevated
  administrator is a normal user.
- Records of other users' processes are invisible: a file written by someone else reads as
  `no-record`.

**Clients verify the service.**
- Linux: the socket lives in a root-owned, non-writable directory.
- Windows: the client checks that the pipe object is owned by SYSTEM or Administrators, which
  an ordinary user cannot arrange.  A squatted pipe name is refused.

## Operations

| Op | Params | Result |
|---|---|---|
| `explain_file` | `path` | `{"label": <label>, "text": <human label>}` |
| `get_file_provenance` | `path`, `include_noise?` | the label (below) |
| `get_file_history` | `path`, `limit?` | writes, moves, deletes, and the first read by each other process; newest first |
| `get_file_inputs` | `path` | creator, `inputs`, `inputs_via_temporaries`, `hidden_input_count`, `shared_by_outputs` |
| `get_file_dependents` | `path`, `depth?` | downstream edges `{from, to, exe, run_id, shared}` |
| `get_recent_changes` | `since_ns?` (default 24 h), `limit?`, `path_prefix?` | newest change per file, with its agent session if any |
| `search_files` | any of `name`, `path`, `creator`, `user`, `agent`, `session_id`, `since_ns`, `until_ns`, `action` (`any`/`created`/`changed`/`deleted`), `limit?` | one row per file, newest activity first: `path`, `last_action`, `at`, `exe`, `user_name`, `agent`, `first_observed`, `created_in_range`, `exists` |
| `list_agent_sessions` | `agent?`, `since_ns?`, `limit?` | registered sessions and detected agent process trees (one per process instance), newest first |
| `get_agent_session` | `session_id` | the session, with its root process(es) |
| `get_files_by_agent` | `session_id`, `limit?` | files written, moved or deleted by the session's process tree during the session |
| `session_start` | `agent_name`, `agent_version?`, `session_id?`, `root_pid?`, `workspace?`, `task?` | `{session_id, started_ns, root_pid}` |
| `session_end` | `session_id` | `{session_id, ended_ns}` |
| `why` / `history` / `impact` | `path` … | the JSON of `whyfs why/history/impact --json` |
| `status` | — | collector state, `collector_ready`, loss counters, store size, retention policy, scope rules, your view |
| `forget` | `path` or `everything: true` | deletes records: your own, or anyone's for an administrator |

## The label (`whyfs-label/1`)

```json
{
  "schema": "whyfs-label/1",
  "path": "C:\\Projects\\App\\dist\\app.js",
  "exists": true,
  "status": "labelled",
  "created": "2026-09-27T14:43:10-07:00",
  "last_written": "2026-09-27T14:43:10-07:00",
  "user": "S-1-5-21-...-1003",
  "user_name": "HOST\\jay",
  "created_by": {"exe": "C:\\...\\node.exe", "pid": 4121, "command": "node node_modules/vite/bin/vite.js build", "cwd": "..."},
  "process_chain": [
    {"exe": "...\\claude.exe", "pid": 3002},
    {"exe": "...\\powershell.exe", "pid": 3310},
    {"exe": "...\\node.exe", "pid": 4121}
  ],
  "agent": {"agent_name": "Claude Code", "agent_version": "2.1.281", "session_id": "...", "source": "registered",
            "confidence": "registered: the local service verified that the requester owns the root process", "...": "..."},
  "intent": {"task": "Build checkout redesign",
             "source": "supplied by the agent session ... when it registered (not verified by whyfs)"},
  "causal_why": "app.js exists because node.exe wrote it after reading main.ts, api.ts, vite.config.ts.",
  "inputs": ["...\\src\\main.ts", "...\\src\\api.ts", "...\\vite.config.ts"],
  "renamed_from": [],
  "history": [{"at": "...", "action": "written", "exe": "..."}],
  "dependents": [{"from": "...", "to": "...", "exe": "...", "shared": 0}],
  "impact": {"generated_outputs": ["..."], "possibly_affected": [], "readers": [{"exe": "...", "processes": 1}],
             "is_generated": true, "no_observed_dependents": false,
             "summary": "2 files were observed being generated from this file ...; changing or removing it may affect them ..."},
  "observation": {"complete": false, "observing_since": "...",
                  "gaps": ["whyfs was not recording from ... to ..."]},
  "identity": {"current": "win:...", "recorded": "win:...", "check": "match"},
  "evidence": "OS-observed + registered agent context"
}
```

`status` is one of:

| Status | Meaning |
|---|---|
| `labelled` | an observed origin |
| `no-record` | nothing observed that you may see |
| `not-observed` | whyfs saw a *previous* file at this path; the file there now was never seen being written.  Its old record is reported only as `previous_file_at_path`; whyfs never attaches an old record to a new file |

Two kinds of "why" are kept apart:
- **`causal_why`** is derived from observed activity.
- **`intent`** is present only when a registered session supplied task text, and it says so.
  Without it, `intent.task` is `null`, with the note "no intent context was provided; whyfs
  does not infer intent".

`impact` answers "what happens if this file is removed or changed" from observed activity only
([HUMAN_INTERFACE.md](HUMAN_INTERFACE.md)).  `no_observed_dependents: true` is **not** a
statement that removal is safe.  `observation.complete: false` lists the gaps that make the
label incomplete.

## Using whyfs from an agent

Use the API (or `whyfs … --json`); never scrape the window.  Typical checks:

| Before you… | Ask | Look at |
|---|---|---|
| edit an unfamiliar file | `get_file_provenance` | `impact.is_generated`: if true, edit its `inputs` and rerun `created_by.command` rather than editing the output |
| decide whether it is generated | `get_file_provenance` | `impact.is_generated`, `inputs`, `created_by` |
| find its sources | `get_file_inputs` | `inputs`, `inputs_via_temporaries` |
| delete or change it | `get_file_provenance` | `impact.generated_outputs`, `impact.readers`, `impact.possibly_affected`, `observation` |
| attribute it | `get_file_provenance` → `get_agent_session` | `agent.session_id`, `agent.source` (`registered` / `detected`) |
| trust the answer | any label | `observation.complete` and `observation.gaps`; `identity.check` |
| find files | `search_files` | by name, folder, program, user, agent, session, time |

## Registering an agent session

A session names a **root process**.  Every descendant of that process, and every file those
descendants write, is attributed to the session.  The OS-observed process chain is always
kept alongside; the agent never replaces the creator.

1. At start, the agent calls `session_start` with its own PID as `root_pid`.  The service
   accepts it only if the requester's user owns that process (administrators may register
   any), and records the process's start time.  A later process that reuses the PID never
   inherits the session.
2. `task` is optional free text: what the user asked the agent to do.  whyfs stores it
   *as supplied*, labels it as agent-supplied, never verifies it, and redacts secrets in it
   with the command-line policy.  Omit it if you do not know it.
3. At exit, call `session_end` (a session that never ends stays open; attribution still
   requires the root process instance to match).

From a shell, or from a hook:

```sh
whyfs agent start --name "My Agent" --agent-version 1.2 --session-id "$SESSION" --root-pid $PPID \
      --task "Fix the checkout page"            # prints the session id
whyfs agent end --session-id "$SESSION"
whyfs agent files --session-id "$SESSION"       # what the session changed
```

Claude Code, for example, can register itself with hooks in `settings.json`:
- a `SessionStart` hook running `whyfs agent start --name "Claude Code" --session-id <id> --root-pid $PPID`
  (the hook shell's parent is the Claude Code process; the id comes from the hook's JSON input);
- a `SessionEnd` hook running `whyfs agent end`.

Registration is optional.  Without it, whyfs still **detects** Claude Code, Codex CLI and
Gemini CLI processes from their image path and command line, which yields a
`source: "detected"` session without task text.  A program merely named `claude` is not
detected.

### Minimal clients

Python (Linux):

```python
import json, socket
s = socket.socket(socket.AF_UNIX); s.connect("/run/whyfs/api.sock")
s.sendall(json.dumps({"v": 1, "op": "explain_file", "params": {"path": "/abs/file"}}).encode() + b"\n")
print(json.loads(s.makefile().readline())["result"]["text"])
```

Any language: `whyfs api OP '{"path": "..."}'` prints the reply as JSON (the CLI is a client of
the same service).
