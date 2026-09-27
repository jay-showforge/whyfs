# Finding and reading labels without a terminal

whyfs has three ways in.  All three read the same records through the local service:

| Who | Interface | What it is |
|---|---|---|
| People | **The WhyFS window** and the **file-manager menu** | Right-click a file to see its label; search the provenance index |
| AI agents and tools | **The local API** (`whyfs-api/1`, [AGENT_PROTOCOL.md](AGENT_PROTOCOL.md)) | JSON over a Unix socket / named pipe |
| Power users, scripts | **The CLI** (`whyfs label`, `whyfs search`, …) | The same JSON with `--json`, or text |

Every surface shows the same canonical label (`whyfs-label/1`), and the gate checks that the
window, the API and the CLI agree field by field (`U.same_label_in_window_api_and_cli`).  A
file whose label comes from an explicitly initialized workspace store (`whyfs init`) is answered
from that store by the CLI.  When that store has no record, the CLI asks the service like the
others.

## Right-click a file

**Windows (Explorer).**  The installer adds these entries.  On Windows 11 they are under **Show
more options** (Shift+F10), which is where Windows lists registry-registered menu entries.
- A file → **WhyFS** →
  - *Why does this file exist?*
  - *What created this file?*
  - *What depends on this file?*
  - *Show WhyFS history*
  - *Search WhyFS...*
- A folder, or the empty space in one → **WhyFS: search this folder**
- Start menu → **WhyFS**: opens search.

Each entry runs `whyfsw.exe ui --file "<the file>"`.  `whyfsw.exe` is the launcher without a
console.  Nothing reads, opens for writing, or modifies the selected file.  The menu is plain
`HKLM\Software\Classes` shell verbs (`*\shell\WhyFS` → `WhyFS.FileMenu`); no shell extension
DLL is loaded into Explorer.

**Linux.**  The .deb installs:

| File manager | Integration |
|---|---|
| Files (Nautilus) | A **WhyFS** submenu, via `/usr/share/nautilus-python/extensions/whyfs_nautilus.py`.  Needs `python3-nautilus` (suggested by the package); run `nautilus -q` once to load it. |
| Dolphin (KDE) | A **WhyFS** submenu (`/usr/share/kio/servicemenus/`, and the KF5 location) |
| Nemo (Cinnamon) | Actions (`/usr/share/nemo/actions/whyfs-*.nemo_action`) |
| Any desktop | **WhyFS** in the application menu (search); **Open With → WhyFS label** for common file types |
| Anywhere (Thunar custom actions, a terminal, SSH) | `whyfs ui --file FILE`, or `whyfs label FILE` |

## The WhyFS window

`whyfs ui` (or any menu entry) opens a small local page in your default browser.  It has two
halves: search on the left, the selected file's label on the right.

**Search** by any combination of:
- part of the file name, e.g. `app.js`;
- part of the path, or a folder;
- the program that wrote it, e.g. `python`, `code.exe`;
- the user;
- the AI agent, or one agent session;
- a time range: last hour, today, 7 or 30 days, or between two dates/times;
- what happened: created, changed, or deleted.

Shortcuts: *Recently changed*, *Created today*, *Made by AI agents*, *Produced by Python*.
Selecting a result shows its label.  Input files, outputs and moved-from paths in a label are
links to their own labels.

**The label answers**, where evidence exists:

| Question | Label section |
|---|---|
| What file is this, where is it? | header: name, full path, *Show in folder* |
| Why does it exist? | *causal why*: what was observed.  *Task*: only if an agent session supplied one; whyfs does not guess intent. |
| When was it created / changed? | *What created it*: created, last written |
| Which process created it, from which chain? | program, pid, command, working folder, process chain |
| Which user? | user |
| Which AI agent / session? | *AI agent*, and whether it was registered or detected.  *Files from this session* runs a search. |
| Which inputs? | *Inputs*, plus how many system/library files were hidden |
| What happened since? | *What has happened to it*: written, moved, read, deleted |
| What depends on it? | *If you remove or change it* (below) |
| Is the evidence complete? | *Evidence*: observing since, identity check, and the observation gaps |

## "What happens if I remove or change this file?"

The answer comes from **observed** activity.  It is not a static dependency analysis.  The label
distinguishes:
- **Files generated from it:** a process read it and then wrote these files, directly or through
  intermediates.  Changing or removing it may affect them.
- **Possibly affected:** files written afterwards by a long-running program that read it and
  wrote more than 25 other files, e.g. an editor, an agent or a browser.  Which of those files
  used it is not observable, so they are listed separately and not called dependents.
- **Programs that read it:** readers that produced no observed output may still need the file
  at run time.
- **No observed dependents:** always said with *"This does not mean it is safe to remove:
  whyfs only knows the activity it observed."*
- **Incomplete evidence:** any observation gap, listed below, is repeated in the answer.

whyfs never says a file is safe to delete.

## Observation gaps

A label separates two questions:
- **Origin**: was whyfs recording, without loss, when this file was created?
  `observation.complete` answers this, and `observation.gaps` lists the reasons when it is
  false.
- **Since then**: was whyfs recording afterwards?  `observation.later_gaps` lists downtime or
  loss after creation.  Later history and dependents may be missing, and the impact answer says
  so.

The origin is **incomplete** when any of these hold:
- the file's origin was not observed at all (`no-record` or `not-observed`);
- the file appeared while whyfs was not recording.  `observation.file_time_in_gap` names the
  gap and whether it followed a crash;
- the file predates whyfs;
- the collector reported lost or unattributed events in the recording session in which the file
  was created;
- the file's identity could not be compared with the recorded one.

**Later gaps** include:
- whyfs was not recording for part of the time since (downtime of more than 5 s, e.g. an
  observer crash or a shut-down machine);
- it is not recording now;
- events were lost in later sessions;
- reads older than the 30-day weak-retention period were pruned.

`observation.notes` carries information that does not make a label incomplete.  An example is a
process chain that begins where whyfs started observing, because earlier ancestors, such as boot
and logon processes, had already exited.

How gaps are recorded is described in [MACHINE_MODE.md](MACHINE_MODE.md#observation-integrity).

## Security of the window

The window is a per-user process bound to `127.0.0.1` on a random port.  It is not a service,
not reachable from the network, and has no accounts.  Its protections:
- **Launch.**  A menu entry or `whyfs ui` gets a one-time launch token (valid 60 s) from the
  per-user state file (`%LOCALAPPDATA%\whyfs\ui.json`, or `$XDG_RUNTIME_DIR/whyfs/ui.json`
  mode 0600).  The token sets an `HttpOnly; SameSite=Strict` cookie.
- **Requests.**  Every request needs that cookie and an `X-Whyfs` header, which a cross-site
  form cannot send.  It must name the exact `127.0.0.1:<port>` Host (no DNS rebinding) and carry
  no foreign `Origin`.
- **Operations.**  Only read-only operations reach the service (`search_files`,
  `get_file_provenance`, …).  `forget` and `session_start` are refused.  *Show in folder* asks
  the file manager to show the path.
- **Identity.**  The window asks the service **as the user who opened it**, so it shows exactly
  what that user may see.
- **Rendering.**  All recorded text is inserted as text, never as HTML.  A file named
  `<script>` stays a file name.  A content security policy forbids everything but the page
  itself.
- **Lifetime.**  The window exits after 30 minutes without requests.  It keeps no data of its
  own.
