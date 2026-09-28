from __future__ import annotations

import os
import sqlite3
from .store import normalize

# Human-view noise only. Raw evidence remains in SQLite and is available with
# --all/JSON. We never delete an observed edge because a heuristic dislikes it.
NOISE_PREFIXES = (
    "/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/", "/usr/share/", "/usr/libexec/",
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/lib/",
    "/etc/", "/proc/", "/sys/", "/dev/", "/run/",
)
NOISE_BASENAMES = {
    ".DS_Store", "ld.so.cache",
}


if os.name == "nt":
    # Windows paths compare case-insensitively (same folding as SQLite NOCASE: ASCII).
    _FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
    NOISE_PREFIXES_NT = tuple(p.lower() for p in (
        os.environ.get("SystemRoot", r"C:\Windows") + "\\",
        os.environ.get("ProgramFiles", r"C:\Program Files") + "\\",
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)") + "\\",
        os.environ.get("ProgramData", r"C:\ProgramData") + "\\",
    ))

    def pkey(p: str) -> str:
        return p.translate(_FOLD)
else:
    NOISE_PREFIXES_NT = ()

    def pkey(p: str) -> str:
        return p


def _is_noise(path: str, workspace: str) -> bool:
    if _in_workspace(path, workspace):
        return False
    return _noise_path(path)


def _noise_path(path: str) -> bool:
    """System/runtime locations, whatever the workspace (the machine store has none)."""
    if os.path.basename(path) in NOISE_BASENAMES:
        return True
    return path.startswith(NOISE_PREFIXES) or (bool(NOISE_PREFIXES_NT) and pkey(path).startswith(NOISE_PREFIXES_NT))


_ORIGIN_SQL = """
      SELECT e.*, r.command AS run_command, r.cwd AS run_cwd, r.workspace, r.collector,
             pr.exe, pr.cwd AS process_cwd, pr.command AS process_command, pr.source AS process_source
      FROM events e JOIN runs r ON r.id=e.run_id
      LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid
      WHERE {cond} AND (? IS NULL OR e.ts_ns<=?)
      ORDER BY e.ts_ns DESC, e.id DESC LIMIT 1
"""


def _latest_write_or_move_in(con: sqlite3.Connection, p: str, before: int | None = None):
    """The newest write to ``p`` or move into ``p`` (at or before ``before``).

    Two index-ordered lookups -- events_path (path, ts_ns) and events_path2 (path2, ts_ns) --
    each stopping at its first match, instead of one OR query that SQLite answers by collecting
    and sorting every event of the path (cost grew with the file's whole history)."""
    rows = [con.execute(_ORIGIN_SQL.format(cond=c), (p, before, before)).fetchone()
            for c in ("e.path=? AND e.is_write=1", "e.path2=? AND e.kind='rename'")]
    rows = [r for r in rows if r is not None]
    return max(rows, key=lambda r: (r["ts_ns"], r["id"])) if rows else None


def last_writer(con: sqlite3.Connection, path: str):
    return _latest_write_or_move_in(con, normalize(path))


def _image_start(con: sqlite3.Connection, run_id: str, pid: int, at_ns: int) -> int:
    """Timestamp of the exec that started the program image active at ``at_ns``.

    One process can exec several images (runuser -> env -> bash -> python).  A
    file written by the last image was produced by *that* program; reads made
    by earlier images (e.g. runuser reading /etc/passwd) are not its inputs.
    Collectors without exec events (v0.1 preload) yield 0 = whole process."""
    row = con.execute(
        "SELECT MAX(ts_ns) FROM events WHERE run_id=? AND pid=? AND kind='exec' AND ts_ns<=?",
        (run_id, pid, at_ns),
    ).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _input_rows(con: sqlite3.Connection, run_id: str, pid: int, before_ns: int):
    since = _image_start(con, run_id, pid, before_ns)
    return con.execute(
        """
      SELECT path, MIN(ts_ns) AS first_ns, MAX(COALESCE(api, '') NOT LIKE '%mmap%') AS read_io FROM events
      WHERE run_id=? AND pid=? AND is_read=1 AND path IS NOT NULL AND ts_ns<=? AND ts_ns>=?
      GROUP BY path ORDER BY first_ns
    """,
        (run_id, pid, before_ns, since),
    ).fetchall()


DEPENDENCY_DIRS = ("node_modules", "site-packages", "dist-packages", "__pycache__")


def _is_dependency(path: str) -> bool:
    """Package-manager trees (e.g. a bundler's own code under node_modules/).
    Collapsed in the default human view only; always kept as raw evidence."""
    parts = path.split(os.sep)
    return any(d in parts for d in DEPENDENCY_DIRS)


CODE_IMAGE_SUFFIXES = (".dll", ".exe", ".pyd", ".so", ".node", ".dylib", ".sys", ".ocx", ".cpl")


def _is_loaded_code(path: str, read_io: int) -> bool:
    """A program image or library the loader mapped (never read as data): code the process
    ran, not an input it consumed.  Collapsed in the human view only; raw evidence keeps it."""
    if read_io:
        return False
    low = path.lower()
    name = os.path.basename(low)
    return low.endswith(CODE_IMAGE_SUFFIXES) or ".so." in name


def _self_written_before(con: sqlite3.Connection, run_id: str, pid: int, path: str, ts_ns: int) -> bool:
    """True if this process instance itself wrote ``path`` before ``ts_ns``: what it
    then reads back is its own output (a linker's scratch file, a compiler re-reading
    the object it just wrote), not an upstream input."""
    return con.execute(
        "SELECT 1 FROM events WHERE run_id=? AND pid=? AND path=? AND is_write=1 AND ts_ns<? LIMIT 1",
        (run_id, pid, path, ts_ns),
    ).fetchone() is not None


def process_inputs(con: sqlite3.Connection, run_id: str, pid: int, before_ns: int, workspace: str, include_noise=False):
    rows = _input_rows(con, run_id, pid, before_ns)
    visible: list[str] = []
    hidden = 0
    for r in rows:
        p = r["path"]
        if include_noise or not (_is_noise(p, workspace) or _is_dependency(p) or _is_loaded_code(p, r["read_io"])
                                 or _self_written_before(con, run_id, pid, p, r["first_ns"])):
            visible.append(p)
        else:
            hidden += 1
    return visible, hidden


def process_outputs(con: sqlite3.Connection, run_id: str, pid: int, workspace: str, include_noise=False,
                    since_ns: int = 0):
    """Files a process wrote or moved; with ``since_ns``, only those written at
    or after that time (an output cannot depend on an input it read later)."""
    rows = con.execute(
        """
      SELECT CASE WHEN kind='rename' THEN path2 ELSE path END AS out_path, MAX(ts_ns) AS last_ns
      FROM events WHERE run_id=? AND pid=? AND (is_write=1 OR kind='rename')
        AND (ts_ns>=? OR (is_write=1 AND api LIKE '%:mmap%'))  -- a writable view can take data read later
      GROUP BY out_path ORDER BY MIN(id)
    """,
        (run_id, pid, since_ns),
    ).fetchall()
    out = []
    for r in rows:
        p = r["out_path"]
        if not p or (not include_noise and (_is_noise(p, workspace) or _self_deleted_after(con, run_id, pid, p, r["last_ns"]))):
            continue
        out.append(p)
    return out


def _mapped_write(api: str | None) -> bool:
    return bool(api) and ":mmap" in api


def _self_deleted_after(con: sqlite3.Connection, run_id: str, pid: int, path: str, ts_ns: int) -> bool:
    """A scratch file the same process wrote and then deleted: not a lasting output."""
    return con.execute(
        "SELECT 1 FROM events WHERE run_id=? AND pid=? AND kind='unlink' AND path=? AND ts_ns>=? LIMIT 1",
        (run_id, pid, path, ts_ns),
    ).fetchone() is not None


def _in_workspace(path: str, workspace: str) -> bool:
    p, w = pkey(path), pkey(workspace)
    return p == w or p.startswith(w.rstrip(os.sep) + os.sep)


_MACHINE_ROOT: list = []


def _is_machine_store(workspace: str) -> bool:
    """A run of the machine collector (docs/MACHINE_MODE.md): its 'workspace' is the machine
    store's own directory, and nothing is "inside" it.  There, a temporary is what the
    evidence says it is (a derived-temporary read), never "a path outside the workspace"."""
    if not _MACHINE_ROOT:
        try:
            from .machine import paths
            _MACHINE_ROOT.append(pkey(normalize(str(paths()["root"]))))
        except Exception:
            _MACHINE_ROOT.append(None)
    return bool(workspace) and pkey(normalize(workspace)) == _MACHINE_ROOT[0]


def _derived_temp_reads(con: sqlite3.Connection, run_id: str, pid: int, before_ns: int) -> set[str]:
    return {r[0] for r in con.execute(
        "SELECT DISTINCT path FROM events WHERE run_id=? AND pid=? AND is_read=1 AND ts_ns<=? AND api LIKE '%derived-temp'",
        (run_id, pid, before_ns))}


def _through_temporaries(con: sqlite3.Connection, inputs: list[str], workspace: str, before_ns: int, depth: int = 3,
                         run_id: str | None = None, pid: int | None = None):
    """Expand observed out-of-workspace temporaries (e.g. gcc's /tmp/ccXXXX.s)
    to the workspace inputs of the process that wrote them.  Every hop is an
    observed write followed by an observed read; nothing is inferred."""
    if run_id is not None and _is_machine_store(workspace):
        return _through_temporaries_machine(con, inputs, run_id, pid, before_ns, depth)
    via: list[dict] = []
    found: list[str] = []
    frontier = [(p, before_ns) for p in inputs if not _in_workspace(p, workspace)]
    seen = set(frontier)
    for _ in range(depth):
        nxt = []
        for tmp, bound in frontier:
            w, _r = _content_origin(con, tmp, before=bound)
            if not w or w["kind"] == "rename":
                continue
            ins = [r["path"] for r in _input_rows(con, w["run_id"], w["pid"], w["ts_ns"]) if r["path"] != tmp]
            via.append({"temporary": tmp, "written_by": w["exe"],
                        "pid": w["os_pid"] if w["os_pid"] is not None else w["pid"], "inputs": ins})
            for p in ins:
                if _in_workspace(p, workspace):
                    if p not in found:
                        found.append(p)
                elif (p, w["ts_ns"]) not in seen:
                    seen.add((p, w["ts_ns"]))
                    nxt.append((p, w["ts_ns"]))
        frontier = nxt
        if not frontier:
            break
    return found, via


def _through_temporaries_machine(con, inputs, run_id, pid, before_ns, depth=3):
    via: list[dict] = []
    found: list[str] = []
    temps = _derived_temp_reads(con, run_id, pid, before_ns)
    frontier = [(p, before_ns) for p in inputs if p in temps]
    seen = set(frontier)
    for _ in range(depth):
        nxt = []
        for tmp, bound in frontier:
            w, _r = _content_origin(con, tmp, before=bound)
            if not w or w["kind"] == "rename":
                continue
            ins = [r["path"] for r in _input_rows(con, w["run_id"], w["pid"], w["ts_ns"]) if r["path"] != tmp]
            wtemps = _derived_temp_reads(con, w["run_id"], w["pid"], w["ts_ns"])
            via.append({"temporary": tmp, "written_by": w["exe"],
                        "pid": w["os_pid"] if w["os_pid"] is not None else w["pid"], "inputs": ins})
            for p in ins:
                if p in wtemps:
                    if (p, w["ts_ns"]) not in seen:
                        seen.add((p, w["ts_ns"]))
                        nxt.append((p, w["ts_ns"]))
                elif not (_noise_path(p) or _is_dependency(p)) and p not in found:
                    found.append(p)
        frontier = nxt
        if not frontier:
            break
    return found, via


def _content_origin(con: sqlite3.Connection, path: str, max_hops: int = 16, before: int | None = None):
    """Follow rename/move events backwards to the process that wrote the bytes.

    Returns (writer_row, renames) where ``renames`` lists the observed
    rename/move steps, newest first.  A rename is recorded evidence of a move,
    not of content creation, so the creator is the last *writer* before it.
    """
    p = normalize(path)
    renames: list[dict] = []
    for _ in range(max_hops):
        row = _latest_write_or_move_in(con, p, before)
        if row is None or row["kind"] != "rename":
            return row, renames
        renames.append({
            "from": row["path"], "to": row["path2"], "ts_ns": row["ts_ns"], "exe": row["exe"],
            "pid": row["os_pid"] if row["os_pid"] is not None else row["pid"],
        })
        p, before = row["path"], row["ts_ns"]
    return None, renames


def why(con: sqlite3.Connection, path: str, include_noise=False):
    w, renames = _content_origin(con, path)
    if not w and renames:
        # Moved into place, but the bytes' original writer was never observed.
        r0 = renames[-1]
        return {
            "path": normalize(path), "renamed_from": renames, "exe": r0["exe"] or "?", "pid": r0["pid"],
            "run_id": None, "ts_ns": r0["ts_ns"], "process_key": None, "process_cwd": None,
            "command": None, "collector": "unknown", "inputs": [], "hidden_input_count": 0, "outputs": [],
        }
    if not w:
        return None
    before = w["ts_ns"]
    if w["kind"] == "open" or _mapped_write(w["api"]):
        # Open-only evidence (the v0.1 preload backend records opens, not writes): the
        # data may be written after later reads -- in `cmd in > out` the shell opens
        # `out` before `cmd` opens `in` -- so bound inputs by the end of the process.
        # A writable mapping likewise: bytes reach the file through memory for as long as
        # the view exists (MSVC link maps its output before mapping its inputs).
        last = con.execute("SELECT MAX(ts_ns) FROM events WHERE run_id=? AND pid=?", (w["run_id"], w["pid"])).fetchone()[0]
        before = max(before, last or before)
    inputs, hidden = process_inputs(con, w["run_id"], w["pid"], before, w["workspace"], include_noise)
    target = normalize(path)
    # O_RDWR output files can appear as both read and write.  A file is not its
    # own upstream cause (under its current or any earlier name), so suppress
    # the self-edge from the human view while preserving the raw event.
    self_names = {pkey(target)} | {pkey(r["from"]) for r in renames}
    # execve() itself opens/reads/maps the program image.  That is real
    # evidence (kept, and shown with --raw), but in the human view the program
    # is already reported as the creator, not as a data input.
    if not include_noise and w["exe"]:
        self_names.add(pkey(w["exe"]))
    inputs = [p for p in inputs if pkey(p) not in self_names]
    shared = _shared_inputs(con, w["run_id"], w["pid"], target, self_names, inputs, before)
    via_inputs, via_temps = _through_temporaries(con, inputs, w["workspace"], w["ts_ns"], run_id=w["run_id"], pid=w["pid"])
    return {
        "path": target,
        "run_id": w["run_id"],
        "ts_ns": w["ts_ns"],
        "pid": w["os_pid"] if w["os_pid"] is not None else w["pid"],
        "process_key": w["pid"],
        "exe": w["exe"] or "?",
        "process_cwd": w["process_cwd"] or w["run_cwd"],
        "command": w["process_command"] or w["run_command"],
        "collector": w["collector"] or w["process_source"] or "unknown",
        "inputs": inputs,
        "inputs_via_temporaries": via_inputs,
        "temporaries": via_temps,
        "renamed_from": renames,
        "hidden_input_count": hidden,
        "outputs": process_outputs(con, w["run_id"], w["pid"], w["workspace"], include_noise),
        "parent": _parent(con, w["run_id"], w["pid"]),
        # >0: this process wrote other outputs too and read every one of these inputs before
        # its first output, so which input produced which output is not observable (one
        # MSVC `cl` compiling several files; `cl /MP` children are exact).  Never guessed.
        "shared_by_outputs": shared,
    }


def _shared_inputs(con, run_id: str, pid: int, target: str, self_names: set, inputs: list[str], before_ns: int) -> int:
    if not inputs:
        return 0
    outs = {pkey(r[0]) for r in con.execute(
        "SELECT DISTINCT CASE WHEN kind='rename' THEN path2 ELSE path END FROM events "
        "WHERE run_id=? AND pid=? AND (is_write=1 OR kind='rename')", (run_id, pid)) if r[0]}
    others = outs - self_names - {pkey(target)}
    if not others:
        return 0
    marks = ",".join("?" * len(inputs))
    first_in, last_in = con.execute(
        f"SELECT MIN(ts_ns), MAX(ts_ns) FROM events WHERE run_id=? AND pid=? AND is_read=1 AND ts_ns<=? AND path IN ({marks})",
        (run_id, pid, before_ns, *inputs)).fetchone()
    if first_in is None:
        return 0
    first_out = con.execute("SELECT MIN(ts_ns) FROM events WHERE run_id=? AND pid=? AND is_write=1", (run_id, pid)).fetchone()[0]
    # (A) batch: the process read everything it read (other than its own outputs) before it
    #     wrote any output (one `cl` compiling several files; a bundler) -- the outputs share
    #     the inputs.
    last_read = max((r[1] for r in con.execute(
        "SELECT path, MAX(ts_ns) FROM events WHERE run_id=? AND pid=? AND is_read=1 GROUP BY path", (run_id, pid))
        if r[0] and pkey(r[0]) not in outs), default=None)
    if first_out is not None and last_read is not None and last_read <= first_out:
        return len(others)
    # (B) interleaved: another output was written after one of these inputs was read and before
    #     this output -- that input may belong to the other output.
    between = {pkey(r[0]) for r in con.execute(
        "SELECT DISTINCT path FROM events WHERE run_id=? AND pid=? AND is_write=1 AND ts_ns>? AND ts_ns<?",
        (run_id, pid, first_in, before_ns)) if r[0]} & others
    return len(others) if between else 0


def _parent(con: sqlite3.Connection, run_id: str, key: int):
    """The creator's parent process (eBPF: per-run parent key; preload: ppid)."""
    row = con.execute("SELECT ppid, parent_key, first_seen_ns FROM processes WHERE run_id=? AND pid=?",
                      (run_id, key)).fetchone()
    if not row:
        return None
    pkey = row["parent_key"] if row["parent_key"] is not None else row["ppid"]
    if pkey is None:
        return None
    p = con.execute("SELECT pid, os_pid, exe, command FROM processes WHERE run_id=? AND pid=?", (run_id, pkey)).fetchone()
    if not p:
        return None
    exe, command = p["exe"], p["command"]
    # The process row holds the parent's latest image.  If the parent exec'd again
    # after forking this child (`bash -c 'a; b'` execs b in place), report the image
    # that did the fork; its command line is not recorded, so none is shown.
    forked = row["first_seen_ns"]
    later = con.execute("SELECT 1 FROM events WHERE run_id=? AND pid=? AND kind='exec' AND ts_ns>? LIMIT 1",
                        (run_id, pkey, forked)).fetchone()
    if later:
        img = con.execute("SELECT path FROM events WHERE run_id=? AND pid=? AND kind='exec' AND ts_ns<=? "
                          "ORDER BY ts_ns DESC, id DESC LIMIT 1", (run_id, pkey, forked)).fetchone()
        exe, command = (img["path"] if img else None), None
    return {"pid": p["os_pid"] if p["os_pid"] is not None else p["pid"], "exe": exe, "command": command}


def history(con: sqlite3.Connection, path: str, limit=20):
    """Writes to and moves of the file, newest first.  ``limit`` <= 0: the complete history.

    Each of the three conditions is one index-ordered scan stopped at ``limit`` rows, merged:
    the newest ``limit`` rows without sorting the file's whole history."""
    p = normalize(path)
    n = limit if limit and limit > 0 else -1  # SQLite: LIMIT -1 is unlimited
    rows: dict = {}
    for cond in ("e.path=? AND e.is_write=1", "e.path=? AND e.kind='rename'", "e.path2=? AND e.kind='rename'"):
        for r in con.execute(
            f"""
          SELECT e.id,e.ts_ns,e.run_id,COALESCE(e.os_pid,e.pid) AS pid,e.pid AS process_key,e.kind,e.path,e.path2,
                 COALESCE(pr.command,r.command) AS command,pr.exe,r.collector,e.source
          FROM events e JOIN runs r ON r.id=e.run_id
          LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid
          WHERE {cond}
          ORDER BY e.ts_ns DESC, e.id DESC LIMIT ?
        """,
            (p, n),
        ).fetchall():
            rows[r["id"]] = r
    out = sorted(rows.values(), key=lambda r: (r["ts_ns"], r["id"]), reverse=True)
    out = out if n < 0 else out[:n]
    return [{k: r[k] for k in r.keys() if k != "id"} for r in out]  # the same fields as before


def impact(con: sqlite3.Connection, path: str, max_depth=5, include_noise=False):
    """Downstream edges (from, to, exe, run_id).  impact_details() adds, per edge, how many
    outputs the reading process wrote after reading `from` (`shared` > 1: per-output
    attribution is not observable, e.g. one MSVC `cl` compiling several files)."""
    return [(e["from"], e["to"], e["exe"], e["run_id"]) for e in impact_details(con, path, max_depth, include_noise)]


RECENT_EVENTS = 1000  # the label's window: a file's most recent events (history keeps them all)


def _recent_window(con: sqlite3.Connection, f: str, n_readers: int) -> tuple[list, list, bool]:
    """The recent view of ``f`` used by the label: one index-ordered scan (events_path, newest
    first) of at most RECENT_EVENTS events of the path.  From it: the ``n_readers`` processes
    that read ``f`` most recently -- each one's first read of ``f`` then looked up exactly
    through its own events (events_pid), not the window -- and the moves away from ``f``.
    Returns (readers, moves, truncated): ``truncated`` when the window did not reach the
    beginning of the file's history or more readers were seen than expanded."""
    window = con.execute(
        "SELECT e.run_id, e.pid, e.kind, e.is_read, e.path2, pr.exe FROM events e "
        "LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid "
        "WHERE e.path=? ORDER BY e.ts_ns DESC, e.id DESC LIMIT ?", (f, RECENT_EVENTS + 1)).fetchall()
    truncated = len(window) > RECENT_EVENTS
    window = window[:RECENT_EVENTS]
    order, seen = [], set()
    for w in window:
        if w["is_read"]:
            k = (w["run_id"], w["pid"])
            if k not in seen:
                seen.add(k)
                order.append(k)
    truncated = truncated or len(order) > n_readers
    readers = []
    for run_id, pid in order[:n_readers]:
        r = con.execute(
            """SELECT e.run_id,e.pid,r.workspace,pr.exe,MIN(e.ts_ns) AS first_read_ns, MAX(e.kind='io') AS observed_io
               FROM events e JOIN runs r ON r.id=e.run_id
               LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid
               WHERE e.run_id=? AND e.pid=? AND +e.path=? AND e.is_read=1""", (run_id, pid, f)).fetchone()
        if r is not None and r["run_id"] is not None:
            readers.append(r)
    moves, seen_moves = [], set()
    for w in window:
        if w["kind"] == "rename" and (w["path2"], w["run_id"], w["exe"]) not in seen_moves:
            seen_moves.add((w["path2"], w["run_id"], w["exe"]))
            moves.append({"path2": w["path2"], "run_id": w["run_id"], "exe": w["exe"]})
    return readers, moves, truncated


def impact_details(con: sqlite3.Connection, path: str, max_depth=5, include_noise=False,
                   recent_readers: int | None = None, info: dict | None = None) -> list[dict]:
    """Downstream edges from ``path``: through every observed reader (the complete walk: `whyfs
    impact`, the API's impact), or -- with ``recent_readers`` -- through each file's most recent
    readers only (the label: its cost must not grow with a file's history).  ``info`` receives
    ``readers_truncated`` when older readers were left out of the recent view."""
    start = normalize(path)
    seen_files = {pkey(start)}
    frontier = [start]
    edges = []
    for _depth in range(max_depth):
        nxt = []
        for f in frontier:
            recent = _recent_window(con, f, recent_readers) if recent_readers is not None else None
            if recent is not None and recent[2]:  # a long history: its recent part only, and say so
                readers, moves, _ = recent
                if info is not None:
                    info["readers_truncated"] = True
            else:  # the complete walk (or a short history: the same queries, the same result)
                readers = con.execute(
                    """
                  SELECT e.run_id,e.pid,r.workspace,pr.exe,MIN(e.ts_ns) AS first_read_ns,
                         MAX(e.kind='io') AS observed_io FROM events e
                  JOIN runs r ON r.id=e.run_id LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid
                  WHERE e.path=? AND e.is_read=1
                  GROUP BY e.run_id, e.pid
                """,
                    (f,),
                ).fetchall()
                moves = con.execute(
                    """SELECT DISTINCT e.path2, e.run_id, pr.exe FROM events e
                       LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid
                       WHERE e.kind='rename' AND e.path=?""",
                    (f,),
                ).fetchall()
            # A rename/move carries the file's lineage to its new name.
            for mv in moves:
                o = mv["path2"]
                if o and pkey(o) != pkey(f):
                    edges.append({"from": f, "to": o, "exe": (mv["exe"] or "?") + " (rename)", "run_id": mv["run_id"],
                                  "shared": 0})
                    if pkey(o) not in seen_files:
                        seen_files.add(pkey(o))
                        nxt.append(o)
            for rr in readers:
                # A process reading back a file it wrote itself is not consuming an input
                # (MSVC `cl` re-reads each object it writes); raw view keeps it.
                if not include_noise and _self_written_before(con, rr["run_id"], rr["pid"], f, rr["first_read_ns"] + 1):
                    continue
                # Read-before-write ordering needs observed reads; open-only evidence
                # (v0.1 preload) links the process's outputs as a whole.
                outs = process_outputs(con, rr["run_id"], rr["pid"], rr["workspace"], include_noise,
                                       since_ns=rr["first_read_ns"] if rr["observed_io"] else 0)
                shared = len([o for o in outs if pkey(o) != pkey(f)])
                for o in outs:
                    if pkey(o) == pkey(f):
                        continue
                    edges.append({"from": f, "to": o, "exe": rr["exe"] or "?", "run_id": rr["run_id"],
                                  "shared": shared if shared > 1 else 0})
                    if pkey(o) not in seen_files:
                        seen_files.add(pkey(o))
                        nxt.append(o)
        frontier = nxt
        if not frontier:
            break
    return edges


def raw_process_events(con: sqlite3.Connection, run_id: str, pid: int, limit: int = 500):
    """Every stored event of one process instance, unfiltered (``why --raw``)."""
    return con.execute(
        """
      SELECT ts_ns,kind,path,path2,is_read,is_write,api,source FROM events
      WHERE run_id=? AND pid=? ORDER BY ts_ns, id LIMIT ?
    """,
        (run_id, pid, limit),
    ).fetchall()
