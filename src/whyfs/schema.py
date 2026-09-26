"""The canonical whyfs provenance event schema (version 1), shared by every collector.

Platform collectors differ (Linux eBPF, Windows ETW, the portable LD_PRELOAD tracer); the
records they hand to the store do not.  The query layer (why / impact / history) reads only
these fields.  docs/SCHEMA.md is the human description; this module is the executable one:
`validate_record` is applied to real collector output by the tests and the corpus.

Evidence types (the `api` field) say *how* something was observed, so that weaker evidence
is never presented as equivalent to stronger evidence.
"""
from __future__ import annotations

SCHEMA_VERSION = 1

KINDS = ("process", "exec", "open", "io", "rename", "unlink")

# api value -> (evidence class, meaning).  Backend prefix: ebpf (Linux kernel), etw (Windows
# kernel), preload (v0.1 user-space interposition, explicit `whyfs trace` only).
EVIDENCE = {
    # observed data flow (the process actually read / wrote bytes)
    "ebpf:rw": ("io", "read(2)/write(2)-family or io_uring I/O, seen at the VFS permission hook"),
    "etw:rw": ("io", "read/write IRP on the file object, seen by Kernel-File"),
    "ebpf:mmap": ("mapped-io", "a file mapping (MAP_SHARED writable = write, otherwise read)"),
    "etw:mmap": ("mapped-io", "a mapped view of the file (writable non-copy-on-write = write)"),
    # the same, for out-of-workspace temporaries that carry workspace data
    "ebpf:rw:derived-temp": ("io", "I/O on a temporary written by a process that read workspace data"),
    "ebpf:mmap:derived-temp": ("mapped-io", "mapping of such a temporary"),
    "etw:rw:derived-temp": ("io", "I/O on a temporary written by a process that read workspace data"),
    "etw:mmap:derived-temp": ("mapped-io", "mapping of such a temporary"),
    # access intent without observed bytes
    "ebpf:open": ("open", "file opened (flags recorded); not evidence of data flow by itself"),
    "etw:open": ("open", "file opened (create disposition recorded); not evidence of data flow by itself"),
    # namespace operations
    "ebpf:rename": ("rename", "rename/move observed at do_renameat2 (success checked)"),
    "etw:rename": ("rename", "rename/move (RenamePath: new name; old name from the file object)"),
    "ebpf:unlink": ("unlink", "unlink observed at do_unlinkat (success checked)"),
    "ebpf:unlink:derived-temp": ("unlink", "unlink of a derived temporary"),
    "etw:delete": ("unlink", "delete (DeletePath)"),
    "etw:delete:derived-temp": ("unlink", "delete of a derived temporary"),
    "etw:delete-on-close": ("unlink", "file opened FILE_DELETE_ON_CLOSE, deleted at its last cleanup"),
    "etw:delete-on-close:derived-temp": ("unlink", "the same, for a derived temporary"),
    # program image boundaries
    "ebpf:exec": ("exec", "execve(): the process's program image changes here"),
    "etw:exec": ("exec", "process start: a Windows process runs one image for its whole life"),
}
# The portable tracer (v0.1) records opens with the open mode and writes it declares; it
# cannot see reads/writes, so its evidence is "open-only" (query.why bounds it accordingly).
PRELOAD_PREFIX = "preload"

EVENT_FIELDS = {  # canonical event record (dict handed to store.ingest_events)
    "run_id": str, "ts_ns": int, "kind": str, "pid": int, "os_pid": int, "path": (str, type(None)),
    "source": str, "api": str,
}
OPTIONAL_EVENT_FIELDS = {"path2": (str, type(None)), "read": bool, "write": bool, "flags": (int, type(None))}
PROCESS_FIELDS = {
    "run_id": str, "ts_ns": int, "kind": str, "pid": int, "os_pid": int, "ppid": (int, type(None)),
    "parent_key": (int, type(None)), "exe": (str, type(None)), "cwd": (str, type(None)), "command": (str, type(None)),
    "source": str,
}

# What each backend can and cannot observe (docs/SCHEMA.md "Platform semantics").
BACKEND_CAPABILITIES = {
    "ebpf": {"cwd": True, "exec_within_process": True, "mapped_io": True, "io_uring": True, "static_binaries": True,
             "path_case": "sensitive", "users": "all users' processes that touch the workspace (root daemon)"},
    "etw": {"cwd": False, "exec_within_process": False, "mapped_io": True, "io_uring": "n/a (IoRing observed as IRPs)",
            "static_binaries": True, "path_case": "insensitive (ASCII folding, like SQLite NOCASE)",
            "users": "only the requesting user's processes"},
    "preload": {"cwd": True, "exec_within_process": False, "mapped_io": False, "io_uring": False, "static_binaries": False,
                "path_case": "sensitive", "users": "the traced command tree only"},
}


class SchemaError(ValueError):
    pass


def _check(rec: dict, fields: dict, optional: dict = {}) -> None:  # noqa: B006
    for k, t in fields.items():
        if k not in rec:
            raise SchemaError(f"missing field {k!r} in {rec}")
        if not isinstance(rec[k], t):
            raise SchemaError(f"field {k!r} has type {type(rec[k]).__name__} in {rec}")
    for k, t in optional.items():
        if k in rec and not isinstance(rec[k], t):
            raise SchemaError(f"field {k!r} has type {type(rec[k]).__name__} in {rec}")
    extra = set(rec) - set(fields) - set(optional)
    if extra:
        raise SchemaError(f"unknown fields {sorted(extra)} in {rec}")


def validate_record(rec: dict) -> None:
    """Raise SchemaError unless ``rec`` is a canonical whyfs record."""
    kind = rec.get("kind")
    if kind not in KINDS:
        raise SchemaError(f"unknown kind {kind!r}")
    if kind == "process":
        _check(rec, PROCESS_FIELDS)
        return
    _check(rec, EVENT_FIELDS, OPTIONAL_EVENT_FIELDS)
    api = rec["api"]
    if rec["source"] == PRELOAD_PREFIX:  # api = the intercepted libc call; evidence is open-only
        if kind != "open":
            raise SchemaError(f"the preload tracer records opens only: {rec}")
        return
    if api not in EVIDENCE:
        raise SchemaError(f"unknown evidence type {api!r}")
    cls = EVIDENCE[api][0]
    expect = {"io": "io", "mapped-io": "io", "open": "open", "rename": "rename", "unlink": "unlink", "exec": "exec"}[cls]
    if kind != expect:
        raise SchemaError(f"evidence {api!r} cannot be a {kind!r} record")
    if kind == "io" and not (rec.get("read") or rec.get("write")):
        raise SchemaError(f"an io record must be a read or a write: {rec}")
    if kind == "rename" and "path2" not in rec:
        raise SchemaError(f"a rename needs path2: {rec}")
    if rec["source"] != api.split(":", 1)[0]:
        raise SchemaError(f"source {rec['source']!r} does not match evidence {api!r}")


def evidence_class(api: str | None, source: str | None = None) -> str:
    if source == PRELOAD_PREFIX:
        return "open-only"
    if not api:
        return "unknown"
    return EVIDENCE.get(api, ("unknown",))[0]
