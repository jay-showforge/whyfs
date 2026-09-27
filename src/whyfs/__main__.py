"""`python -m whyfs` (the whyfs.exe / whyfsw.exe launchers run this).

Fast path: `whyfs why|label FILE [--json]` for a file outside any explicitly initialized workspace
is answered by the service after importing only the API client, not the whole CLI -- every
query is a fresh process, and its start-up time is most of its latency.  Everything else, and
anything unusual about these commands, goes through the full CLI with identical output.
"""
import sys


def _fast() -> int | None:
    a = sys.argv[1:]
    if len(a) not in (2, 3) or a[0] not in ("why", "label"):
        return None
    rest = a[1:]
    as_json = "--json" in rest
    files = [x for x in rest if x != "--json"]
    if len(files) != 1 or files[0].startswith("-") or (a[0] == "why" and not as_json):
        return None
    import os
    path = os.path.abspath(files[0])
    d = os.path.dirname(os.path.realpath(path))
    while True:  # an initialized workspace store answers first: the full CLI handles it
        if os.path.exists(os.path.join(d, ".whyfs")):
            return None
        up = os.path.dirname(d)
        if up == d:
            break
        d = up
    import json
    from .client import ServiceUnavailable, call
    try:
        if a[0] == "why":
            reply = call("why", {"path": path, "include_noise": False, "raw": False})
        else:
            reply = call("get_file_provenance", {"path": path, "include_noise": False})
    except (ServiceUnavailable, OSError):
        return None  # the full CLI explains the problem
    if not reply.get("ok"):
        return None
    result = reply["result"]
    if a[0] == "why":
        print(json.dumps(result, indent=2))
        return 0 if result else 1
    if as_json:
        print(json.dumps(result, indent=2, default=str))
    else:
        from .labeltext import render_label
        print(render_label(result))
    return 0 if result.get("status") == "labelled" else 1


rc = _fast()
if rc is None:
    from .cli import main
    main()
else:
    sys.exit(rc)
