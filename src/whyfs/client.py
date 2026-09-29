"""whyfs-api/1 client: one request to the local service (docs/AGENT_PROTOCOL.md).

Kept apart from api.py (the server) so a CLI query imports only what a request needs: every
`whyfs why` / `whyfs label` is a fresh process, and its start-up time is most of its latency.
"""
from __future__ import annotations

import os
import sys

from . import jsonlite

PROTOCOL = 1
PIPE_NAME = r"\\.\pipe\whyfs-api"
SOCKET_PATH = "/var/run/whyfs/api.sock" if sys.platform == "darwin" else "/run/whyfs/api.sock"


class ServiceUnavailable(RuntimeError):
    pass


def dumps(obj) -> bytes:
    import json
    return (json.dumps(obj, default=str, separators=(",", ":")) + "\n").encode()


def call(op: str, params: dict | None = None, timeout: float = 30.0) -> dict:
    """One request to the local service; returns the reply dict."""
    req = (jsonlite.dumps({"v": PROTOCOL, "op": op, "params": params or {}}) + "\n").encode()
    if os.name == "nt":
        from . import winsecurity as ws
        raw = ws.pipe_client_call(PIPE_NAME, req, timeout)
    else:
        import socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(SOCKET_PATH)
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            raise ServiceUnavailable(f"the whyfs service is not running ({SOCKET_PATH}: {exc.strerror})")
        # /run/whyfs (macOS /var/run/whyfs) is root-owned: the socket cannot be planted by another user
        st = os.stat(os.path.dirname(SOCKET_PATH))
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise ServiceUnavailable(f"refusing {SOCKET_PATH}: its directory is not root-owned and private")
        s.sendall(req)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(1 << 16)
            if not chunk:
                break
            buf += chunk
        s.close()
        raw = buf
    if not raw:
        raise ServiceUnavailable("the whyfs service closed the connection")
    return jsonlite.loads(raw)
