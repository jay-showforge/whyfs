"""The local human interface: search the provenance index and read file labels in a browser.

`whyfs ui [--file F [--view label|impact|history]] [--path DIR]` opens it (the Explorer and
file-manager menu entries run exactly this).  Nothing new is recorded or stored here: the page
asks the whyfs service through the same local API agents use (docs/AGENT_PROTOCOL.md), as the
user who opened it, so it shows exactly what that user may see.

The page is served by a small per-user process bound to 127.0.0.1 on a random port.  It is
reachable only with a cookie that a one-time launch token (60 s, single use) sets; the launch
token comes from a per-user state file only that user can read.  Requests must also carry the
X-Whyfs header (no cross-site form can) and the exact 127.0.0.1 Host (no DNS rebinding).  The
process exits after IDLE_S without requests.  It never modifies files.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from .client import ServiceUnavailable, call

IDLE_S = 30 * 60
LAUNCH_TTL_S = 60
COOKIE = "whyfs_ui"
# read-only operations the page may ask for
READ_OPS = {"search_files", "get_file_provenance", "get_file_history", "get_file_dependents", "get_file_inputs",
            "get_agent_session", "get_files_by_agent", "get_recent_changes", "list_agent_sessions", "status"}
PAGE = Path(__file__).with_name("ui.html")


def state_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "whyfs"
    else:
        rt = os.environ.get("XDG_RUNTIME_DIR")
        base = Path(rt) / "whyfs" if rt and _own_private_dir(rt) else Path.home() / ".cache" / "whyfs"
    return base / "ui.json"


def _own_private_dir(d: str) -> bool:
    """XDG_RUNTIME_DIR is used only when it is this user's own private directory (su/runuser can
    pass another user's value through)."""
    try:
        st = os.stat(d)
    except OSError:
        return False
    return st.st_uid == os.getuid() and not st.st_mode & 0o077


def _write_state(d: dict) -> None:
    p = state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(p.parent, 0o700)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f)
    os.replace(tmp, p)


def _read_state() -> dict | None:
    try:
        return json.loads(state_path().read_text())
    except (OSError, ValueError):
        return None


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.port = self.server_address[1]
        self.master = secrets.token_urlsafe(32)   # in the state file: mints launch tokens
        self.session = secrets.token_urlsafe(32)  # the cookie
        self.launch: dict[str, float] = {}
        self.lock = threading.Lock()
        self.last = time.monotonic()

    def new_launch_token(self) -> str:
        t = secrets.token_urlsafe(24)
        with self.lock:
            now = time.monotonic()
            self.launch = {k: v for k, v in self.launch.items() if v > now}
            self.launch[t] = now + LAUNCH_TTL_S
        return t

    def use_launch_token(self, t: str) -> bool:
        with self.lock:
            exp = self.launch.pop(t, None)
        return exp is not None and exp > time.monotonic()


def reveal(path: str) -> bool:
    """Show the file in the system file manager (selects it on Windows)."""
    if not os.path.isabs(path) or not os.path.exists(path):
        return False
    if os.name == "nt":
        subprocess.Popen(["explorer.exe", "/select,", os.path.normpath(path)])
    else:
        target = path if os.path.isdir(path) else os.path.dirname(path)
        subprocess.Popen(["xdg-open", target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return True


class _Handler(BaseHTTPRequestHandler):
    server: _Server
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # no request log: paths are private
        pass

    def _send(self, code: int, body: bytes = b"", ctype: str = "text/plain; charset=utf-8", headers: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'unsafe-inline'; connect-src 'self'; img-src data:; frame-ancestors 'none'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _host_ok(self) -> bool:
        return self.headers.get("Host") == f"127.0.0.1:{self.server.port}"

    def _cookie_ok(self) -> bool:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE and secrets.compare_digest(v, self.server.session):
                return True
        return False

    def do_GET(self):
        self.server.last = time.monotonic()
        if not self._host_ok():
            return self._send(421, b"wrong host")
        u = urlparse(self.path)
        if u.path == "/launch":
            q = parse_qs(u.query)
            if not self.server.use_launch_token((q.get("t") or [""])[0]):
                return self._send(403, b"This WhyFS link has expired. Open WhyFS again from the menu.")
            frag = "&".join(f"{k}={quote(q[k][0], safe='')}" for k in ("file", "view", "path") if q.get(k))
            return self._send(303, headers={
                "Location": "/#" + frag,
                "Set-Cookie": f"{COOKIE}={self.server.session}; HttpOnly; SameSite=Strict; Path=/"})
        if u.path == "/":
            if not self._cookie_ok():
                return self._send(403, b"Open WhyFS from its menu entry or with `whyfs ui`.")
            return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        return self._send(404, b"not found")

    def do_POST(self):
        self.server.last = time.monotonic()
        if not self._host_ok():
            return self._send(421, b"wrong host")
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1 << 20:
            return self._send(413, b"too large")
        body = self.rfile.read(n)
        if self.path == "/token":  # a later `whyfs ui` asking this server for a launch token
            auth = self.headers.get("Authorization") or ""
            if not secrets.compare_digest(auth, f"Bearer {self.server.master}"):
                return self._send(403, b"forbidden")
            return self._send(200, json.dumps({"t": self.server.new_launch_token()}).encode(), "application/json")
        if self.path != "/api":
            return self._send(404, b"not found")
        origin = self.headers.get("Origin")
        if (not self._cookie_ok() or self.headers.get("X-Whyfs") != "1"
                or (origin and origin != f"http://127.0.0.1:{self.server.port}")):
            return self._send(403, b"forbidden")
        try:
            req = json.loads(body or b"{}")
            op, params = req.get("op"), req.get("params") or {}
            if op == "reveal":
                reply = {"ok": reveal(str(params.get("path") or ""))}
            elif op in READ_OPS:
                reply = call(op, params)
            else:
                reply = {"ok": False, "error": f"operation not available here: {op}"}
        except ServiceUnavailable as exc:
            reply = {"ok": False, "error": f"{exc}. The whyfs service records and answers labels; start it and retry."}
        except (ValueError, TypeError) as exc:
            reply = {"ok": False, "error": f"bad request: {exc}"}
        return self._send(200, json.dumps(reply, default=str).encode(), "application/json")


def serve() -> int:
    srv = _Server()
    _write_state({"port": srv.port, "master": srv.master, "pid": os.getpid()})
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        while time.monotonic() - srv.last < IDLE_S:
            time.sleep(5)
    finally:
        srv.shutdown()
        st = _read_state()
        if st and st.get("port") == srv.port:
            try:
                state_path().unlink()
            except OSError:
                pass
    return 0


def _token_from(st: dict) -> str | None:
    import urllib.request
    req = urllib.request.Request(f"http://127.0.0.1:{st['port']}/token", data=b"{}", method="POST",
                                 headers={"Authorization": f"Bearer {st['master']}", "Host": f"127.0.0.1:{st['port']}"})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.loads(r.read())["t"]
    except (OSError, ValueError, KeyError):
        return None


def _start_server() -> dict:
    """Start the per-user server detached from this process; return its state."""
    before = _read_state()
    argv = [sys.executable, "-B", "-m", "whyfs", "ui", "--serve"]
    import tempfile
    err = tempfile.TemporaryFile()  # the server's start-up errors, reported if it does not come up
    if os.name == "nt":
        exe = Path(sys.executable)
        w = exe.with_name("pythonw.exe")
        argv[0] = str(w if w.exists() else exe)
        proc = subprocess.Popen(argv, creationflags=0x00000008 | 0x00000200 | 0x08000000,  # DETACHED | NEW_GROUP | NO_WINDOW
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err, close_fds=True)
    else:
        proc = subprocess.Popen(argv, start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=err, close_fds=True)
    deadline = time.time() + 15
    while time.time() < deadline and proc.poll() is None:
        st = _read_state()
        if st and st != before:
            return st
        time.sleep(0.1)
    err.seek(0)
    tail = err.read().decode(errors="replace").strip().splitlines()[-1:]
    raise SystemExit("whyfs: the WhyFS window could not be started" + (f": {tail[0]}" if tail else ""))


def launch_url(file: str | None = None, view: str | None = None, path: str | None = None) -> str:
    st = _read_state()
    t = _token_from(st) if st else None
    if not t:
        st = _start_server()
        t = _token_from(st)
        if not t:
            raise SystemExit("whyfs: the WhyFS window did not answer")
    q = f"t={quote(t)}"
    if file:
        q += "&file=" + quote(os.path.abspath(file), safe="")
    if view:
        q += "&view=" + quote(view, safe="")
    if path:
        q += "&path=" + quote(os.path.abspath(path), safe="")
    return f"http://127.0.0.1:{st['port']}/launch?{q}"


def open_ui(file=None, view=None, path=None, print_url=False) -> int:
    url = launch_url(file, view, path)
    if print_url:
        print(url)
        return 0
    if os.environ.get("WHYFS_UI_BROWSER") == "none":
        # headless machines (CI) and tests: hand the one-time address to the user's private state
        # directory instead of a browser, so the menu entries can be exercised without a display
        p = state_path().with_name("last-launch.url")
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(url)
        return 0
    if os.name == "nt":
        os.startfile(url)  # noqa: S606 -- the user's default browser
    else:
        import webbrowser
        if not webbrowser.open(url):
            print(f"Open this address in a browser (valid for {LAUNCH_TTL_S} s): {url}")
    return 0
