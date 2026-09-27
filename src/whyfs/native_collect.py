"""Locate, build and run the native ingestion helper (native/whyfs-collect.c).

The eBPF daemon's per-event path runs in this helper; Python keeps BPF loading
(BCC), daemon control, and every query.  Installed packages ship it prebuilt
(/usr/lib/whyfs/whyfs-collect); a source checkout compiles it at first use
(needs cc, libbpf-dev and libsqlite3-dev), like BCC compiles its programs.

The binary is cached by source hash.  A root daemon executes it, so a root
build lives only in a root-owned directory that no other user can write
(/var/cache/whyfs); an unprivileged build uses the user's own cache.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

SOURCE = Path(__file__).resolve().parent / "native" / "whyfs-collect.c"


class NativeUnavailable(RuntimeError):
    pass


def _cache_dir() -> Path:
    if os.geteuid() == 0:
        d = Path("/var/cache/whyfs")
        d.mkdir(mode=0o755, parents=True, exist_ok=True)
        _require_private_to_root(d)
        return d
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    d = base / "whyfs"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def _require_private_to_root(p: Path) -> None:
    """Every directory from / down to ``p`` is root-owned and not group/other-writable."""
    for q in [*reversed(p.parents), p]:
        st = os.lstat(q)
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise NativeUnavailable(f"refusing native helper cache {p}: {q} is not private to root")


def _flags() -> list[str]:
    pc = shutil.which("pkg-config")
    if pc:
        r = subprocess.run([pc, "--cflags", "--libs", "libbpf", "sqlite3"], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.split()
    return ["-lbpf", "-lelf", "-lz", "-lsqlite3"]


PACKAGED = Path("/usr/lib/whyfs/whyfs-collect")  # installed by the whyfs .deb (prebuilt per architecture)


def _packaged(digest: str) -> Path | None:
    """The prebuilt collector shipped by the distribution package, if it was built from
    exactly this source (recorded next to it at package build time) and sits in a location
    no one but root can modify (a root daemon executes it)."""
    stamp = PACKAGED.with_name("whyfs-collect.source-sha256")
    try:
        if not PACKAGED.is_file() or stamp.read_text().split()[0][:16] != digest:
            return None
        if os.geteuid() == 0:
            _require_private_to_root(PACKAGED.parent)
            st = os.lstat(PACKAGED)
            if st.st_uid != 0 or st.st_mode & 0o022:
                return None
        return PACKAGED
    except (OSError, IndexError, NativeUnavailable):
        return None


def binary() -> Path:
    """Path of the collector helper: the packaged prebuilt one, else a cached local build."""
    override = os.environ.get("WHYFS_COLLECT")
    if override:  # developer override; a root daemon still runs only a root-controlled file
        o = Path(override).resolve()
        if os.geteuid() == 0:
            _require_private_to_root(o.parent)
            st = os.lstat(o)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise NativeUnavailable(f"refusing WHYFS_COLLECT={override}: not a root-owned, root-only-writable file")
        return o
    src = SOURCE.read_bytes()
    digest = hashlib.sha256(src).hexdigest()[:16]
    pkg = _packaged(digest)
    if pkg:
        return pkg
    d = _cache_dir()
    out = d / f"whyfs-collect-{digest}"
    if out.exists():
        return out
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        raise NativeUnavailable("whyfs daemon needs a C compiler to build its native collector (install gcc or clang)")
    tmp = d / f".whyfs-collect-{digest}.{os.getpid()}"
    r = subprocess.run([cc, "-O2", "-Wall", "-o", str(tmp), str(SOURCE), *_flags()], capture_output=True, text=True)
    if r.returncode != 0:
        tmp.unlink(missing_ok=True)
        raise NativeUnavailable("could not build the native collector (install libbpf-dev and libsqlite3-dev):\n"
                                + r.stderr.strip()[-2000:])
    os.chmod(tmp, 0o755)
    os.replace(tmp, out)
    return out


def available() -> tuple[bool, str]:
    try:
        return True, str(binary())
    except (NativeUnavailable, OSError) as exc:
        return False, str(exc)


def replay(records: list[bytes], *, root: Path, run_id: str = "run", temp_roots=(), seeds=(), clock_offset: int | None = None,
           capture_all: bool = False) -> tuple[list[dict], dict]:
    """Run the native event model over raw ring payloads; return (records, stats).

    Records are the dicts BCCCollector hands to its writer (tests compare the two)."""
    import tempfile

    with tempfile.NamedTemporaryFile(prefix="whyfs-replay-", delete=False) as f:
        for r in records:
            f.write(len(r).to_bytes(4, "little") + r)
        name = f.name
    try:
        args = [str(binary()), "--replay", name, "--emit", "--root", str(root), "--run-id", run_id]
        for t in temp_roots:
            args += ["--temp-root", str(t)]
        for pid, cwd in seeds:
            args += ["--seed", f"{pid}:{cwd}"]
        if clock_offset is not None:
            args += ["--clock-offset", str(clock_offset)]
        if capture_all:
            args.append("--capture-all")
        p = subprocess.run(args, capture_output=True, check=True)
    finally:
        os.unlink(name)
    lines = p.stdout.decode().splitlines()
    stats = json.loads(lines[-1])
    out = []
    for line in lines[:-1]:
        d = json.loads(line)
        for k in ("path", "path2", "exe", "cwd", "command"):
            if isinstance(d.get(k), str):
                d[k] = bytes.fromhex(d[k]).decode("utf-8", "surrogateescape")
        out.append(d)
    return out, stats


class NativeIngest:
    """The daemon's ingestion process: consumes the loaded collector's ring buffer.

    ``collector`` is a BCCCollector after load_programs(); its BPF object stays in
    this (Python) process, which keeps the programs attached.  SQLite is written by
    the helper's forked writer, dropped to ``owner`` (uid, gid) when given."""

    def __init__(self, collector, root: Path, run_id: str, *, capture_all: bool = False,
                 owner: tuple[int, int] | None = None, extra_args: tuple[str, ...] = ()):
        self.collector, self.root, self.run_id = collector, root, run_id
        self.extra_args = tuple(extra_args)  # diagnostics only (--diag-discard / --diag-no-store)
        self.capture_all, self.owner = capture_all, owner
        self.p: subprocess.Popen | None = None
        self.info: dict = {}

    def start(self) -> "NativeIngest":
        ring_fd = self.collector.bpf["events"].map_fd
        drop_fd = self.collector.bpf["drop_count"].map_fd
        args = [str(binary()), "--ring-fd", str(ring_fd), "--drop-fd", str(drop_fd), "--root", str(self.root),
                "--run-id", self.run_id]
        for t in self.collector.temp_roots:
            args += ["--temp-root", t]
        if self.capture_all:
            args.append("--capture-all")
        if self.owner is not None:
            args += ["--uid", str(self.owner[0]), "--gid", str(self.owner[1])]
        args += self.extra_args
        self.p = subprocess.Popen(args, pass_fds=(ring_fd, drop_fd), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  text=True)
        line = self.p.stdout.readline()
        if not line:
            self.p.wait(timeout=10)
            raise RuntimeError(f"whyfs native collector failed to start (exit {self.p.returncode})")
        self.info = json.loads(line)
        return self

    @property
    def pid(self) -> int | None:
        return self.p.pid if self.p else None

    def alive(self) -> bool:
        return self.p is not None and self.p.poll() is None

    def stop(self, timeout: float = 120.0) -> tuple[dict, int]:
        """Signal a final drain; return (collector stats, exit status)."""
        import signal

        try:
            self.p.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            pass
        out, _ = self.p.communicate(timeout=timeout)
        lines = [x for x in out.splitlines() if x.strip()]
        stats = json.loads(lines[-1]) if lines else {}
        return stats, self.p.returncode
