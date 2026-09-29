"""Observe what programs run, with Endpoint Security (macOS test helper; run as root).

A second Endpoint Security client (the WhyFS collector binary, recording every message it
receives: --es-record) runs next to the service while a test does something, then reports every
program executed (pid, parent, image, argv).  Tests use it where the thing under test starts
programs in contexts they cannot instrument -- a Finder Quick Action runs inside Automator's XPC
service, with its own environment -- so what ran is shown by the operating system itself.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

COLLECTOR = "/Library/WhyFS/WhyFSCollector.app/Contents/MacOS/whyfs-collect"


class Execs:
    def __init__(self, binary: str = COLLECTOR):
        self.binary = binary
        self.dir = Path(tempfile.mkdtemp(prefix="whyfs-observe-"))
        self.cap = self.dir / "capture.jsonl"
        self.proc = None
        self.execs: list[dict] = []

    def __enter__(self):
        (self.dir / "scope.conf").write_text("exclude /\n")  # nothing is recorded as evidence
        self.proc = subprocess.Popen([self.binary, "--es", "--machine", "--scope", str(self.dir / "scope.conf"),
                                      "--root", str(self.dir), "--run-id", "observe", "--emit", "--es-record", str(self.cap)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        first = json.loads(self.proc.stdout.readline() or "{}")
        if not first.get("ready"):
            raise RuntimeError(f"observer did not start: {first}")
        time.sleep(0.5)
        return self

    def __exit__(self, *exc):
        time.sleep(1.0)
        self.proc.send_signal(signal.SIGTERM)
        self.proc.wait(timeout=60)
        for line in self.cap.read_text().splitlines():
            m = json.loads(line)
            if m.get("type") == "exec":
                t = m.get("target") or {}
                self.execs.append({"pid": t.get("pid"), "ppid": t.get("ppid"), "exe": t.get("exe"), "argv": m.get("argv") or [],
                                   "ts": m.get("ts")})
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)  # the raw capture holds every program's arguments
        return False

    def browser_opened_by(self, pid: int) -> bool:
        """``pid`` (a `whyfs ui`) handed its address to the browser: it ran osascript or open."""
        return any(os.path.basename(e["exe"] or "") in ("osascript", "open") for e in self.children_of(pid))

    def matching(self, *parts: str) -> list[dict]:
        """Executions whose argv contains every one of ``parts`` (each as a whole argument)."""
        return [e for e in self.execs if all(p in e["argv"] for p in parts)]

    def children_of(self, pid: int) -> list[dict]:
        return [e for e in self.execs if e["ppid"] == pid]
