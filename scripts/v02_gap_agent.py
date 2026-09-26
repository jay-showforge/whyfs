#!/usr/bin/env python3
"""Diagnostic collector process for scripts/v02_daemon_gap.py (not a product component).

Runs the production collection path (BCCCollector + privilege-separated Store,
exactly as whyfs.daemon.run_foreground wires them) in its own process, and
takes line commands on stdin so the driver can change one variable at a time
without restarting it:

  attach | detach            attach/detach the loaded production BPF programs
  mode kernel_only           ring callback returns at once (kernel cost + consumption)
  mode no_store              full event processing; normalized records discarded before SQLite
  mode full                  full processing + SQLite (production behaviour)
  bpfstats on|off            kernel.bpf_stats_enabled
  snap                       JSON: collector stats, counters, /proc of self and store worker
  progstats                  JSON: run_cnt/run_time_ns per BPF program
  quit                       stop collector (drain), end run, exit

Replies are one JSON line each on stdout.  Nothing here times the workload.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

import whyfs.ebpf_bcc as eb  # noqa: E402
from whyfs.ebpf_bcc import BCCCollector  # noqa: E402
from whyfs.privsep import Store  # noqa: E402
from v02_hotpath_profile import prog_stats, set_attached  # noqa: E402


def proc_metrics(pid: int | None) -> dict:
    """Process-wide CPU, faults, context switches, migrations, I/O from /proc."""
    if not pid:
        return {}
    out = {}
    try:
        f = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        tck = os.sysconf("SC_CLK_TCK")
        out.update(minflt=int(f[7]), majflt=int(f[9]), utime_s=int(f[11]) / tck, stime_s=int(f[12]) / tck)
        vol = invol = mig = 0
        for t in Path(f"/proc/{pid}/task").iterdir():
            try:
                for line in (t / "status").read_text().splitlines():
                    if line.startswith("voluntary_ctxt_switches"):
                        vol += int(line.split()[1])
                    elif line.startswith("nonvoluntary_ctxt_switches"):
                        invol += int(line.split()[1])
                for line in (t / "sched").read_text().splitlines():
                    if line.startswith("se.nr_migrations"):
                        mig += int(line.split(":")[1])
            except OSError:
                pass
        out.update(vol_ctx=vol, invol_ctx=invol, migrations=mig)
        for line in Path(f"/proc/{pid}/io").read_text().splitlines():
            k, v = line.split(":")
            if k in ("wchar", "write_bytes", "syscw", "rchar", "read_bytes", "syscr"):
                out[k] = int(v)
    except OSError:
        pass
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--run-id", required=True)
    a = ap.parse_args()
    ws = Path(a.workspace).resolve()
    mode = {"discard": False, "nostore": False}
    counters = {"resolve_calls": 0, "canon_calls": 0, "ingest_calls": 0, "ingest_rows": 0, "ingest_ns": 0}

    store = Store(ws).start()
    store.call("begin_run", a.run_id, time.time_ns(), str(ws))
    c = BCCCollector(ws, a.run_id, store=store)

    orig_cb = c._process_event
    c._process_event = lambda ctx, data, size: None if mode["discard"] else orig_cb(ctx, data, size)
    orig_resolve = c._resolve

    def resolve(*args, **kw):
        counters["resolve_calls"] += 1
        return orig_resolve(*args, **kw)

    c._resolve = resolve
    orig_canon = eb._canon

    def canon(p):
        counters["canon_calls"] += 1
        return orig_canon(p)

    eb._canon = canon
    orig_ingest = store.ingest

    def ingest(events):
        if mode["nostore"]:
            return len(events)
        t0 = time.perf_counter_ns()
        n = orig_ingest(events)
        counters["ingest_ns"] += time.perf_counter_ns() - t0
        counters["ingest_calls"] += 1
        counters["ingest_rows"] += len(events)
        return n

    store.ingest = ingest
    c.start()
    set_attached(c.bpf, False)  # BCC auto-attaches at load; the driver attaches per run
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            c.poll(50)  # as whyfs.daemon.run_foreground

    th = threading.Thread(target=loop, daemon=True)
    th.start()

    def reply(obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    reply({"ready": True, "pid": os.getpid(), "store_pid": store.pid})
    for line in sys.stdin:
        cmd = line.split()
        if not cmd:
            continue
        try:
            if cmd[0] == "attach":
                set_attached(c.bpf, True)
                reply({"ok": True})
            elif cmd[0] == "detach":
                set_attached(c.bpf, False)
                reply({"ok": True})
            elif cmd[0] == "mode":
                mode["discard"] = cmd[1] == "kernel_only"
                mode["nostore"] = cmd[1] == "no_store"
                reply({"ok": True, "mode": cmd[1]})
            elif cmd[0] == "bpfstats":
                Path("/proc/sys/kernel/bpf_stats_enabled").write_text("1" if cmd[1] == "on" else "0")
                reply({"ok": True})
            elif cmd[0] == "snap":
                reply({"stats": {k: int(v) for k, v in vars(c.stats).items()}, "counters": dict(counters),
                       "kernel_drops": c.kernel_drop_count(), "writer_rows": c.writer.written,
                       "writer_batches": c.writer.batches, "self": proc_metrics(os.getpid()),
                       "store": proc_metrics(store.pid)})
            elif cmd[0] == "progstats":
                reply({str(k): v for k, v in prog_stats(c.bpf).items()})
            elif cmd[0] == "quit":
                break
            else:
                reply({"error": f"unknown command {cmd[0]}"})
        except Exception as exc:  # report, keep serving
            reply({"error": repr(exc)})
    stop.set()
    th.join(timeout=5)
    stats = c.stop()
    store.call("end_run", a.run_id, time.time_ns(), 0, {k: int(v) for k, v in vars(stats).items()})
    store.close()
    c.bpf.cleanup()
    reply({"bye": True, "final": {k: int(v) for k, v in vars(stats).items()}})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
