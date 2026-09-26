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
  native start MODE DB       pause the Python ring consumer; hand the ring map fd to the native
                             spike (native/spike/spike_ingest, MODE discard|min) writing DB, or
                             (MODE full) to the production native collector writing the real store
  native stop                SIGTERM the spike (it drains and commits); reply with its stats
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
# --src selects which tree's production code this agent runs (before/after experiments).
_SRC = sys.argv[sys.argv.index("--src") + 1] if "--src" in sys.argv else str(REPO / "src")
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, _SRC)

import whyfs.ebpf_bcc as eb  # noqa: E402
from whyfs.ebpf_bcc import BCCCollector  # noqa: E402
from whyfs.privsep import Store  # noqa: E402
from v02_hotpath_profile import prog_stats, set_attached  # noqa: E402


def thread_metrics(tid: int | None) -> dict:
    """CPU and context switches of one thread of this process."""
    if not tid:
        return {}
    try:
        f = Path(f"/proc/self/task/{tid}/stat").read_text().rsplit(")", 1)[1].split()
        tck = os.sysconf("SC_CLK_TCK")
        out = {"utime_s": int(f[11]) / tck, "stime_s": int(f[12]) / tck}
        for line in Path(f"/proc/self/task/{tid}/status").read_text().splitlines():
            if line.startswith("voluntary_ctxt_switches"):
                out["vol_ctx"] = int(line.split()[1])
            elif line.startswith("nonvoluntary_ctxt_switches"):
                out["invol_ctx"] = int(line.split()[1])
        return out
    except OSError:
        return {}


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
    ap.add_argument("--src", default=str(REPO / "src"))
    ap.add_argument("--cflags", default="", help="extra BPF cflags (diagnostic variants), space separated")
    ap.add_argument("--native-diag", default="", help="native diagnostic mode: discard | no-store | flush-immediate")
    ap.add_argument("--native", action="store_true",
                    help="production native topology: BPF loaded here, one persistent whyfs-collect consumes the ring")
    a = ap.parse_args()
    if a.native:
        return native_main(a)
    ws = Path(a.workspace).resolve()
    mode = {"discard": False, "nostore": False}
    counters = {"resolve_calls": 0, "canon_calls": 0, "ingest_calls": 0, "ingest_rows": 0, "ingest_ns": 0}

    store = Store(ws).start()
    store.call("begin_run", a.run_id, time.time_ns(), str(ws))
    c = BCCCollector(ws, a.run_id, store=store, extra_cflags=a.cflags.split() if a.cflags else None)

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

    # Queue instrumentation (observes the handoff; works for per-record and batched code).
    q = c.q
    qs = {"puts": 0, "put_records": 0, "gets": 0, "get_waited": 0, "high_water_items": 0, "high_water_records_est": 0}
    orig_put, orig_get = q.put_nowait, q.get

    def put_nowait(item):
        orig_put(item)
        n = len(item) if isinstance(item, list) else 1
        qs["puts"] += 1
        qs["put_records"] += n
        size = q.qsize()
        qs["high_water_items"] = max(qs["high_water_items"], size)
        qs["high_water_records_est"] = max(qs["high_water_records_est"], size * n)

    def get(block=True, timeout=None):
        was_empty = q.empty()
        item = orig_get(block, timeout)
        qs["gets"] += 1
        if was_empty:
            qs["get_waited"] += 1  # the writer was blocked and had to be woken for this item
        return item

    q.put_nowait, q.get = put_nowait, get
    c.start()
    set_attached(c.bpf, False)  # BCC auto-attaches at load; the driver attaches per run
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            c.poll(50)  # as whyfs.daemon.run_foreground

    paused = threading.Event()
    idle = threading.Event()

    def loop():  # noqa: F811 (pausable variant: only one consumer may drain the ring)
        while not stop.is_set():
            if paused.is_set():
                idle.set()
                time.sleep(0.01)
                continue
            idle.clear()
            c.poll(50)

    native = {"p": None}
    spike = REPO / "native" / "spike" / "spike_ingest"
    th = threading.Thread(target=loop, daemon=True)
    th.start()

    def reply(obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    reply({"ready": True, "pid": os.getpid(), "store_pid": store.pid, "src": _SRC, "cflags": a.cflags,
           "batched_handoff": hasattr(c, "flush_pending")})
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
                       "store": proc_metrics(store.pid), "queue": dict(qs),
                       "threads": {"ring_consumer": thread_metrics(th.native_id),
                                   "writer": thread_metrics(c.writer.native_id),
                                   "main": thread_metrics(threading.main_thread().native_id)}})
            elif cmd[0] == "native" and cmd[1] == "start":
                paused.set()
                idle.wait(5)
                c.poll(0)  # anything already in the ring belongs to the previous run
                fd = c.bpf["events"].map_fd
                import subprocess
                if cmd[2] == "full":  # the production native collector, writing the real store as the owner
                    from whyfs import native_collect
                    from whyfs.privsep import workspace_owner
                    dfd = c.bpf["drop_count"].map_fd
                    args = [str(native_collect.binary()), "--ring-fd", str(fd), "--drop-fd", str(dfd), "--root", str(ws),
                            "--run-id", a.run_id]
                    for t in c.temp_roots:
                        args += ["--temp-root", t]
                    if store.privsep:
                        uid, gid = workspace_owner(ws)
                        args += ["--uid", str(uid), "--gid", str(gid)]
                    native["p"] = subprocess.Popen(args, pass_fds=(fd, dfd), stdout=subprocess.PIPE, text=True)
                else:
                    native["p"] = subprocess.Popen([str(spike), "--fd", str(fd), "--mode", cmd[2], "--workspace", str(ws),
                                                    "--db", cmd[3], "--run-id", a.run_id + "-native"],
                                                   pass_fds=(fd,), stdout=subprocess.PIPE, text=True)
                reply({"ok": True, "native_pid": native["p"].pid, "hello": json.loads(native["p"].stdout.readline())})
            elif cmd[0] == "native" and cmd[1] == "stop":
                import signal as _signal
                p = native["p"]
                p.send_signal(_signal.SIGTERM)
                out = p.communicate(timeout=30)[0]
                native["p"] = None
                paused.clear()
                reply({"native": json.loads(out.strip().splitlines()[-1]), "kernel_drops": c.kernel_drop_count()})
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


def native_main(a) -> int:
    """Persistent native collector exactly as whyfs.daemon.run_foreground wires it."""
    import signal as _signal
    from whyfs import native_collect
    from whyfs.privsep import workspace_owner

    ws = Path(a.workspace).resolve()
    store = Store(ws).start()
    store.call("begin_run", a.run_id, time.time_ns(), str(ws), "ebpf-native")
    c = BCCCollector(ws, a.run_id, store=store, extra_cflags=a.cflags.split() if a.cflags else None)
    c.load_programs()
    set_attached(c.bpf, False)
    extra = ((f"--diag-{a.native_diag}",) if a.native_diag in ("discard", "no-store")
             else (f"--{a.native_diag}",) if a.native_diag else ())
    n = native_collect.NativeIngest(c, ws, a.run_id, owner=workspace_owner(ws) if store.privsep else None,
                                    extra_args=extra).start()
    writer_pid = n.info.get("writer_pid")

    def reply(obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    reply({"ready": True, "pid": os.getpid(), "store_pid": store.pid, "native_pid": n.pid, "native_writer_pid": writer_pid,
           "src": _SRC, "cflags": a.cflags, "batched_handoff": True, "native": True})
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
                reply({"ok": True, "mode": "native"})
            elif cmd[0] == "bpfstats":
                Path("/proc/sys/kernel/bpf_stats_enabled").write_text("1" if cmd[1] == "on" else "0")
                reply({"ok": True})
            elif cmd[0] == "snap":
                n.p.send_signal(_signal.SIGUSR1)
                counters = json.loads(n.p.stdout.readline())
                reply({"stats": counters, "kernel_drops": c.kernel_drop_count(), "self": proc_metrics(os.getpid()),
                       "native": proc_metrics(n.pid), "native_writer": proc_metrics(writer_pid)})
            elif cmd[0] == "progstats":
                reply({str(k): v for k, v in prog_stats(c.bpf).items()})
            elif cmd[0] == "quit":
                break
            else:
                reply({"error": f"unknown command {cmd[0]}"})
        except Exception as exc:  # report, keep serving
            reply({"error": repr(exc)})
    final, status = n.stop()
    store.call("end_run", a.run_id, time.time_ns(), status, {k: int(v) for k, v in final.items()})
    store.close()
    c.bpf.cleanup()
    reply({"bye": True, "final": final, "status": status})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
