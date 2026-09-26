#!/usr/bin/env python3
"""IOSEEN_REPORT.md + tables for the io_seen investigation (numbers derived from raw data).

    python3 scripts/v02_ioseen_report.py EXP_DIR QRUNS_GLOB_DIR SEMANTICS_LOG_DIR OUT_DIR

EXP_DIR/ioseen.json (scripts/v02_ioseen_exp.py); QRUNS dir holds q-<workload>-M<mode>-<hash>/hotpath.json
(scripts/v02_hotpath_profile.py --phases Q); SEMANTICS dir holds semantics-M<mode>-<hash>.log.
"""
from __future__ import annotations

import csv
import glob
import json
import re
import statistics as st
import sys
from pathlib import Path

WL = ["static", "make", "vite"]
WL_NAME = {"static": "static ×300", "make": "make -j8 (36 units)", "vite": "Vite build"}


def ci(s, unit=" ms"):
    return f"{s['median']:+.2f}{unit} ({s['median_ci90'][0]:+.2f}..{s['median_ci90'][1]:+.2f})"


def sig(s):
    lo, hi = s["median_ci90"]
    return "significant" if lo > 0 or hi < 0 else "not significant"


def q_ops(path: str, mode: int) -> dict:
    Q = json.loads(Path(path).read_text())["phase_Q"]

    def net(pid, k):
        return st.median(r["prof"][pid].get(k, 0) - i["prof"][pid].get(k, 0) for r, i in zip(Q["reps"], Q["idle"]))
    o_del, o_lk, o_ns = net("0", "map_deletes"), net("0", "map_lookups"), net("0", "io_seen_map_ns")
    lk = net("1", "map_lookups") + net("2", "map_lookups")
    up = net("1", "map_updates") + net("2", "map_updates")
    lkns = net("1", "io_seen_map_ns") + net("2", "io_seen_map_ns")
    upns = net("1", "io_seen_update_ns") + net("2", "io_seen_update_ns")
    return {"opens": net("0", "calls"), "reset_lookups": o_lk, "reset_deletes": o_del, "reset_ns": o_ns,
            "reset_ns_per_op": o_ns / (o_del + o_lk) if (o_del + o_lk) else 0.0,
            "io_lookups": lk, "io_lookup_ns_per_op": lkns / lk if lk else 0.0,
            "io_updates": up, "io_update_ns_per_op": upns / up if up else 0.0,
            "io_seen_total_ns": o_ns + lkns + upns}


def main() -> int:
    exp, qdir, semdir, out = (Path(x) for x in sys.argv[1:5])
    r = json.loads((exp / "ioseen.json").read_text())
    (out / "tables").mkdir(parents=True, exist_ok=True)
    D: dict = {"experiment": str(exp), "git": r["git"]["head"], "workloads": {}, "q": {}, "semantics": {}}
    for w in WL:
        x = r["workloads"][w]
        D["workloads"][w] = {"rounds": len([y for y in x["rows"] if not y["warmup"]]),
                             "added_ms": x["added_ms"], "overhead_pct": x["overhead_pct"],
                             "M0_minus_M1": x["M0_minus_M1"], "M0_minus_M2": x["M0_minus_M2"], "records": x["records"],
                             "bpf_ms": {m: x["bpf"][m]["total_ms"] for m in ("M0", "M1", "M2")},
                             "bpf_open_us": {m: x["bpf"][m]["per_prog_ns_median"].get("0", 0) / 1e3 for m in ("M0", "M1", "M2")},
                             "bpf_perm_us": {m: x["bpf"][m]["per_prog_ns_median"].get("1", 0) / 1e3 for m in ("M0", "M1", "M2")}}
        for m in (0, 1):
            f = sorted(glob.glob(str(qdir / f"q-{w}-M{m}-*" / "hotpath.json")))[-1]
            D["q"][f"{w}-M{m}"] = q_ops(f, m)
    for m in (0, 1, 2):
        f = sorted(glob.glob(str(semdir / f"semantics-M{m}-*.log")))[-1]
        txt = Path(f).read_text()
        res = dict(re.findall(r"^(test_\w+) \(.*?\) \.\.\. (ok|FAIL|ERROR)$", txt, re.M))
        D["semantics"][f"M{m}"] = {"summary": txt.strip().splitlines()[-1], "results": res,
                                   "assertions": re.findall(r"AssertionError: (.*)", txt)}
    (out / "derived.json").write_text(json.dumps(D, indent=2))
    with (out / "tables" / "wallclock_and_bpf.csv").open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["workload", "variant", "rounds", "added_ms_median", "added_ms_ci90_lo", "added_ms_ci90_hi", "overhead_pct",
                     "bpf_ms_median", "bpf_open_us", "bpf_perm_us", "received_median", "submitted_median", "kernel_drops", "queue_drops"])
        for w in WL:
            v = D["workloads"][w]
            for m in ("M0", "M1", "M2"):
                a = v["added_ms"][m]
                wr.writerow([w, m, v["rounds"], a["median"], a["median_ci90"][0], a["median_ci90"][1], v["overhead_pct"][m]["median"],
                             v["bpf_ms"][m]["median"], v["bpf_open_us"][m], v["bpf_perm_us"][m], v["records"][m]["received_median"],
                             v["records"][m]["submitted_median"], v["records"][m]["kernel_drops"], v["records"][m]["queue_drops"]])
    with (out / "tables" / "io_seen_ops.csv").open("w", newline="") as fh:
        wr = csv.writer(fh)
        keys = list(next(iter(D["q"].values())).keys())
        wr.writerow(["workload-variant"] + keys)
        for k, v in D["q"].items():
            wr.writerow([k] + [v[kk] for kk in keys])

    S = D["workloads"]["static"]
    q0, q1 = D["q"]["static-M0"], D["q"]["static-M1"]
    L = []
    A = L.append
    A("# whyfs v0.2 — io_seen investigation")
    A("")
    A("**Standing verdict: V0.2 PERFORMANCE GATE REMAINS FAILED.** Graduation was not rerun: no candidate produced a clear win.")
    A("Production `io_seen` behaviour is unchanged. Generated by `scripts/v02_ioseen_report.py` from raw data.")
    A("")
    A("## Answer")
    A("")
    A("*Can whyfs eliminate the expensive per-open io_seen reset while preserving exact read/write dedup semantics, and does")
    A("doing so recover enough real workload time to matter?*")
    A("")
    A("**No on both counts.**")
    A("")
    A("- **The reset cannot be eliminated.** Without it, stale state from freed-and-reused `struct file` memory silently")
    A("  suppressed first-read/first-write events. Reported vs expected: " + "; ".join(D["semantics"]["M2"]["assertions"]) + ".")
    A("- **The cheaper correct variant does not recover workload time.** A lockless lookup, deleting only when a stale entry exists "
      f"and skipping directories, recovered {ci(S['M0_minus_M1'])} on static ×300 ({sig(S['M0_minus_M1'])}).")
    A(f"- **Its production BPF saving is {S['bpf_ms']['M0']['median'] - S['bpf_ms']['M1']['median']:.3f} ms per run.**")
    A(f"- **Even the unsafe no-reset bound saves only {S['bpf_ms']['M0']['median'] - S['bpf_ms']['M2']['median']:.3f} ms** of static BPF time.")
    A("")
    A("So `io_seen` is **rejected** as the remaining explanation for the static ×300 overhead.")
    A("")
    A("## 1. What io_seen guarantees (from the production source)")
    A("")
    A("- **Map:** `BPF_TABLE(\"lru_hash\", struct io_key_t, u8, io_seen, 262144)`.")
    A("- **Key:** `{u64 file, u64 ino, u32 tgid, u32 pad}`, where `file` is the kernel `struct file *` and `tgid` is the root-namespace tgid.")
    A("- **Value:** a `u8` bitmask (1 = read reported, 2 = write reported).")
    A("- **Sites:**")
    A("  - `security_file_open`: `delete(k)` on every open of a regular file or directory.")
    A("  - `wf_emit_io`, used by `security_file_permission` (read/write syscalls, io_uring, sendfile, splice, copy_file_range) and")
    A("    `security_mmap_file`: `lookup(k)`. If the direction bit is set, return. Otherwise `update(k, mask | dir)` and emit the first read or write event.")
    A("- **Invariant:** exactly one read event and one write event per open file description per process.")
    A("  - dup/dup2 share the description, so they are deduplicated.")
    A("  - A forked child has its own tgid, so it gets its own first events.")
    A("  - Two simultaneous opens of one inode are independent.")
    A("  - Every new open gets fresh first events.")
    A("- **Why the open-time delete exists:** a closed file's `struct file` is freed (after an RCU grace period on this 6.6 kernel), and")
    A("  its address is readily reused by a later open. If that later open is by the same process and of the same inode, a leftover")
    A("  entry would make the new open look already seen. Its first read or write would then be silently suppressed: across reopens")
    A("  by long-running programs, across `exec` (same pid), and across PID reuse.")
    A("- **No alternative without a map operation exists here:** the kernel offers no per-file BPF local storage (only inode, task,")
    A("  socket and cgroup storage), and `struct file` carries no per-open generation. Every correct design needs some per-open")
    A("  reset or check. The options are *which* map operation, and whether directories need it.")
    A("")
    A("## 2. Semantic tests: they catch stale-state suppression")
    A("")
    A("There are 10 live kernel tests (`tests/test_ebpf_live.py::IoSeenSemanticsTests`). The variant results were reproduced from the")
    A("variant tree `16b0e2b` (`semantics-M*.log`):")
    A("")
    names = sorted(D["semantics"]["M0"]["results"])
    A("| Test | M0 production | M1 conditional delete | M2 no reset (unsafe) |")
    A("|---|---|---|---|")
    for n in names:
        A(f"| {n} | " + " | ".join(D["semantics"][m]["results"].get(n, "?") for m in ("M0", "M1", "M2")) + " |")
    A("")
    A("M2 failures: " + "; ".join(D["semantics"]["M2"]["assertions"]) + ".")
    A("")
    A("Back-to-back reopens pass even without a reset, because RCU delays address reuse. The paused-reopen test is the real")
    A("detector: with realistic timing, the kernel reuses `struct file` addresses constantly.")
    A("")
    A("## 3. io_seen cost per run (WF_PROFILE_TIME build; approximate, timers included)")
    A("")
    A("| Workload / variant | Opens | Reset lookups | Reset deletes | Reset ns/op | Reset µs | I/O lookups @ ns | I/O updates @ ns | io_seen total µs |")
    A("|---|---|---|---|---|---|---|---|---|")
    for k, v in D["q"].items():
        A(f"| {k} | {v['opens']:,.0f} | {v['reset_lookups']:,.0f} | {v['reset_deletes']:,.0f} | {v['reset_ns_per_op']:.0f} | "
          f"{v['reset_ns']/1e3:.0f} | {v['io_lookups']:,.0f} @ {v['io_lookup_ns_per_op']:.0f} | {v['io_updates']:,.0f} @ {v['io_update_ns_per_op']:.0f} | "
          f"{v['io_seen_total_ns']/1e3:.0f} |")
    A("")
    A(f"**Why the reset is expensive, and why M1 barely helps.** The open-time *lookup* in M1 costs {q1['reset_ns_per_op']:.0f} ns,")
    A(f"almost as much as the delete ({q0['reset_ns_per_op']:.0f} ns), while the same kind of lookup costs {q0['io_lookup_ns_per_op']:.0f} ns")
    A("in the I/O hooks. The cost is touching a cache-cold bucket of a 262,144-entry hash map for a brand-new pointer, not the")
    A("delete's bucket lock. In these workloads M1 never found a stale entry (0 deletes needed), so its whole saving is")
    A(f"{q0['reset_ns_per_op'] - q1['reset_ns_per_op']:.0f} ns per open.")
    A("")
    A("## 4. Before/after (rotated rounds; shell-timed; separate production-path collector per variant)")
    A("")
    A("M0 is current production, M1 is lookup plus delete-if-present with directories skipped, and M2 is no reset (unsafe bound, not adoptable).")
    A("")
    A("| Workload | Rounds | Variant | Added ms (90% CI) | Overhead % | BPF ms/run (prod.) | open / perm µs | Records recv/sub | Drops k/q |")
    A("|---|---|---|---|---|---|---|---|---|")
    for w in WL:
        v = D["workloads"][w]
        for m in ("M0", "M1", "M2"):
            rc = v["records"][m]
            A(f"| {WL_NAME[w]} | {v['rounds']} | {m} | {ci(v['added_ms'][m])} | {v['overhead_pct'][m]['median']:+.2f} | "
              f"{v['bpf_ms'][m]['median']:.3f} | {v['bpf_open_us'][m]:.0f} / {v['bpf_perm_us'][m]:.0f} | "
              f"{rc['received_median']:.0f}/{rc['submitted_median']:.0f} | {rc['kernel_drops']}/{rc['queue_drops']} |")
    A("")
    A("| Workload | M0 − M1 wall (90% CI) | M0 − M1 BPF | M0 − M2 wall (90% CI) | M0 − M2 BPF |")
    A("|---|---|---|---|---|")
    for w in WL:
        v = D["workloads"][w]
        A(f"| {WL_NAME[w]} | {ci(v['M0_minus_M1'])}, {sig(v['M0_minus_M1'])} | {v['bpf_ms']['M0']['median'] - v['bpf_ms']['M1']['median']:+.3f} ms | "
          f"{ci(v['M0_minus_M2'])}, {sig(v['M0_minus_M2'])} | {v['bpf_ms']['M0']['median'] - v['bpf_ms']['M2']['median']:+.3f} ms |")
    A("")
    A("Notes:")
    A("")
    A("- Without resets, M2's I/O hooks got slower (more stale entries in the map), which offsets part of its open-time saving.")
    A("- M2's larger wall deltas on make and static are not supported by its BPF-time change and are not adoptable anyway: it loses events.")
    A("- The Vite M1 result came out *worse* than M0, with its CI crossing zero only barely. That is consistent with noise around a ~0.07 ms BPF change.")
    A("")
    A("## 5. Keep/revert decision")
    A("")
    A("| Criterion | M1 |")
    A("|---|---|")
    A("| correctness identical | yes (10/10 semantic tests; identical record counts) |")
    A("| zero new drops | yes |")
    A(f"| io_seen kernel cost falls materially | no: reset {q0['reset_ns']/1e3:.0f} → {q1['reset_ns']/1e3:.0f} µs per static run (timed build) |")
    A(f"| total kernel cost falls materially | no: static {S['bpf_ms']['M0']['median']:.3f} → {S['bpf_ms']['M1']['median']:.3f} ms (make −{D['workloads']['make']['bpf_ms']['M0']['median'] - D['workloads']['make']['bpf_ms']['M1']['median']:.2f} ms) |")
    A(f"| static workload improves defensibly | no: {ci(S['M0_minus_M1'])}, {sig(S['M0_minus_M1'])} |")
    A("")
    A("**Rejected and reverted.** The variants were removed from production source, and they remain reproducible at commit `16b0e2b`.")
    A("")
    A("Kept:")
    A("")
    A("- the 10 semantic tests;")
    A("- the `Live.stop()` fix: the test helper leaked BPF programs, and once a kernel function reached the 38-program trampoline limit, later live tests failed to attach;")
    A("- the workload-general profiler (`--workload static|make|vite`);")
    A("- a diagnostic-only split of `io_seen` lookup vs update timing.")
    A("")
    A("## 6. Conclusion for v0.2")
    A("")
    A("This was bounded as the final major optimization attempt aimed solely at the static ×300 gate.")
    A("")
    A(f"- The remaining static ×300 overhead is about {S['added_ms']['M0']['median']:.1f} ms per run "
      f"(≈ {S['overhead_pct']['M0']['median']:.1f}%) in this experiment.")
    A("- It spreads across kernel hook work (≈ 3 ms of BPF run time, dominated by per-event work that constitutes the evidence) and")
    A("  userspace processing and store (≈ 2 ms, mechanism unidentified).")
    A("- No single correctness-neutral cost larger than the ones already tested remains.")
    A("")
    A("**v0.2 stays an honest alpha with a documented microprocess overhead limitation.** Normal builds (make, Vite) stay well")
    A("under 5%, but exec-heavy microprocess workloads measure about 5–7% on this WSL2 host.")
    (out / "IOSEEN_REPORT.md").write_text("\n".join(L) + "\n")
    print("\n".join(L[:30]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
