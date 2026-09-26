"""Live kernel regression tests for the v0.2 eBPF backend.

These load the real BPF program and drive real processes.  They are skipped
unless the host can actually run the collector (Linux, root/CAP_BPF, BCC,
kernel headers).  No fallback backend is substituted.
"""
import os
import shutil
import sqlite3
import subprocess
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

from whyfs.daemon import capability_report, ensure_kernel_headers
from whyfs.ebpf_bcc import BCCCollector
from whyfs.query import history, impact, why
from whyfs.store import connect

try:
    ensure_kernel_headers()
    READY = capability_report()["ready"] and shutil.which("gcc") is not None
except Exception:  # pragma: no cover
    READY = False


class Live:
    """Run the real collector in-process with a background ring-buffer poller."""

    def __init__(self, root: Path, *, poll: bool = True):
        self.root = root.resolve()
        con = connect(self.root)
        con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
                    ("live", time.time_ns(), str(self.root), "live-test", str(self.root), "ebpf-bcc"))
        con.commit()
        con.close()
        self.c = BCCCollector(self.root, "live")
        self.c.start()
        self._stop = threading.Event()
        self.poll = poll
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        while not self._stop.is_set():
            if self.poll:
                self.c.poll(50)
            else:
                time.sleep(0.02)

    def stop(self):
        self._stop.set()
        self.t.join(timeout=5)
        self.stats = self.c.stop()
        return self.stats


def sh(cmd: str, cwd: Path):
    return subprocess.run(["bash", "-c", cmd], cwd=cwd, check=True, capture_output=True, text=True)


def cc(root: Path, name: str, code: str, *flags: str) -> Path:
    src = root / f"{name}.c"
    src.write_text(textwrap.dedent(code))
    out = root / name
    subprocess.run(["gcc", "-O2", *flags, str(src), "-o", str(out)], check=True, capture_output=True)
    return out


@unittest.skipUnless(READY, "requires Linux + root/CAP_BPF + BCC + kernel headers")
class LiveKernelTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(prefix="whyfs-live-")
        self.root = Path(self.td.name).resolve()

    def tearDown(self):
        self.td.cleanup()

    def con(self):
        return connect(self.root)

    def test_static_binary_lineage(self):
        prog = cc(self.root, "static_copy", r"""
            #include <stdio.h>
            int main(int c, char **v) { FILE *i = fopen(v[1], "rb"), *o = fopen(v[2], "wb");
              char b[4096]; size_t n; while ((n = fread(b, 1, sizeof b, i)) > 0) fwrite(b, 1, n, o);
              fclose(i); fclose(o); return 0; }""", "-static")
        self.assertNotIn(b"INTERP", subprocess.run(["readelf", "-l", str(prog)], capture_output=True).stdout)
        (self.root / "raw.txt").write_text("static\n")
        s = Live(self.root)
        sh("./static_copy raw.txt out.txt", self.root)
        s.stop()
        w = why(self.con(), str(self.root / "out.txt"))
        self.assertEqual(Path(w["exe"]).name, "static_copy")
        self.assertEqual(w["inputs"], [str(self.root / "raw.txt")])
        self.assertIn("raw.txt out.txt", w["command"])

    def test_shell_redirection_and_short_lived_child(self):
        (self.root / "in.txt").write_text("abc\n")
        s = Live(self.root)
        sh("tr a-z A-Z < in.txt > out.txt", self.root)
        s.stop()
        w = why(self.con(), str(self.root / "out.txt"))
        self.assertEqual(Path(w["exe"]).name, "tr")
        self.assertEqual(w["inputs"], [str(self.root / "in.txt")])

    def test_fd_reuse_by_pipe_is_not_file_io(self):
        cc(self.root, "fdreuse", r"""
            #include <fcntl.h>
            #include <unistd.h>
            int main(void) { char b[64]; int fd = open("in.txt", O_RDONLY); read(fd, b, sizeof b); close(fd);
              int p[2]; pipe(p); write(p[1], "x", 1); /* p[0]/p[1] re-use fd numbers */
              int o = open("out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644); write(o, "y", 1); close(o); return 0; }""")
        (self.root / "in.txt").write_text("in\n")
        s = Live(self.root)
        sh("./fdreuse", self.root)
        s.stop()
        con = self.con()
        wrote_in = con.execute("SELECT COUNT(*) FROM events WHERE path=? AND is_write=1",
                               (str(self.root / "in.txt"),)).fetchone()[0]
        self.assertEqual(wrote_in, 0, "a pipe write must not be recorded as a write to the closed input")
        w = why(con, str(self.root / "out.txt"))
        self.assertEqual(Path(w["exe"]).name, "fdreuse")
        self.assertEqual(w["inputs"], [str(self.root / "in.txt")])

    def test_multithreaded_process_and_early_thread_exit(self):
        cc(self.root, "threads", r"""
            #include <pthread.h>
            #include <fcntl.h>
            #include <unistd.h>
            static void *reader(void *a) { char b[64]; int fd = open("in.txt", O_RDONLY); read(fd, b, sizeof b); close(fd); return 0; }
            static void *writer(void *a) { int fd = open("side.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644); write(fd, "s", 1); close(fd); return 0; }
            int main(void) { pthread_t r, w; pthread_create(&r, 0, reader, 0); pthread_join(r, 0);  /* thread exits */
              int fd = open("out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
              pthread_create(&w, 0, writer, 0); pthread_join(w, 0);
              write(fd, "o", 1); close(fd); return 0; }""", "-pthread")
        (self.root / "in.txt").write_text("in\n")
        s = Live(self.root)
        sh("./threads", self.root)
        s.stop()
        con = self.con()
        w = why(con, str(self.root / "out.txt"))
        self.assertEqual(Path(w["exe"]).name, "threads")
        self.assertEqual(w["inputs"], [str(self.root / "in.txt")], "a finished thread must not erase the process fd table")
        self.assertEqual(Path(why(con, str(self.root / "side.txt"))["exe"]).name, "threads")
        n = con.execute("SELECT COUNT(*) FROM processes WHERE exe LIKE '%/threads'").fetchone()[0]
        self.assertEqual(n, 1, "threads must not be recorded as separate processes")

    def test_pid_reuse_via_clone3_set_tid(self):
        """Two real processes with the *same* OS pid, chosen with clone3(set_tid)."""
        cc(self.root, "samepid", r"""
            #define _GNU_SOURCE
            #include <fcntl.h>
            #include <linux/sched.h>
            #include <sched.h>
            #include <signal.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #include <sys/syscall.h>
            #include <sys/wait.h>
            #include <unistd.h>
            int main(int argc, char **argv) {
              pid_t want = atoi(argv[1]);
              for (int i = 0; i < 2; i++) {
                struct clone_args ca; memset(&ca, 0, sizeof ca);
                ca.exit_signal = SIGCHLD; ca.set_tid = (unsigned long)&want; ca.set_tid_size = 1;
                long pid = syscall(SYS_clone3, &ca, sizeof ca);
                if (pid < 0) { perror("clone3"); return 2; }
                if (pid == 0) { /* the reused-pid process itself redirects and execs the writer */
                  char in[32], out[32]; snprintf(in, sizeof in, "in%d.txt", i); snprintf(out, sizeof out, "out%d.txt", i);
                  int fd = open(out, O_WRONLY|O_CREAT|O_TRUNC, 0644); dup2(fd, 1); close(fd);
                  execl("/bin/cat", "cat", in, (char *)0); _exit(3); }
                int st; waitpid(pid, &st, 0); if (!WIFEXITED(st) || WEXITSTATUS(st)) return 4;
                printf("%ld\n", pid);
              }
              return 0; }""")
        (self.root / "in0.txt").write_text("zero\n")
        (self.root / "in1.txt").write_text("one\n")
        pid_max = int(Path("/proc/sys/kernel/pid_max").read_text())
        used = {int(p) for p in os.listdir("/proc") if p.isdigit()}
        want = next(p for p in range(min(pid_max - 1, 3_000_000), 1000, -7) if p not in used)
        s = Live(self.root)
        out = sh(f"./samepid {want}", self.root).stdout.split()
        s.stop()
        self.assertEqual(out, [str(want), str(want)], "both children must have received the same pid")
        con = self.con()
        w0, w1 = why(con, str(self.root / "out0.txt")), why(con, str(self.root / "out1.txt"))
        self.assertEqual(w0["pid"], want)
        self.assertEqual(w1["pid"], want)
        self.assertNotEqual(w0["process_key"], w1["process_key"])
        self.assertEqual(w0["inputs"], [str(self.root / "in0.txt")])
        self.assertEqual(w1["inputs"], [str(self.root / "in1.txt")])

    def test_symlink_escape_is_not_captured(self):
        os.symlink("/etc", self.root / "etc-link")
        s = Live(self.root)
        sh("cat etc-link/hostname > leak.txt; cat /etc/hostname > leak2.txt; ../ 2>/dev/null; true", self.root)
        s.stop()
        con = self.con()
        outside = con.execute("SELECT COUNT(*) FROM events WHERE path LIKE '/etc/%' OR path2 LIKE '/etc/%'").fetchone()[0]
        self.assertEqual(outside, 0)
        self.assertEqual(why(con, str(self.root / "leak.txt"))["inputs"], [])

    def test_failed_open_and_duplicate_io_are_not_recorded(self):
        cc(self.root, "manywrites", r"""
            #include <fcntl.h>
            #include <unistd.h>
            int main(void) { open("does-not-exist.txt", O_RDONLY);
              int fd = open("out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
              for (int i = 0; i < 1000; i++) write(fd, "x", 1); close(fd); return 0; }""")
        s = Live(self.root)
        sh("./manywrites", self.root)
        s.stop()
        con = self.con()
        self.assertEqual(con.execute("SELECT COUNT(*) FROM events WHERE path LIKE '%does-not-exist.txt'").fetchone()[0], 0)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM events WHERE path=? AND is_write=1",
                                     (str(self.root / "out.txt"),)).fetchone()[0], 1)

    def test_rename_and_unlink_lineage(self):
        (self.root / "in.txt").write_text("x\n")
        (self.root / "moved").mkdir()
        s = Live(self.root)
        sh("cp in.txt a.txt && mv a.txt b.txt && mv b.txt moved/c.txt && cp in.txt gone.txt && rm gone.txt", self.root)
        s.stop()
        con = self.con()
        w = why(con, str(self.root / "moved" / "c.txt"))
        self.assertEqual(Path(w["exe"]).name, "cp")
        self.assertEqual(w["inputs"], [str(self.root / "in.txt")])
        self.assertEqual([r["from"] for r in w["renamed_from"]], [str(self.root / "b.txt"), str(self.root / "a.txt")])
        self.assertIn(str(self.root / "moved" / "c.txt"), {b for _a, b, _e, _r in impact(con, str(self.root / "in.txt"))})
        kinds = [r["kind"] for r in history(con, str(self.root / "gone.txt"))]
        self.assertIn("io", kinds)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM events WHERE kind='unlink' AND path=?",
                                     (str(self.root / "gone.txt"),)).fetchone()[0], 1)

    def test_exit_before_flush_is_drained(self):
        (self.root / "in.txt").write_text("x\n")
        s = Live(self.root, poll=False)  # nothing consumed until stop()
        sh("cp in.txt out.txt", self.root)
        st = s.stop()
        self.assertGreater(st.received, 0)
        self.assertEqual(Path(why(self.con(), str(self.root / "out.txt"))["exe"]).name, "cp")

    def test_ring_buffer_overflow_is_counted_not_silent(self):
        s = Live(self.root, poll=False)
        # ~3 events per iteration (open/read/close) far beyond the 16 MiB ring buffer.
        sh("python3 -c \"import os\n"
           "for i in range(40000):\n"
           "  fd=os.open('/etc/hostname', os.O_RDONLY); os.read(fd, 8); os.close(fd)\"", self.root)
        st = s.stop()
        self.assertGreater(st.kernel_drops, 0, "overflow must be counted")

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_node_async_fs_io_uring_is_captured(self):
        """libuv >= 1.45 (Ubuntu 24.04's Node) performs async fs through io_uring,
        which syscall tracepoints never see.  A real Vite build lost every output."""
        (self.root / "in.txt").write_text("from node\n")
        s = Live(self.root)
        sh("node -e \"const fs=require('fs').promises;"
           "fs.readFile('in.txt').then(d=>fs.writeFile('out.txt', d)).then(()=>fs.rename('out.txt','final.txt'))\"",
           self.root)
        s.stop()
        con = self.con()
        w = why(con, str(self.root / "final.txt"))
        self.assertIsNotNone(w, "io_uring file I/O was not observed")
        self.assertEqual(Path(w["exe"]).name, "node")
        self.assertIn(str(self.root / "in.txt"), w["inputs"])
        self.assertEqual(w["renamed_from"][0]["from"], str(self.root / "out.txt"))

    def test_queries_during_concurrent_writes(self):
        (self.root / "in.txt").write_text("x\n")
        s = Live(self.root)
        errors = []

        def query_loop():
            end = time.time() + 3
            while time.time() < end:
                try:
                    c = connect(self.root)
                    why(c, str(self.root / "out5.txt"))
                    c.close()
                except sqlite3.Error as exc:  # pragma: no cover
                    errors.append(exc)

        t = threading.Thread(target=query_loop)
        t.start()
        sh("for i in $(seq 1 300); do cp in.txt out$i.txt; done", self.root)
        t.join()
        s.stop()
        self.assertEqual(errors, [])
        self.assertEqual(Path(why(self.con(), str(self.root / "out300.txt"))["exe"]).name, "cp")


if __name__ == "__main__":
    unittest.main()
