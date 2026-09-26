"""Live kernel regression tests for the v0.2 eBPF backend.

These load the real BPF program and drive real processes.  They are skipped
unless the host can actually run the collector (Linux, root/CAP_BPF, BCC,
kernel headers).  No fallback backend is substituted.
"""
import json
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

from types import SimpleNamespace

from whyfs import native_collect
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
        # WF_TEST_EXTRA_CFLAGS: diagnostic only (e.g. prove a test catches an unsafe BPF variant).
        extra = os.environ.get("WF_TEST_EXTRA_CFLAGS", "").split()
        self.c = BCCCollector(self.root, "live", extra_cflags=extra or None)
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
        # Detach and free this test's BPF programs now: a kernel function accepts at
        # most 38 trampoline programs, and leaked ones made later tests fail to attach.
        self.c.bpf.cleanup()
        return self.stats


class NativeLive:
    """The daemon's native path: BPF loaded here, whyfs-collect consumes the ring and
    writes the store.  ``poll=False`` starts the consumer only at stop(), so nothing is
    consumed while the workload runs (drain and overflow tests)."""

    def __init__(self, root: Path, *, poll: bool = True):
        self.root = root.resolve()
        con = connect(self.root)
        con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
                    ("live", time.time_ns(), str(self.root), "live-test", str(self.root), "ebpf-native"))
        con.commit()
        con.close()
        extra = os.environ.get("WF_TEST_EXTRA_CFLAGS", "").split()
        self.c = BCCCollector(self.root, "live", extra_cflags=extra or None)
        self.c.load_programs()
        self.n = native_collect.NativeIngest(self.c, self.root, "live")
        if poll:
            self.n.start()

    def stop(self):
        if not self.n.p:
            self.n.start()
        final, status = self.n.stop()
        self.c.bpf.cleanup()
        if status != 0:
            raise RuntimeError(f"native collector exited {status}: {final}")
        self.stats = SimpleNamespace(**final)
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
    live_cls = Live

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
        s = self.live_cls(self.root)
        sh("./static_copy raw.txt out.txt", self.root)
        s.stop()
        w = why(self.con(), str(self.root / "out.txt"))
        self.assertEqual(Path(w["exe"]).name, "static_copy")
        self.assertEqual(w["inputs"], [str(self.root / "raw.txt")])
        self.assertIn("raw.txt out.txt", w["command"])

    def test_shell_redirection_and_short_lived_child(self):
        (self.root / "in.txt").write_text("abc\n")
        s = self.live_cls(self.root)
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
        s = self.live_cls(self.root)
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
        s = self.live_cls(self.root)
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
        s = self.live_cls(self.root)
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
        s = self.live_cls(self.root)
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
        s = self.live_cls(self.root)
        sh("./manywrites", self.root)
        s.stop()
        con = self.con()
        self.assertEqual(con.execute("SELECT COUNT(*) FROM events WHERE path LIKE '%does-not-exist.txt'").fetchone()[0], 0)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM events WHERE path=? AND is_write=1",
                                     (str(self.root / "out.txt"),)).fetchone()[0], 1)

    def test_rename_and_unlink_lineage(self):
        (self.root / "in.txt").write_text("x\n")
        (self.root / "moved").mkdir()
        s = self.live_cls(self.root)
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
        s = self.live_cls(self.root, poll=False)  # nothing consumed until stop()
        sh("cp in.txt out.txt", self.root)
        st = s.stop()
        self.assertGreater(st.received, 0)
        self.assertEqual(Path(why(self.con(), str(self.root / "out.txt"))["exe"]).name, "cp")

    def test_ring_buffer_overflow_is_counted_not_silent(self):
        s = self.live_cls(self.root, poll=False)
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
        s = self.live_cls(self.root)
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
        s = self.live_cls(self.root)
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


IOSEEN_HELPER = r"""
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
static void rd(int fd) { char b[4]; if (read(fd, b, 1) < 0) exit(10); }
static void wr(int fd) { if (write(fd, "y", 1) != 1) exit(11); }
int main(int argc, char **argv) {
  const char *m = argv[1], *p = argv[2];
  printf("%d\n", getpid()); fflush(stdout);
  if (!strcmp(m, "reopen_read")) {            /* N x (open, read, close[, pause us]) */
    int pause = argc > 4 ? atoi(argv[4]) : 0;
    for (int i = 0; i < atoi(argv[3]); i++) { int fd = open(p, O_RDONLY); rd(fd); close(fd); if (pause) usleep(pause); }
  } else if (!strcmp(m, "reopen_write_read")) { /* N x (open rw, write, read, close[, pause us]) */
    int pause = argc > 4 ? atoi(argv[4]) : 0;
    for (int i = 0; i < atoi(argv[3]); i++) { int fd = open(p, O_RDWR); wr(fd); lseek(fd, 0, SEEK_SET); rd(fd); close(fd); if (pause) usleep(pause); }
  } else if (!strcmp(m, "read_then_write")) {  /* one open: 5 reads then 5 writes */
    int fd = open(p, O_RDWR); for (int i = 0; i < 5; i++) rd(fd); for (int i = 0; i < 5; i++) wr(fd); close(fd);
  } else if (!strcmp(m, "write_then_read")) {  /* one open: 5 writes then 5 reads */
    int fd = open(p, O_RDWR); for (int i = 0; i < 5; i++) wr(fd); lseek(fd, 0, SEEK_SET); for (int i = 0; i < 5; i++) rd(fd); close(fd);
  } else if (!strcmp(m, "dup")) {              /* same open description via dup: one read */
    int fd = open(p, O_RDONLY); int d = dup(fd); rd(fd); rd(d); close(d); close(fd);
  } else if (!strcmp(m, "two_opens")) {        /* two open descriptions of one inode at once */
    int a = open(p, O_RDONLY), b = open(p, O_RDONLY); rd(a); rd(b); close(a); close(b);
  } else if (!strcmp(m, "fork_inherit")) {     /* parent reads, child reads the inherited fd */
    int fd = open(p, O_RDONLY); rd(fd);
    pid_t c = fork(); if (c == 0) { printf("%d\n", getpid()); fflush(stdout); rd(fd); _exit(0); }
    waitpid(c, 0, 0); close(fd);
  } else if (!strcmp(m, "concurrent")) {       /* N children, each opens and reads */
    int n = atoi(argv[3]);
    for (int i = 0; i < n; i++) if (fork() == 0) { int fd = open(p, O_RDONLY); rd(fd); close(fd); _exit(0); }
    for (int i = 0; i < n; i++) wait(0);
  } else if (!strcmp(m, "exec_stage1")) {      /* same pid: read input, close, exec stage2 */
    for (int i = 0; i < 50; i++) { int fd = open(p, O_RDONLY); rd(fd); close(fd); usleep(2000); }
    usleep(20000);  /* let RCU free the last struct file so stage2 may get its address */
    execl(argv[0], argv[0], "exec_stage2", p, argv[3], (char *)0); exit(12);
  } else if (!strcmp(m, "exec_stage2")) {      /* new image, same pid: reopen input, write output */
    int fd = open(p, O_RDONLY); rd(fd); close(fd);
    int o = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0644); wr(o); close(o);
  } else return 2;
  return 0;
}
"""


@unittest.skipUnless(READY, "requires Linux + root/CAP_BPF + BCC + kernel headers")
class IoSeenSemanticsTests(unittest.TestCase):
    """First-read/first-write dedup (io_seen) must never let state from an earlier
    open suppress a later open's events.  The kernel re-uses freed struct file
    memory, so a reopen in the same process often gets the same pointer."""

    live_cls = Live

    def setUp(self):
        self.td = tempfile.TemporaryDirectory(prefix="whyfs-ioseen-")
        self.root = Path(self.td.name).resolve()
        self.prog = cc(self.root, "ioseen", IOSEEN_HELPER)
        (self.root / "f.txt").write_text("0123456789")

    def tearDown(self):
        self.td.cleanup()

    def run_helper(self, *args):
        s = self.live_cls(self.root)
        p = subprocess.run([str(self.prog), *args], cwd=self.root, capture_output=True, text=True, check=True)
        s.stop()
        return [int(x) for x in p.stdout.split()], connect(self.root)

    def io(self, con, pid, path, read):
        return con.execute("SELECT COUNT(*) FROM events WHERE os_pid=? AND path=? AND kind='io' AND is_read=? AND is_write=?",
                           (pid, str(path), int(read), int(not read))).fetchone()[0]

    def opens(self, con, pid, path):
        return con.execute("SELECT COUNT(*) FROM events WHERE os_pid=? AND path=? AND kind='open'", (pid, str(path))).fetchone()[0]

    def test_every_reopen_reports_its_first_read(self):
        # Pauses let RCU free each closed struct file, so reopens re-use its address:
        # exactly the case where stale dedup state would swallow the new open's read.
        f = self.root / "f.txt"
        (pid,), con = self.run_helper("reopen_read", str(f), "100", "5000")
        self.assertEqual(self.opens(con, pid, f), 100)
        self.assertEqual(self.io(con, pid, f, read=True), 100, "stale io_seen state suppressed a reopen's first read")

    def test_back_to_back_reopens_report_every_read(self):
        f = self.root / "f.txt"
        (pid,), con = self.run_helper("reopen_read", str(f), "200")
        self.assertEqual((self.opens(con, pid, f), self.io(con, pid, f, read=True)), (200, 200))

    def test_every_reopen_reports_write_and_read(self):
        f = self.root / "f.txt"
        (pid,), con = self.run_helper("reopen_write_read", str(f), "100", "5000")
        self.assertEqual(self.io(con, pid, f, read=False), 100)
        self.assertEqual(self.io(con, pid, f, read=True), 100)

    def test_read_then_write_on_one_open_reports_one_each(self):
        f = self.root / "f.txt"
        (pid,), con = self.run_helper("read_then_write", str(f))
        self.assertEqual((self.io(con, pid, f, True), self.io(con, pid, f, False)), (1, 1))

    def test_write_then_read_on_one_open_reports_one_each(self):
        f = self.root / "f.txt"
        (pid,), con = self.run_helper("write_then_read", str(f))
        self.assertEqual((self.io(con, pid, f, True), self.io(con, pid, f, False)), (1, 1))

    def test_dup_shares_the_open_description(self):
        f = self.root / "f.txt"
        (pid,), con = self.run_helper("dup", str(f))
        self.assertEqual(self.io(con, pid, f, True), 1)

    def test_two_opens_of_one_inode_are_independent(self):
        f = self.root / "f.txt"
        (pid,), con = self.run_helper("two_opens", str(f))
        self.assertEqual((self.opens(con, pid, f), self.io(con, pid, f, True)), (2, 2))

    def test_fork_child_reports_its_read_of_an_inherited_fd(self):
        f = self.root / "f.txt"
        (parent, child), con = self.run_helper("fork_inherit", str(f))
        self.assertEqual((self.io(con, parent, f, True), self.io(con, child, f, True)), (1, 1))

    def test_concurrent_processes_each_report_their_read(self):
        f = self.root / "f.txt"
        _pid, con = self.run_helper("concurrent", str(f), "8")
        n = con.execute("SELECT COUNT(DISTINCT os_pid) FROM events WHERE path=? AND kind='io' AND is_read=1 AND os_pid != ?",
                        (str(f), _pid[0])).fetchone()[0]
        self.assertEqual(n, 8)

    def test_new_image_reopening_its_input_keeps_lineage(self):
        f, out = self.root / "f.txt", self.root / "out.txt"
        pids, con = self.run_helper("exec_stage1", str(f), str(out))
        pid = pids[0]
        self.assertEqual(pids, [pid, pid], "both images must run in the same process")
        self.assertEqual(self.io(con, pid, f, True), 51)
        w = why(con, str(out))
        self.assertEqual(w["inputs"], [str(f)], "the exec'd image's read of its input was suppressed")


def whyfs_cli(root: Path, *args: str, user: str | None = None, collector: str = "native") -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"), WHYFS_COLLECTOR=collector)
    argv = [shutil.which("python3") or "python3", "-W", "ignore", "-m", "whyfs", *args]
    if user:
        argv = ["runuser", "-u", user, "--", "env", f"PYTHONPATH={env['PYTHONPATH']}", *argv]
    return subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True)


@unittest.skipUnless(READY, "requires Linux + root/CAP_BPF + BCC + kernel headers")
class LiveDaemonEndToEndTests(unittest.TestCase):
    """The real `whyfs daemon start/stop` path, store included.  Found by the
    unmodified shipped gate: in a root-owned workspace the in-process store's
    SQLite connection was opened on one thread and used on the writer thread,
    so every event was lost ("SQLite objects created in a thread...")."""

    collector = "native"  # the default daemon path; see PythonCollectorDaemonTests

    def run_static(self, root: Path, user: str | None = None) -> dict:
        prog = cc(root, "static_copy", r"""
            #include <stdio.h>
            int main(int c, char **v) { FILE *i = fopen(v[1], "rb"), *o = fopen(v[2], "wb");
              char b[4096]; size_t n; while ((n = fread(b, 1, sizeof b, i)) > 0) fwrite(b, 1, n, o);
              fclose(i); fclose(o); return 0; }""", "-static")
        (root / "raw.txt").write_text("static lineage\n")
        if user:
            subprocess.run(["chown", "-R", f"{user}:", str(root)], check=True)
        init = whyfs_cli(root, "init", ".", user=user)
        self.assertEqual(init.returncode, 0, init.stdout + init.stderr)
        start = whyfs_cli(root, "daemon", "start", "--workspace", str(root), collector=self.collector)
        self.assertEqual(start.returncode, 0, start.stderr)
        try:
            time.sleep(0.25)
            run = ["./static_copy", "raw.txt", "static-out.txt"]
            subprocess.run((["runuser", "-u", user, "--"] if user else []) + run, cwd=root, check=True)
            time.sleep(0.25)
        finally:
            stop = whyfs_cli(root, "daemon", "stop", "--workspace", str(root))
        self.assertEqual(stop.returncode, 0, stop.stderr)
        log = (root / ".whyfs" / "daemon.log").read_text(errors="replace")
        self.assertNotIn("Traceback", log)
        con = connect(root)
        used = con.execute("SELECT collector FROM runs ORDER BY started_ns DESC LIMIT 1").fetchone()[0]
        con.close()
        self.assertEqual(used, "ebpf-native" if self.collector == "native" else "ebpf-bcc")
        q = whyfs_cli(root, "why", "static-out.txt", "--json", user=user)
        self.assertEqual(q.returncode, 0, q.stdout + q.stderr)
        return json.loads(q.stdout)

    def test_daemon_in_root_owned_workspace(self):
        with tempfile.TemporaryDirectory(prefix="whyfs-v02-gate-") as td:
            root = Path(td).resolve()
            w = self.run_static(root)
            self.assertEqual(Path(w["exe"]).name, "static_copy")
            self.assertEqual(w["inputs"], [str(root / "raw.txt")])

    def test_daemon_in_user_owned_workspace_is_queryable_by_the_user(self):
        import pwd  # the account that owns the source tree can import whyfs
        user = pwd.getpwuid(Path(__file__).stat().st_uid).pw_name
        if user == "root":
            self.skipTest("needs a non-root owner of the source tree")
        base = Path(tempfile.mkdtemp(prefix="whyfs-e2e-"))
        os.chmod(base, 0o755)
        try:
            root = base / "ws"
            root.mkdir()
            w = self.run_static(root, user=user)
            self.assertEqual(Path(w["exe"]).name, "static_copy")
            self.assertEqual(w["inputs"], [str(root / "raw.txt")])
            uid = int(subprocess.run(["id", "-u", user], capture_output=True, text=True).stdout)
            for p in [root / ".whyfs", *(root / ".whyfs").iterdir()]:
                self.assertEqual(p.lstat().st_uid, uid, p)
        finally:
            shutil.rmtree(base, ignore_errors=True)



# ---------------------------------------------------------------- native collector (daemon default)
@unittest.skipUnless(READY and native_collect.available()[0], "requires the live eBPF host and the native collector")
class NativeLiveKernelTests(LiveKernelTests):
    live_cls = NativeLive


@unittest.skipUnless(READY and native_collect.available()[0], "requires the live eBPF host and the native collector")
class NativeIoSeenSemanticsTests(IoSeenSemanticsTests):
    live_cls = NativeLive


@unittest.skipUnless(READY, "requires Linux + root/CAP_BPF + BCC + kernel headers")
class PythonCollectorDaemonTests(LiveDaemonEndToEndTests):
    """The Python collector remains the daemon's fallback path."""

    collector = "python"


@unittest.skipUnless(READY and native_collect.available()[0], "requires the live eBPF host and the native collector")
class NativeDaemonBehaviourTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(prefix="whyfs-native-")
        self.root = Path(self.td.name).resolve()
        self.assertEqual(whyfs_cli(self.root, "init", ".").returncode, 0)

    def tearDown(self):
        whyfs_cli(self.root, "daemon", "stop", "--workspace", str(self.root))
        self.td.cleanup()

    def state(self):
        return json.loads((self.root / ".whyfs" / "daemon.json").read_text())

    def test_evidence_becomes_queryable_while_the_daemon_runs(self):
        """Persistence is deferred while the workload is active, but bounded: once
        activity stops, records are queryable within the quiet period (+ one drain)."""
        (self.root / "in.txt").write_text("x\n")
        self.assertEqual(whyfs_cli(self.root, "daemon", "start", "--workspace", str(self.root)).returncode, 0)
        self.assertEqual(self.state()["collector"], "native")
        time.sleep(0.25)
        sh("cp in.txt out.txt", self.root)
        t0 = time.monotonic()
        seen = None
        while time.monotonic() - t0 < 3:
            c = connect(self.root)
            w = why(c, str(self.root / "out.txt"))
            c.close()
            if w:
                seen = time.monotonic() - t0
                break
            time.sleep(0.02)
        self.assertIsNotNone(seen, "record never became visible while the daemon ran")
        self.assertLess(seen, 1.0)
        self.assertEqual(Path(w["exe"]).name, "cp")

    def test_continuous_activity_is_persisted_within_the_max_delay(self):
        """Under uninterrupted activity the quiet period never arrives; the oldest
        queued batch must still reach SQLite within the 2 s bound."""
        (self.root / "in.txt").write_text("x\n")
        self.assertEqual(whyfs_cli(self.root, "daemon", "start", "--workspace", str(self.root)).returncode, 0)
        time.sleep(0.25)
        busy = subprocess.Popen(["bash", "-c", "end=$((SECONDS+6)); while [ $SECONDS -lt $end ]; do cat in.txt > busy.txt; done"],
                                cwd=self.root)
        try:
            time.sleep(0.3)
            sh("cp in.txt marker.txt", self.root)
            t0 = time.monotonic()
            seen = None
            while time.monotonic() - t0 < 4.5:
                c = connect(self.root)
                w = why(c, str(self.root / "marker.txt"))
                c.close()
                if w:
                    seen = time.monotonic() - t0
                    break
                time.sleep(0.05)
            self.assertIsNone(busy.poll(), "the workload must still be running")
        finally:
            busy.wait()
        self.assertIsNotNone(seen, "record not persisted under continuous activity")
        self.assertLess(seen, 2.5)

    def test_native_collector_does_not_outlive_a_killed_daemon(self):
        self.assertEqual(whyfs_cli(self.root, "daemon", "start", "--workspace", str(self.root)).returncode, 0)
        st = self.state()
        os.kill(st["pid"], 9)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and Path(f"/proc/{st['collector_pid']}").exists():
            try:
                if Path(f"/proc/{st['collector_pid']}/stat").read_text().split(") ")[1][0] == "Z":
                    break
            except OSError:
                break
            time.sleep(0.05)
        alive = Path(f"/proc/{st['collector_pid']}").exists() and \
            Path(f"/proc/{st['collector_pid']}/stat").read_text().split(") ")[1][0] != "Z"
        self.assertFalse(alive, "native collector kept running after its daemon was killed")


if __name__ == "__main__":
    unittest.main()
