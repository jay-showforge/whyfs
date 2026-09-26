"""Portable workload tool for the cross-platform behavioural corpus.

Every scenario step is a real, separate OS process doing real file I/O, so each platform's
collector observes it natively.  Nothing here talks to whyfs.

  copy SRC... DST          read every SRC, write their bytes to DST
  readmany N SRC DST       open+read SRC N times (reopen), then write DST
  cc SRC HDR OUT           a "compiler": reads a source and a header, writes a binary
  spawn TOOLARGS...        a parent process that runs one child `wtool TOOLARGS...`
  rename A B               move A to B (os.replace)
  parallel N               N concurrent children: copy in_I.txt -> out_I.txt
"""
import os
import subprocess
import sys


def main(argv):
    op, args = argv[0], argv[1:]
    if op == "copy":
        data = b"".join(open(p, "rb").read() for p in args[:-1])
        with open(args[-1], "wb") as f:
            f.write(data)
    elif op == "readmany":
        n, src, dst = int(args[0]), args[1], args[2]
        data = b""
        for _ in range(n):
            with open(src, "rb") as f:
                data = f.read()
        with open(dst, "wb") as f:
            f.write(data * n)
    elif op == "cc":
        src, hdr, out = args
        text = open(src, "rb").read() + open(hdr, "rb").read()
        with open(out, "wb") as f:
            f.write(b"BIN" + bytes(reversed(text)))
    elif op == "spawn":
        return subprocess.run([sys.executable, __file__, *args]).returncode
    elif op == "rename":
        os.replace(args[0], args[1])
    elif op == "parallel":
        n = int(args[0])
        procs = [subprocess.Popen([sys.executable, __file__, "copy", f"in_{i}.txt", f"out_{i}.txt"]) for i in range(n)]
        return max(p.wait() for p in procs)
    else:
        raise SystemExit(f"unknown op {op}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
