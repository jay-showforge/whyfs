#!/bin/bash
# Proves that the macOS work leaves the Linux collector unchanged: the Linux object file built
# from this checkout's src/whyfs/native/whyfs-collect.c is byte-identical to the one built from
# the v1.0.0 release's copy (same compiler, same flags, same file name).
#   bash scripts/linux_collector_unchanged.sh [REF]      (REF defaults to v1.0.0)
set -euo pipefail
REF=${1:-v1.0.0}
cd "$(dirname "$0")/.."
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/ref" "$T/new"
git show "$REF:src/whyfs/native/whyfs-collect.c" > "$T/ref/whyfs-collect.c"
cp src/whyfs/native/whyfs-collect.c "$T/new/whyfs-collect.c"
FLAGS=$(pkg-config --cflags libbpf sqlite3 2>/dev/null || true)
for d in ref new; do (cd "$T/$d" && cc -O2 -Wall -c $FLAGS -o whyfs-collect.o whyfs-collect.c); done
echo "compiler: $(cc --version | head -1)"
echo "ref $REF: $(sha256sum < "$T/ref/whyfs-collect.o" | cut -d' ' -f1)"
echo "this checkout: $(sha256sum < "$T/new/whyfs-collect.o" | cut -d' ' -f1)"
if cmp -s "$T/ref/whyfs-collect.o" "$T/new/whyfs-collect.o"; then
  echo "LINUX COLLECTOR UNCHANGED: identical object code"
else
  echo "LINUX COLLECTOR CHANGED"; exit 1
fi
