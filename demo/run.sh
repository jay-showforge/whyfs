#!/usr/bin/env bash
# whyfs demo: a four-stage pipeline of separate processes, then ask where the output came from.
#
#   bash demo/run.sh [WORKDIR]
#
# Uses the installed `whyfs` command and the explicit `whyfs trace` backend, so it needs
# no root: only bash, coreutils, grep and a C compiler (the trace backend builds a small
# LD_PRELOAD shim on first use). For the always-on eBPF daemon, see demo/run-daemon.sh.
set -euo pipefail

WHYFS="${WHYFS:-whyfs}"
command -v "$WHYFS" >/dev/null || { echo "whyfs is not installed (pip install whyfs-*.whl)" >&2; exit 1; }
WORK="${1:-./whyfs-demo}"
rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"

"$WHYFS" init . >/dev/null
mkdir -p data build dist
printf 'The operating system saw every file being made.\nBuild logs disappear, but the operating system saw.\n' > data/source.txt
printf 'the\nbut\n' > data/stopwords.txt

step() { printf '\n\033[1m$ %s\033[0m\n' "$*"; }
run() { "$WHYFS" trace -- bash -c "$1" >/dev/null; }

# Each stage is its own process reading one file and writing the next.
run 'tr -cs "[:alpha:]" "\n" < data/source.txt > build/words.txt'        # split into words
run 'grep -vixFf data/stopwords.txt build/words.txt > build/kept.txt'    # drop stopwords
run 'sort -f build/kept.txt > build/sorted.txt'                          # sort
run 'uniq -ic < build/sorted.txt > dist/report.txt'                           # count -> artifact

step "cat dist/report.txt"
cat dist/report.txt

step "whyfs why dist/report.txt"
"$WHYFS" why dist/report.txt

step "whyfs why build/kept.txt"
"$WHYFS" why build/kept.txt

step "whyfs impact data/source.txt"
"$WHYFS" impact data/source.txt

step "whyfs history dist/report.txt"
"$WHYFS" history dist/report.txt
