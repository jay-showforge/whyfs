#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
WORK="${1:-$ROOT/demo-work}"
rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK"
python3 -m whyfs init . >/dev/null
printf 'hello world\nsecond line\n' > raw.txt
python3 -m whyfs trace --workspace . -- bash -c 'tr a-z A-Z < raw.txt > upper.txt'
python3 -m whyfs trace --workspace . -- bash -c 'wc -l < upper.txt > report.txt'
printf '\n$ whyfs why upper.txt\n'
python3 -m whyfs why upper.txt
printf '\n$ whyfs impact raw.txt\n'
python3 -m whyfs impact raw.txt
printf '\n$ whyfs history report.txt\n'
python3 -m whyfs history report.txt
printf '\n$ whyfs stats\n'
python3 -m whyfs stats
