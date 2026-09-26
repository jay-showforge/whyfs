#!/usr/bin/env bash
# whyfs always-on demo: the same pipeline with NO wrapper command, observed by the eBPF
# daemon. Needs root, BCC (e.g. python3-bpfcc) and a kernel with BTF; check with
# `sudo whyfs doctor`.
#
#   sudo bash demo/run-daemon.sh [WORKDIR] [USER]
#
# The pipeline runs as USER (default: $SUDO_USER). The daemon runs as root but writes its
# database as that user, and queries need no privileges.
set -euo pipefail

WHYFS="${WHYFS:-whyfs}"
[ "$(id -u)" = 0 ] || { echo "run with sudo (the eBPF daemon needs root)" >&2; exit 1; }
USER_NAME="${2:-${SUDO_USER:-}}"
[ -n "$USER_NAME" ] || { echo "pass the user to run the pipeline as" >&2; exit 1; }
WORK="$(realpath -m "${1:-./whyfs-daemon-demo}")"
rm -rf "$WORK"
mkdir -p "$WORK/data" "$WORK/build" "$WORK/dist"
printf 'The operating system saw every file being made.\nBuild logs disappear, but the operating system saw.\n' > "$WORK/data/source.txt"
printf 'the\nbut\n' > "$WORK/data/stopwords.txt"
chown -R "$USER_NAME": "$WORK"
as_user() { runuser -u "$USER_NAME" -- bash -c "cd '$WORK' && $1"; }

"$WHYFS" doctor >/dev/null || { "$WHYFS" doctor; exit 1; }
"$WHYFS" daemon start --workspace "$WORK"
trap '"$WHYFS" daemon stop --workspace "$WORK" >/dev/null 2>&1 || true' EXIT
sleep 0.5

# No `whyfs trace` wrapper: the kernel observes everything inside the workspace.
as_user 'tr -cs "[:alpha:]" "\n" < data/source.txt > build/words.txt'
as_user 'grep -vixFf data/stopwords.txt build/words.txt > build/kept.txt'
as_user 'sort -f build/kept.txt > build/sorted.txt'
as_user 'uniq -ic < build/sorted.txt > dist/report.txt'
sleep 0.5
"$WHYFS" daemon stop --workspace "$WORK"
trap - EXIT

for q in "why dist/report.txt" "why build/kept.txt" "impact data/source.txt" "history dist/report.txt"; do
  printf '\n\033[1m$ whyfs %s\033[0m\n' "$q"
  as_user "\"$WHYFS\" $q"
done
