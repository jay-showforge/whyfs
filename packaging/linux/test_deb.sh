#!/bin/bash
# Clean-install test of the whyfs .deb (run as root; workloads run as --user).
#   packaging/linux/test_deb.sh DEB USER OUTDIR
set -uo pipefail
DEB=$1; USER_=$2; OUT=$3
REPO=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUT"
declare -A R
check() { R[$1]=$2; printf '%-5s %s %s\n' "$([ "$2" = 1 ] && echo PASS || echo FAIL)" "$1" "${3:-}"; }

dpkg -r whyfs >/dev/null 2>&1; rm -rf /var/cache/whyfs
check precondition_clean "$([ ! -e /usr/bin/whyfs ] && [ ! -e /usr/lib/whyfs ] && echo 1 || echo 0)"
apt-get install -y -q "$(readlink -f "$DEB")" > "$OUT/install.log" 2>&1
check install "$([ $? = 0 ] && echo 1 || echo 0)"
check cli_on_path "$(command -v whyfs >/dev/null && echo 1 || echo 0)" "$(whyfs --version 2>&1)"
check package_modes "$([ "$(stat -c %a /usr/lib/whyfs/whyfs-collect)" = 755 ] && [ "$(stat -c %a /usr/lib/whyfs/whyfs-collect.source-sha256)" = 644 ] && [ "$(stat -c %U /usr/lib/whyfs/whyfs-collect)" = root ] && echo 1 || echo 0)" "$(stat -c '%a %U' /usr/lib/whyfs/whyfs-collect)"
check prebuilt_collector_used "$(cd /tmp && python3 -c 'from whyfs import native_collect as n; print(n.binary())' 2>&1 | grep -q '^/usr/lib/whyfs/whyfs-collect$' && echo 1 || echo 0)"
check no_compiler_needed "$([ ! -e /var/cache/whyfs ] || [ -z "$(ls -A /var/cache/whyfs)" ] && echo 1 || echo 0)"
# trust: a tampered or unprotected packaged collector is never executed
PKGC=/usr/lib/whyfs/whyfs-collect
pick() { (cd /tmp && env -u PYTHONPATH python3 -c 'from whyfs import native_collect as n
try: print(n.binary())
except Exception as e: print("refused:", e)' 2>&1 | tail -1); }
chmod o+w $PKGC; P1=$(pick); chmod o-w $PKGC
cp $PKGC.source-sha256 /tmp/whyfs-stamp.bak; echo 0000000000000000 > $PKGC.source-sha256; P2=$(pick); cp /tmp/whyfs-stamp.bak $PKGC.source-sha256
cp /bin/true /tmp/whyfs-fake-collect; chmod 777 /tmp/whyfs-fake-collect; P3=$(WHYFS_COLLECT=/tmp/whyfs-fake-collect pick); rm -f /tmp/whyfs-fake-collect
rm -rf /var/cache/whyfs
check tampered_collector_not_used "$([ "$P1" != "$PKGC" ] && [ "$P2" != "$PKGC" ] && echo 1 || echo 0)" "world-writable: $P1 | wrong source stamp: $P2"
check unsafe_override_refused "$(echo "$P3" | grep -q '^refused' && echo 1 || echo 0)" "$P3"
check doctor_ready "$(whyfs doctor --json 2>/dev/null | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["ready"]))')"

# the shared behavioural corpus through the installed package (no source tree on sys.path)
( cd /tmp && env -u PYTHONPATH python3 -W ignore "$REPO/scripts/run_corpus.py" --installed --user "$USER_" --out "$OUT/corpus" ) > "$OUT/corpus.log" 2>&1
check corpus_installed "$([ $? = 0 ] && echo 1 || echo 0)" "$(tail -1 "$OUT/corpus.log")"

# systemd template unit (where systemd runs: native Linux, WSL with systemd=true)
if [ -d /run/systemd/system ]; then
  WS=$(mktemp -d /home/$USER_/whyfs-unit-XXXX); chown "$USER_:" "$WS"; chmod 755 "$WS"
  runuser -u "$USER_" -- whyfs init "$WS" >/dev/null
  UNIT="whyfs@$(systemd-escape --path "$WS").service"
  systemctl start "$UNIT"
  for i in $(seq 1 "${WHYFS_START_TIMEOUT:-60}"); do [ -f "$WS/.whyfs/daemon.json" ] && break; sleep 1; done; sleep 1
  runuser -u "$USER_" -- bash -c "cd $WS && echo x > in.txt && cp in.txt out.txt"; sleep 1
  systemctl stop "$UNIT"
  check systemd_unit "$(cd "$WS" && runuser -u "$USER_" -- whyfs why out.txt --json | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["exe"].endswith("/cp")))')"
  rm -rf "$WS"
else
  check systemd_unit 1 "skipped: no systemd in this environment (documented: sudo whyfs daemon start)"
fi

WSDATA=$(mktemp -d /tmp/whyfs-keep-XXXX); whyfs init "$WSDATA" >/dev/null
dpkg -r whyfs > "$OUT/remove.log" 2>&1
check remove "$([ $? = 0 ] && echo 1 || echo 0)"
check files_removed "$([ ! -e /usr/bin/whyfs ] && [ ! -e /usr/lib/whyfs ] && [ ! -e /usr/lib/python3/dist-packages/whyfs ] && [ ! -e /lib/systemd/system/whyfs@.service ] && echo 1 || echo 0)"
check cache_removed "$([ ! -e /var/cache/whyfs ] && echo 1 || echo 0)"
check user_data_kept "$([ -f "$WSDATA/.whyfs/whyfs.db" ] && echo 1 || echo 0)"
rm -rf "$WSDATA"
fails=0; for k in "${!R[@]}"; do [ "${R[$k]}" = 1 ] || fails=$((fails+1)); done
python3 -c "import json,sys; print(json.dumps(dict(a.split('=',1) for a in sys.argv[1:]), indent=1))" $(for k in "${!R[@]}"; do echo "$k=${R[$k]}"; done) > "$OUT/deb_test.json"
echo "deb clean-install test ($(dpkg --print-architecture)): $(( ${#R[@]} - fails ))/${#R[@]} checks"
[ $fails = 0 ]
