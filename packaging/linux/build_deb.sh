#!/bin/bash
# Build the whyfs Debian/Ubuntu package for the machine's architecture (amd64 or arm64).
#   packaging/linux/build_deb.sh [OUTDIR]
# The native collector is compiled here, natively for this architecture, and shipped prebuilt
# (/usr/lib/whyfs/whyfs-collect) with the SHA-256 of the source it was built from.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-$REPO/dist}
ARCH=$(dpkg --print-architecture)
PYVER=$(grep '^version' "$REPO/pyproject.toml" | cut -d'"' -f2)
DEBVER=$(echo "$PYVER" | sed -E 's/\.?(dev|a|b|rc)([0-9]+)$/~\1\2/')   # 0.9.0.dev1 -> 0.9.0~dev1
STAGE=$(mktemp -d)
PKG=$STAGE/whyfs_${DEBVER}_${ARCH}
mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/usr/lib/whyfs" "$PKG/usr/lib/python3/dist-packages" \
         "$PKG/lib/systemd/system" "$PKG/usr/share/doc/whyfs"

# Python package (Linux collector, store, queries; Windows-only native sources left out)
rsync -a --exclude __pycache__ --exclude _bin --exclude 'native/windows' "$REPO/src/whyfs" "$PKG/usr/lib/python3/dist-packages/"

# prebuilt native collector for this architecture
gcc -O2 -Wall -Wextra -o "$PKG/usr/lib/whyfs/whyfs-collect" "$REPO/src/whyfs/native/whyfs-collect.c" \
    $(pkg-config --cflags --libs libbpf sqlite3)
sha256sum "$REPO/src/whyfs/native/whyfs-collect.c" | cut -d' ' -f1 > "$PKG/usr/lib/whyfs/whyfs-collect.source-sha256"
file "$PKG/usr/lib/whyfs/whyfs-collect" | grep -q -E "ELF 64-bit.*($( [ "$ARCH" = arm64 ] && echo aarch64 || echo x86-64))" \
    || { echo "collector architecture mismatch"; exit 1; }

cat > "$PKG/usr/bin/whyfs" <<'EOF'
#!/usr/bin/python3
from whyfs.cli import main
main()
EOF
chmod 755 "$PKG/usr/bin/whyfs"

cat > "$PKG/lib/systemd/system/whyfs@.service" <<'EOF'
[Unit]
Description=whyfs provenance collector for %f
Documentation=file:/usr/share/doc/whyfs/README.md
After=local-fs.target

# One always-on collector per workspace:
#   sudo systemctl enable --now "whyfs@$(systemd-escape --path /home/me/project).service"
[Service]
Type=simple
ExecStart=/usr/bin/whyfs daemon run --workspace %f
KillSignal=SIGTERM
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
EOF

# The machine-wide labelling service (docs/MACHINE_MODE.md): enabled at install.
cat > "$PKG/lib/systemd/system/whyfs.service" <<'EOF'
[Unit]
Description=whyfs: provenance labels for files (machine-wide collector and local API)
Documentation=file:/usr/share/doc/whyfs/README.md
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/bin/whyfs machine run
KillSignal=SIGTERM
TimeoutStopSec=90
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# scope policy: shipped defaults + the administrator's additions (a conffile)
PYTHONPATH="$REPO/src" python3 -m whyfs.scope linux > "$PKG/usr/lib/whyfs/scope-default.conf"
mkdir -p "$PKG/etc/whyfs"
cat > "$PKG/etc/whyfs/scope.conf" <<'EOF'
# whyfs scope additions (defaults: /usr/lib/whyfs/scope-default.conf; restart whyfs.service after edits)
#   exclude <path pattern>        never record files here
#   include <path pattern>        record files here even if a default excludes them
#   temp <path pattern>           treat as a temporary root
#   exclude-image <name|path>     never record events of this program
# Patterns: absolute paths; `*` matches one component; `~` means every user's home.
EOF

# file-manager integration (right-click -> WhyFS) and the WhyFS window in the application menu;
# `whyfs label FILE` / `whyfs ui` remain the universal fallback (docs/HUMAN_INTERFACE.md)
D="$REPO/packaging/linux/desktop"
install -D -m 644 "$D/whyfs.desktop" "$PKG/usr/share/applications/whyfs.desktop"
install -D -m 644 "$D/whyfs-label.desktop" "$PKG/usr/share/applications/whyfs-label.desktop"
install -D -m 644 "$D/whyfs-servicemenu.desktop" "$PKG/usr/share/kio/servicemenus/whyfs.desktop"             # Dolphin (KF6)
install -D -m 644 "$D/whyfs-servicemenu.desktop" "$PKG/usr/share/kservices5/ServiceMenus/whyfs.desktop"      # Dolphin (KF5)
for f in "$D"/*.nemo_action; do install -D -m 644 "$f" "$PKG/usr/share/nemo/actions/$(basename "$f")"; done  # Nemo
install -D -m 644 "$D/whyfs_nautilus.py" "$PKG/usr/share/nautilus-python/extensions/whyfs_nautilus.py"    # Files

cp "$REPO/LICENSE" "$PKG/usr/share/doc/whyfs/copyright"
cp "$REPO/README.md" "$PKG/usr/share/doc/whyfs/README.md"

cat > "$PKG/DEBIAN/control" <<EOF
Package: whyfs
Version: $DEBVER
Architecture: $ARCH
Maintainer: Jonathan Tyler Montgomery <licensing@tenzorpipe.org>
Depends: python3 (>= 3.10), python3-bpfcc, libbpf1, libsqlite3-0, libelf1
Recommends: bpfcc-tools
Suggests: python3-nautilus
Section: devel
Priority: optional
Description: automatic provenance labels for files
 whyfs automatically labels files with their provenance -- where, when, how,
 and what or who caused them to exist -- so people and software agents can
 understand the files they encounter.  A local service (eBPF) records which
 processes create, read, rename and delete files; "whyfs label FILE" and the
 local API explain any file, including its inputs and known dependents.
 .
 Source available under the Business Source License 1.1 (see copyright).
EOF
echo "/etc/whyfs/scope.conf" > "$PKG/DEBIAN/conffiles"
cat > "$PKG/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then systemctl disable --now whyfs.service >/dev/null 2>&1 || true; fi
pkill -TERM -f "[/]usr/bin/whyfs machine run" 2>/dev/null || true
# bytecode Python wrote at run time is not in the package manifest (py3clean's job)
find /usr/lib/python3/dist-packages/whyfs -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
if [ -d /run/systemd/system ]; then
  for u in $(systemctl list-units --plain --no-legend 'whyfs@*.service' 2>/dev/null | awk '{print $1}'); do
    systemctl stop "$u" || true
  done
fi
EOF
cat > "$PKG/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
# collectors built from source by earlier installs; workspace stores (<workspace>/.whyfs) are the users' data and stay
if [ "$1" = remove ] || [ "$1" = purge ]; then rm -rf /var/cache/whyfs /run/whyfs; fi
# the machine store holds the provenance record: kept on remove, deleted on purge
if [ "$1" = purge ]; then rm -rf /var/lib/whyfs; fi
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
EOF
cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# bytecode for every user: each CLI query is a fresh process (removed again by prerm)
python3 -m compileall -q /usr/lib/python3/dist-packages/whyfs >/dev/null 2>&1 || true
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  systemctl enable --now whyfs.service || echo "whyfs: could not start whyfs.service; see: journalctl -u whyfs" >&2
else
  echo "whyfs: systemd is not running here (e.g. WSL without systemd=true): start the labelling service with" >&2
  echo "       sudo whyfs machine run   (or enable systemd in /etc/wsl.conf)" >&2
fi
EOF
chmod 755 "$PKG/DEBIAN/prerm" "$PKG/DEBIAN/postrm" "$PKG/DEBIAN/postinst"
find "$PKG/usr/lib/python3/dist-packages" -name '*.c' ! -name 'whyfs-collect.c' ! -name 'libwhyfs.c' -delete
find "$PKG/usr/lib/python3/dist-packages" "$PKG/usr/share" "$PKG/lib" -type f -exec chmod 644 {} +   # source trees on
find "$PKG" -type d -exec chmod 755 {} +                                                                # /mnt/c are 0777
chmod 644 "$PKG/etc/whyfs/scope.conf" "$PKG/usr/lib/whyfs/scope-default.conf" "$PKG/DEBIAN/conffiles"
# explicit modes: never inherit the builder's umask (a group-writable collector is refused at run time)
chmod 755 "$PKG/usr/lib/whyfs/whyfs-collect" "$PKG/usr/bin/whyfs"
chmod 644 "$PKG/usr/lib/whyfs/whyfs-collect.source-sha256"
mkdir -p "$OUT"
dpkg-deb --root-owner-group --build "$PKG" "$OUT/whyfs_${DEBVER}_${ARCH}.deb" >/dev/null
ls -la "$OUT/whyfs_${DEBVER}_${ARCH}.deb"
rm -rf "$STAGE"
