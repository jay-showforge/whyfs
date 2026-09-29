#!/bin/sh
# Remove WhyFS:  sudo /Library/WhyFS/uninstall.sh [--purge]
# The provenance store (/Library/Application Support/WhyFS) is kept unless --purge is given.
set -u
if [ "$(id -u)" != 0 ]; then echo "run as root: sudo $0 ${1:-}"; exit 1; fi
LABEL=org.tenzorpipe.whyfs
launchctl bootout system/$LABEL 2>/dev/null   # stops the service; the collector drains first
rm -f /Library/LaunchDaemons/$LABEL.plist
rm -rf /Library/WhyFS /Applications/WhyFS.app /var/run/whyfs
rm -rf "/Library/Services/WhyFS - "*.workflow
if [ -L /usr/local/bin/whyfs ]; then rm -f /usr/local/bin/whyfs; fi
pkgutil --forget org.tenzorpipe.whyfs >/dev/null 2>&1
if [ "${1:-}" = "--purge" ]; then
    rm -rf "/Library/Application Support/WhyFS" /Library/Logs/WhyFS
    echo "WhyFS removed, with its provenance store."
else
    echo "WhyFS removed.  Kept: /Library/Application Support/WhyFS (the provenance store); remove it with --purge."
fi
exit 0
