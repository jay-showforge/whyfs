"""Machine-wide scope policy: which files get a provenance label.

Reference implementation.  The native collectors (whyfs-collect.c, whyfs-collect-win.c) parse
the same rule files with the same semantics and are tested against tests/scope_vectors.json.

Every regular file is in scope unless a rule excludes it; the default rules exclude only
operating-system and application-internal churn (see docs/MACHINE_MODE.md).

Rule file: one rule per line, `#` comments.
    exclude <pattern>         not recorded
    include <pattern>         recorded even if a default exclude matches (include wins)
    temp <pattern>            temporary root: recorded only as a derived temporary
    exclude-image <pattern>   events of processes running this image are not recorded
Patterns are absolute paths matched component-wise as prefixes:
    *        one path component (also a drive: `*:\\Windows`)
    ab*cd    a component with that prefix and suffix (one `*` per component)
    ~        every user's home (Linux `/home/*` and `/root`; Windows `*:\\Users\\*`)
exclude-image patterns without a separator match the image's file name.
Windows paths compare case-insensitively (ASCII), as in the rest of whyfs.
Precedence: include > temp > exclude > (default) in scope.
"""
from __future__ import annotations

import sys

LINUX_DEFAULTS = """\
# whyfs default scope (Linux).  Additions: /etc/whyfs/scope.conf
temp /tmp
temp /var/tmp
temp /dev/shm
exclude /proc
exclude /sys
exclude /dev
exclude /run
exclude /boot
exclude /usr
exclude /lib
exclude /lib32
exclude /lib64
exclude /libx32
exclude /bin
exclude /sbin
exclude /snap
exclude /var/cache
exclude /var/lib
exclude /var/log
exclude /var/spool
exclude /var/crash
exclude ~/.cache
exclude ~/.local/share/Trash
exclude ~/.local/state
exclude ~/.mozilla
exclude ~/.config/google-chrome
exclude ~/.config/chromium
exclude ~/.config/BraveSoftware
exclude ~/.config/microsoft-edge
exclude ~/.thumbnails
exclude ~/.npm/_cacache
exclude ~/.vscode-server/data/logs
exclude ~/.xsession-errors*
exclude-image whyfs-collect
exclude-image tracker-miner-fs-3
exclude-image tracker-extract-3
exclude-image baloo_file
exclude-image baloo_file_extractor
"""

WINDOWS_DEFAULTS = """\
# whyfs default scope (Windows).  Additions: %ProgramData%\\whyfs\\scope.conf
temp ~\\AppData\\Local\\Temp
temp *:\\Windows\\Temp
temp *:\\Windows\\SystemTemp
exclude *:\\Windows
exclude *:\\Program Files
exclude *:\\Program Files (x86)
exclude *:\\ProgramData
exclude *:\\$Recycle.Bin
exclude *:\\System Volume Information
exclude *:\\Recovery
exclude *:\\$WinREAgent
exclude *:\\Config.Msi
exclude *:\\pagefile.sys
exclude *:\\hiberfil.sys
exclude *:\\swapfile.sys
exclude *:\\DumpStack.log*
exclude ~\\AppData\\Local
exclude ~\\AppData\\LocalLow
exclude ~\\AppData\\Roaming\\Microsoft
exclude ~\\NTUSER*
exclude ~\\ntuser*
exclude-image whyfs-collect-win.exe
exclude-image MsMpEng.exe
exclude-image MpDefenderCoreService.exe
exclude-image NisSrv.exe
exclude-image MsSense.exe
exclude-image SearchIndexer.exe
exclude-image SearchProtocolHost.exe
exclude-image SearchFilterHost.exe
"""

IN, TEMP, OUT = "in", "temp", "out"


def _lower(s: str) -> str:
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


class Scope:
    def __init__(self, nt: bool | None = None, text: str | None = None):
        self.nt = (sys.platform == "win32") if nt is None else nt
        self.sep = "\\" if self.nt else "/"
        self.rules: list[tuple[str, list[str]]] = []   # (kind, components)
        self.images: list[list[str] | str] = []
        self.add(text if text is not None else (WINDOWS_DEFAULTS if self.nt else LINUX_DEFAULTS))

    # -- parsing
    def add(self, text: str) -> "Scope":
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            kind, _, pat = line.partition(" ")
            pat = pat.strip()
            if not pat or kind not in ("exclude", "include", "temp", "exclude-image"):
                continue
            if kind == "exclude-image":
                self.images.append(self._split(pat) if ("/" in pat or "\\" in pat) else self._fold(pat))
                continue
            for comps in self._expand(pat):
                self.rules.append((kind, comps))
        return self

    def _fold(self, s: str) -> str:
        return _lower(s) if self.nt else s

    def _split(self, p: str) -> list[str]:
        if self.nt:
            p = p.replace("/", "\\")
        return [self._fold(c) for c in p.split(self.sep) if c]

    def _expand(self, pat: str) -> list[list[str]]:
        if pat == "~" or pat.startswith("~/") or pat.startswith("~\\"):
            rest = pat[2:] if len(pat) > 1 else ""
            homes = ["*:\\Users\\*"] if self.nt else ["/home/*", "/root"]
            return [self._split(h + (self.sep + rest if rest else "")) for h in homes]
        return [self._split(pat)]

    # -- matching
    @staticmethod
    def _comp_match(pc: str, c: str) -> bool:
        """`pre*suf` (one `*`, either part may be empty) or an exact component."""
        star = pc.find("*")
        if star < 0:
            return pc == c
        pre, suf = pc[:star], pc[star + 1:]
        return len(c) >= len(pre) + len(suf) and c.startswith(pre) and c.endswith(suf)

    def _match(self, comps: list[str], pat: list[str]) -> bool:
        if len(pat) > len(comps):
            return False
        return all(self._comp_match(pc, c) for pc, c in zip(pat, comps))

    def classify(self, path: str) -> str:
        comps = self._split(path)
        found = {k: False for k in ("include", "temp", "exclude")}
        for kind, pat in self.rules:
            if not found[kind] and self._match(comps, pat):
                found[kind] = True
        if found["include"]:
            return IN
        if found["temp"]:
            return TEMP
        if found["exclude"]:
            return OUT
        return IN

    def image_excluded(self, exe: str | None) -> bool:
        if not exe:
            return False
        comps = self._split(exe)
        name = comps[-1] if comps else ""
        for pat in self.images:
            if isinstance(pat, str):
                if self._comp_match(pat, name):
                    return True
            elif self._match(comps, pat):
                return True
        return False


def defaults_text(nt: bool | None = None) -> str:
    nt = (sys.platform == "win32") if nt is None else nt
    return WINDOWS_DEFAULTS if nt else LINUX_DEFAULTS


if __name__ == "__main__":  # python -m whyfs.scope [linux|windows] > scope-default.conf
    which = sys.argv[1] if len(sys.argv) > 1 else ("windows" if sys.platform == "win32" else "linux")
    sys.stdout.write(defaults_text(which == "windows"))
