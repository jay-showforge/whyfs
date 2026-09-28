"""Where the tests find the Windows collector built for the machine they run on."""
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def win_arch() -> str | None:
    return {"AMD64": "x64", "ARM64": "arm64"}.get(
        (os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE", "")).upper())


def win_collector() -> Path | None:
    """WHYFS_COLLECT_WIN, else src/whyfs/_bin/win-<this machine's arch>/whyfs-collect-win.exe, if it exists."""
    if os.name != "nt":
        return None
    for p in (os.environ.get("WHYFS_COLLECT_WIN"), REPO / "src" / "whyfs" / "_bin" / f"win-{win_arch()}" / "whyfs-collect-win.exe"):
        if p and Path(p).exists():
            return Path(p)
    return None
