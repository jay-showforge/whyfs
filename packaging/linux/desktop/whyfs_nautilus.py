"""WhyFS entries in the Files (Nautilus) right-click menu (needs python3-nautilus).

Installed to /usr/share/nautilus-python/extensions/; restart Files (`nautilus -q`) to load it.
Each entry runs `whyfs ui`, which opens the file's provenance label in the WhyFS window.
Nothing here reads or changes the selected file.
"""
import subprocess
from urllib.parse import unquote, urlparse

from gi.repository import GObject

try:
    from gi.repository import Nautilus
except ImportError:  # pragma: no cover
    Nautilus = None

ENTRIES = (
    ("why", "Why does this file exist?", []),
    ("created", "What created this file?", ["--view", "created"]),
    ("impact", "What depends on this file?", ["--view", "impact"]),
    ("history", "Show WhyFS history", ["--view", "history"]),
)


def _path(info):
    uri = info.get_uri()
    u = urlparse(uri)
    return unquote(u.path) if u.scheme == "file" else None


def _run(args):
    subprocess.Popen(["whyfs", "ui", *args], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)


class WhyfsMenu(GObject.GObject, Nautilus.MenuProvider):
    def _menu(self, items):
        top = Nautilus.MenuItem(name="WhyFS::menu", label="WhyFS")
        sub = Nautilus.Menu()
        top.set_submenu(sub)
        for item in items:
            sub.append_item(item)
        return [top]

    def get_file_items(self, *args):
        files = args[-1]
        if len(files) != 1:
            return []
        path = _path(files[0])
        if not path:
            return []
        items = []
        for key, label, extra in ENTRIES:
            if files[0].is_directory() and key != "history":
                continue
            it = Nautilus.MenuItem(name=f"WhyFS::{key}", label=label)
            it.connect("activate", lambda _m, p=path, e=extra: _run(["--file", p, *e]))
            items.append(it)
        if files[0].is_directory():
            it = Nautilus.MenuItem(name="WhyFS::search", label="Search WhyFS in this folder")
            it.connect("activate", lambda _m, p=path: _run(["--path", p]))
            items.append(it)
        return self._menu(items)

    def get_background_items(self, *args):
        folder = args[-1]
        path = _path(folder)
        if not path:
            return []
        it = Nautilus.MenuItem(name="WhyFS::search-bg", label="Search WhyFS in this folder")
        it.connect("activate", lambda _m, p=path: _run(["--path", p]))
        return self._menu([it])
