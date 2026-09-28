"""Regenerate docs/assets/whyfs-window.png from real WhyFS output.

1. Build the demo (see docs/assets/README.md) with the whyfs service running.
2. `python docs/assets/make_screenshots.py capture` records the real API replies for the demo
   (search, label, sessions, status) into docs/assets/demo-api.json, replacing the local user
   name, host name and SID with neutral ones.
3. `python docs/assets/make_screenshots.py shoot` serves the unmodified src/whyfs/ui.html with
   those recorded replies on 127.0.0.1 and takes a headless Edge/Chrome screenshot.
Nothing is invented: every value shown was produced by WhyFS for the demo files.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DEMO = r"C:\WhyFS-Demo\checkout-app"
DATA = HERE / "demo-api.json"


def anonymize(obj, user: str, host: str, sid: str):
    text = json.dumps(obj)
    for a, b in ((sid, "S-1-5-21-1111111111-2222222222-3333333333-1001"), (f"{host}\\\\{user}", "DEMO-PC\\\\alex"),
                 (f"C:\\\\Users\\\\{user}", "C:\\\\Users\\\\alex"), (host, "DEMO-PC")):
        text = text.replace(a, b)
    text = re.sub(r"--resume=[0-9a-f-]+", "--resume=<session>", text)
    text = re.sub(re.escape(user), "alex", text, flags=re.I)                 # any remaining form of the user name
    text = re.sub(re.escape(host), "DEMO-PC", text, flags=re.I)
    text = re.sub(r"C--Users-alex-[A-Za-z0-9 -]+", "C--Users-alex-project", text)  # agent state paths
    text = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\\|\.|\")",
                  lambda m: m.group(0) if m.group(0).startswith("d0") else "00000000-0000-0000-0000-000000000000", text)
    return json.loads(text)


def capture() -> None:
    sys.path.insert(0, str(REPO / "src"))
    from whyfs.client import call
    app = DEMO + r"\dist\assets\app.js"
    rec = {
        "search_files": call("search_files", {"path": DEMO, "limit": 50})["result"],
        "get_file_provenance": {p: call("get_file_provenance", {"path": p})["result"]
                                for p in (app, DEMO + r"\src\main.ts", DEMO + r"\release.zip")},
        "list_agent_sessions": [s for s in call("list_agent_sessions", {"limit": 50})["result"]
                                if (s.get("workspace") or "").lower().startswith(DEMO.lower())][:3],
        "status": call("status", {})["result"],
    }
    rec["search_files"] = [r for r in rec["search_files"] if "node_modules" not in r["path"]]
    st = rec["status"]
    for k in ("scope_rules", "collector_stats", "policy", "collector"):
        st.pop(k, None)
    user, host = os.environ["USERNAME"], os.environ["COMPUTERNAME"]
    sid = st.get("requester") or ""
    DATA.write_text(json.dumps(anonymize(rec, user, host, sid), indent=1), encoding="utf-8")
    print(f"recorded {DATA}")


def shoot(out: Path) -> None:
    """The unmodified ui.html, with its /api calls answered from the recorded replies (a small
    script injected before the page's own), rendered from a local file by headless Chrome/Edge."""
    import tempfile
    rec = json.loads(DATA.read_text(encoding="utf-8"))
    page = (REPO / "src" / "whyfs" / "ui.html").read_text(encoding="utf-8")
    shim = ("<script>\nconst RECORDED = " + json.dumps(rec) + ";\n"
            "history.replaceState = () => {};\n"
            "window.fetch = async (url, opt) => {\n"
            "  const req = JSON.parse(opt.body);\n"
            "  let res = req.op === 'get_file_provenance' ? (RECORDED.get_file_provenance[req.params.path] ||\n"
            "    {status: 'no-record', path: req.params.path, history: []}) : (RECORDED[req.op] || []);\n"
            "  return {ok: true, json: async () => ({ok: true, result: res})};\n"
            "};\n</script>\n")
    page = page.replace("<script>\n\"use strict\";", shim + "<script>\n\"use strict\";", 1)
    tmp = HERE / "_render"  # next to the assets: some sandboxes hide the user's TEMP from the browser
    tmp.mkdir(exist_ok=True)
    html = tmp / "window.html"
    html.write_text(page, encoding="utf-8")
    frag = urllib.parse.urlencode({"path": DEMO, "file": DEMO + r"\dist\assets\app.js"}, quote_via=urllib.parse.quote)
    url = html.as_uri() + "#" + frag
    # headless browsers are not always available: capture a real app window (capture_window.ps1)
    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", str(HERE / "capture_window.ps1"),
                    "-Url", url, "-Out", str(out), "-Width", "1300", "-Height", "960"], check=True, timeout=180)
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"wrote {out}")


if __name__ == "__main__":
    if sys.argv[1:] == ["capture"]:
        capture()
    else:
        shoot(HERE / "whyfs-window.png")
