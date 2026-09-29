"""Build the macOS installer package on a Mac of the target architecture.

  python3 packaging/macos/build_pkg.py --out dist [--version 1.0.0.9001] [--build-id ID]
      [--codesign-identity "Developer ID Application: ..." --provisioning-profile FILE]
      [--installer-identity "Developer ID Installer: ..."]

Without the identities the package is an UNSIGNED DEVELOPMENT ARTIFACT -- NOT FOR PUBLIC RELEASE
(its file name and installer title say so): the collector carries an ad hoc signature, which
only a Mac with System Integrity Protection disabled accepts for the Endpoint Security
entitlement.  Real signing and notarization are the options above plus `xcrun notarytool`;
nothing in the layout changes (docs/MACOS.md).

Installs (everything root-owned):
  /Library/WhyFS/WhyFSCollector.app          the Endpoint Security collector, an app bundle so a
                                             provisioning profile can be embedded; also the launchd
                                             program (--launchd), which holds Full Disk Access
  /Library/WhyFS/runtime/                    private CPython (python-build-standalone, pinned by
                                             SHA-256) with whyfs in its site-packages
  /Library/WhyFS/bin/whyfs                   the command; /usr/local/bin/whyfs links to it
  /Library/WhyFS/scope-default.conf, uninstall.sh, LICENSE, THIRD_PARTY_NOTICES.txt
  /Library/LaunchDaemons/org.tenzorpipe.whyfs.plist   RunAtLoad + KeepAlive
  /Applications/WhyFS.app                    opens the WhyFS window (search)
  /Library/Services/WhyFS - *.workflow       Finder Quick Actions
The provenance store (/Library/Application Support/WhyFS) is created by the service and is never
part of the package: upgrades and uninstalls keep it (uninstall.sh --purge removes it).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import plistlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "src"))
from whyfs import __version__, macos  # noqa: E402
from whyfs.scope import defaults_text  # noqa: E402

LABEL = macos.LABEL
IDENT = "org.tenzorpipe.whyfs"
RUNTIME_RELEASE = "20260924"
RUNTIME_VERSION = "3.12.14"
RUNTIME_SHA256 = {  # the release's own digests (GitHub asset digests), checked before use
    "arm64": "9763f43db2481a6af36af82ec40302aab7a73632f880129d07a6e81aec846277",
    "x86_64": "0d6a4a299908123f00bc844df737603f047ff9eba14fda6cad83f3cf3cb3a2af",
}
TRIPLE = {"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}
UNSIGNED = "UNSIGNED DEVELOPMENT ARTIFACT — NOT FOR PUBLIC RELEASE"
QUICK_ACTIONS = [  # (file name, menu item, whyfs ui arguments) -- the Explorer / Files menu, same words
    ("WhyFS - Why does this file exist", "Why does this file exist?", '--file "$f"'),
    ("WhyFS - What created this file", "What created this file?", '--file "$f" --view created'),
    ("WhyFS - What depends on this file", "What depends on this file?", '--file "$f" --view impact'),
    ("WhyFS - Show WhyFS history", "Show WhyFS history", '--file "$f" --view history'),
    ("WhyFS - Search WhyFS", "Search WhyFS in this folder", None),
]


def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run([str(c) for c in cmd], check=True, **kw)


def fetch_runtime(arch: str, cache: Path) -> Path:
    name = f"cpython-{RUNTIME_VERSION}+{RUNTIME_RELEASE}-{TRIPLE[arch]}-install_only.tar.gz"
    dest = cache / name
    if not dest.exists():
        url = (f"https://github.com/astral-sh/python-build-standalone/releases/download/{RUNTIME_RELEASE}/"
               + name.replace("+", "%2B"))
        cache.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".part")
        for attempt in range(4):  # a dropped connection is retried; the digest below is checked regardless
            try:
                with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:
                    shutil.copyfileobj(r, f)
                break
            except OSError as exc:  # URLError, RemoteDisconnected, timeouts
                if attempt == 3:
                    raise SystemExit(f"runtime download failed: {exc}")
                print(f"runtime download attempt {attempt + 1} failed ({exc}); retrying", flush=True)
                import time
                time.sleep(10 * (attempt + 1))
        tmp.rename(dest)
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    if digest != RUNTIME_SHA256[arch]:
        dest.unlink()
        raise SystemExit(f"runtime {name}: SHA-256 {digest} is not the pinned {RUNTIME_SHA256[arch]}")
    return dest


def workflow(menu: str, script: str, folders: bool) -> tuple[dict, dict]:
    """(Info.plist, document.wflow) of a Finder Quick Action running one shell script with the
    selected items as arguments (Automator's Run Shell Script action, input as arguments)."""
    info = {"NSServices": [{
        "NSBackgroundColorName": "background", "NSIconName": "NSActionTemplate",
        "NSMenuItem": {"default": f"WhyFS: {menu}"}, "NSMessage": "runWorkflowAsService",
        "NSRequiredContext": {"NSApplicationIdentifier": "com.apple.finder"},
        "NSSendFileTypes": ["public.folder"] if folders else ["public.item"]}]}
    uid = [str(uuid.uuid5(uuid.NAMESPACE_URL, f"whyfs-quick-action:{menu}:{x}")).upper() for x in range(3)]  # reproducible
    args = {str(i): {"default value": dv, "name": n, "required": "0", "type": "0", "uuid": str(i)}
            for i, (n, dv) in enumerate([("inputMethod", 0), ("source", ""), ("CheckedForUserDefaultShell", True),
                                         ("COMMAND_STRING", ""), ("shell", "")])}
    action = {
        "AMAccepts": {"Container": "List", "Optional": True, "Types": ["com.apple.cocoa.string"]},
        "AMActionVersion": "2.0.3", "AMApplication": ["Automator"],
        "AMParameterProperties": {k: {} for k in ("COMMAND_STRING", "CheckedForUserDefaultShell", "inputMethod", "shell", "source")},
        "AMProvides": {"Container": "List", "Types": ["com.apple.cocoa.string"]},
        "ActionBundlePath": "/System/Library/Automator/Run Shell Script.action", "ActionName": "Run Shell Script",
        "ActionParameters": {"COMMAND_STRING": script, "CheckedForUserDefaultShell": True, "inputMethod": 1,
                             "shell": "/bin/sh", "source": ""},
        "BundleIdentifier": "com.apple.RunShellScript", "CFBundleVersion": "2.0.3",
        "CanShowSelectedItemsWhenRun": False, "CanShowWhenRun": True, "Category": ["AMCategoryUtilities"],
        "Class Name": "RunShellScriptAction", "InputUUID": uid[0], "Keywords": ["Shell", "Script", "Command", "Run", "Unix"],
        "OutputUUID": uid[1], "UUID": uid[2], "UnlocalizedApplications": ["Automator"], "arguments": args,
        "isViewVisible": 1, "location": "309.000000:253.000000",
        "nibPath": "/System/Library/Automator/Run Shell Script.action/Contents/Resources/Base.lproj/main.nib"}
    doc = {"AMApplicationBuild": "523", "AMApplicationVersion": "2.10", "AMDocumentVersion": "2",
           "actions": [{"action": action, "isViewVisible": 1}], "connectors": {},
           "workflowMetaData": {
               "applicationBundleIDsByPath": {}, "applicationPaths": [],
               "inputTypeIdentifier": "com.apple.Automator.fileSystemObject",
               "outputTypeIdentifier": "com.apple.Automator.nothing", "presentationMode": 15,
               "processesInput": False, "serviceInputTypeIdentifier": "com.apple.Automator.fileSystemObject",
               "serviceOutputTypeIdentifier": "com.apple.Automator.nothing", "serviceProcessesInput": False,
               "systemImageName": "NSActionTemplate", "useAutomaticInputType": False,
               "workflowTypeIdentifier": "com.apple.Automator.servicesMenu"}}
    return info, doc


def quick_actions(dest: Path) -> None:
    for name, menu, uiargs in QUICK_ACTIONS:
        if uiargs:
            script = f'for f in "$@"; do /Library/WhyFS/bin/whyfs ui {uiargs}; done\n'
        else:  # search in the chosen folder (or the folder of a chosen file)
            script = 'for f in "$@"; do [ -d "$f" ] || f=$(dirname "$f"); /Library/WhyFS/bin/whyfs ui --path "$f"; done\n'
        info, doc = workflow(menu, script, folders=uiargs is None)
        c = dest / f"{name}.workflow" / "Contents"
        c.mkdir(parents=True)
        with open(c / "Info.plist", "wb") as f:
            plistlib.dump(info, f)
        with open(c / "document.wflow", "wb") as f:
            plistlib.dump(doc, f)


def app_bundle(dest: Path, ident: str, name: str, exe: str, version: str, *, ui_element: bool) -> Path:
    c = dest / f"{name}.app" / "Contents"
    (c / "MacOS").mkdir(parents=True)
    with open(c / "Info.plist", "wb") as f:
        plistlib.dump({"CFBundleIdentifier": ident, "CFBundleName": name, "CFBundleDisplayName": name,
                       "CFBundleExecutable": exe, "CFBundlePackageType": "APPL", "CFBundleVersion": version,
                       "CFBundleShortVersionString": version, "LSMinimumSystemVersion": "13.0",
                       "LSUIElement": ui_element, "NSHumanReadableCopyright": "(c) 2026 Jonathan Tyler Montgomery"}, f)
    return c


def stage(arch: str, version: str, root: Path, cache: Path, a) -> None:
    lib = root / "Library" / "WhyFS"
    (lib / "bin").mkdir(parents=True)
    # --- runtime + whyfs
    tgz = fetch_runtime(arch, cache)
    with tarfile.open(tgz) as t:
        t.extractall(lib, filter="tar")
    (lib / "python").rename(lib / "runtime")
    py = lib / "runtime" / "bin" / "python3"
    site = next((lib / "runtime" / "lib").glob("python3.*")) / "site-packages"
    shutil.copytree(REPO / "src" / "whyfs", site / "whyfs",
                    ignore=shutil.ignore_patterns("__pycache__", "_bin", "windows", "*.pyc"))
    run([py, "-I", "-m", "compileall", "-q", site / "whyfs"])
    out = run([py, "-I", "-c", "import platform, whyfs; print(platform.machine(), whyfs.__version__)"],
              capture_output=True, text=True).stdout.split()
    if out[0] != arch:
        raise SystemExit(f"bundled runtime runs as {out[0]}, not {arch}")
    # --- the collector, in its app bundle
    c = app_bundle(lib, "org.tenzorpipe.whyfs.collector", "WhyFSCollector", "whyfs-collect", version, ui_element=True)
    exe = c / "MacOS" / "whyfs-collect"
    macos.build_collector(exe, sign=None)
    if a.provisioning_profile:
        shutil.copy2(a.provisioning_profile, c / "embedded.provisionprofile")
    sign = a.codesign_identity or "-"
    run(["codesign", "-s", sign, "-f", "--options", "runtime", "--timestamp" if a.codesign_identity else "--timestamp=none",
         "--entitlements", macos.ENTITLEMENTS, c.parent])
    arch_of = subprocess.run(["lipo", "-archs", exe], capture_output=True, text=True).stdout.strip()
    if arch_of != arch:
        raise SystemExit(f"collector is {arch_of}, not {arch}")
    # --- command, configuration, uninstaller, notices
    (lib / "bin" / "whyfs").write_text('#!/bin/sh\nexec /Library/WhyFS/runtime/bin/python3 -I -m whyfs "$@"\n')
    (lib / "scope-default.conf").write_text(defaults_text(False, True))
    shutil.copy2(HERE / "uninstall.sh", lib / "uninstall.sh")
    shutil.copy2(REPO / "LICENSE", lib / "LICENSE")
    lic = next(iter(sorted((lib / "runtime").rglob("LICENSE.txt"), key=lambda p: len(p.parts))), None)
    if lic is None:
        raise SystemExit("the bundled runtime has no LICENSE.txt")
    shutil.copy2(lic, lib / "PYTHON_LICENSE.txt")
    (lib / "THIRD_PARTY_NOTICES.txt").write_text(
        "WhyFS for macOS bundles third-party components that are not part of the Licensed Work:\n\n"
        f"* CPython {RUNTIME_VERSION} (runtime/): Python Software Foundation License Version 2; full text in\n"
        "  PYTHON_LICENSE.txt, which includes the licenses of the components CPython bundles.  The\n"
        f"  build is python-build-standalone {RUNTIME_RELEASE} (github.com/astral-sh/python-build-standalone),\n"
        "  whose distribution licenses are in runtime/.\n")
    for f in (lib / "bin" / "whyfs", lib / "uninstall.sh"):
        os.chmod(f, 0o755)
    # --- launchd job
    ld = root / "Library" / "LaunchDaemons"
    ld.mkdir(parents=True)
    with open(ld / f"{LABEL}.plist", "wb") as f:
        plistlib.dump({
            "Label": LABEL,
            "ProgramArguments": [str(Path("/") / exe.relative_to(root)), "--launchd", "--",
                                 "/Library/WhyFS/runtime/bin/python3", "-I", "-m", "whyfs", "machine", "run"],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 5, "ExitTimeOut": 120,
            "ProcessType": "Standard", "AssociatedBundleIdentifiers": ["org.tenzorpipe.whyfs.collector"],
            "StandardOutPath": "/Library/Logs/WhyFS/service.log", "StandardErrorPath": "/Library/Logs/WhyFS/service.log",
        }, f)
    # --- command on the PATH, the WhyFS window, Finder Quick Actions
    ub = root / "usr" / "local" / "bin"
    ub.mkdir(parents=True)
    os.symlink("/Library/WhyFS/bin/whyfs", ub / "whyfs")
    c = app_bundle(root / "Applications", "org.tenzorpipe.whyfs.app", "WhyFS", "WhyFS", version, ui_element=True)
    (c / "MacOS" / "WhyFS").write_text("#!/bin/sh\nexec /Library/WhyFS/bin/whyfs ui\n")
    os.chmod(c / "MacOS" / "WhyFS", 0o755)
    quick_actions(root / "Library" / "Services")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--version", default=f"{__version__}.9000")
    ap.add_argument("--build-id", default="local", help="identifies the development build in the file name")
    ap.add_argument("--codesign-identity")
    ap.add_argument("--provisioning-profile")
    ap.add_argument("--installer-identity")
    ap.add_argument("--cache", default=str(Path.home() / "Library" / "Caches" / "whyfs-build"))
    a = ap.parse_args()
    arch = os.uname().machine
    signed = bool(a.codesign_identity and a.provisioning_profile and a.installer_identity)
    outdir = Path(a.out).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        root, scripts, res = t / "root", t / "scripts", t / "resources"
        stage(arch, a.version, root, Path(a.cache), a)
        shutil.copytree(HERE / "scripts", scripts)
        for f in scripts.iterdir():
            os.chmod(f, 0o755)
        res.mkdir()
        shutil.copy2(REPO / "LICENSE", res / "LICENSE.txt")
        comp = t / "whyfs-component.pkg"
        run(["pkgbuild", "--root", root, "--scripts", scripts, "--identifier", IDENT, "--version", a.version,
             "--install-location", "/", "--ownership", "recommended", comp])
        title = "WhyFS" if signed else f"WhyFS ({UNSIGNED})"
        dist = (HERE / "distribution.xml").read_text().replace("@TITLE@", title).replace("@ARCH@", arch) \
            .replace("@VERSION@", a.version)
        (t / "distribution.xml").write_text(dist)
        name = (f"whyfs-{a.version}-macos-{arch}.pkg" if signed
                else f"whyfs-{a.version}-macos-{arch}-dev-{a.build_id}-UNSIGNED.pkg")
        cmd = ["productbuild", "--distribution", t / "distribution.xml", "--resources", res, "--package-path", t]
        if a.installer_identity:
            cmd += ["--sign", a.installer_identity]
        run([*cmd, outdir / name])
    if not signed:
        (outdir / f"{name}.README.txt").write_text(
            f"{name}\n\n{UNSIGNED}.\nBuilt for {arch} from commit {os.environ.get('GITHUB_SHA', 'local')}.\n"
            "Its collector carries an ad hoc signature: on a Mac with System Integrity Protection enabled,\n"
            "macOS refuses its Endpoint Security entitlement (docs/MACOS.md).\n")
    print(outdir / name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
