"""Build the Windows installer (whyfs-<version>-<arch>.msi).

Run with a Python that still has msilib (3.11/3.12); the *bundled runtime* is taken from
--runtime (default C:\\Python313) and must match the target architecture.

  C:\\Python311\\python.exe native\\windows\\make_msi.py --arch x64 --out dist

Installs to %ProgramFiles%\\whyfs:
  whyfs.exe                  launcher on the system PATH (runs runtime\\python.exe -m whyfs)
  whyfs-svc.exe              the collector service (registered, auto-start, started at install)
  whyfs-collect-win.exe      the native ETW collector the service runs per workspace
  runtime\\                   private, isolated Python runtime (._pth: no site-packages, no env)
  lib\\whyfs\\                 the whyfs package (precompiled)
  LICENSE, THIRD_PARTY_NOTICES.txt
Uninstall stops and removes the service and every installed file.  Workspace stores
(<workspace>\\.whyfs) belong to their users and are never touched.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import msilib
from msilib import CAB, Directory, Feature, schema, sequence

REPO = Path(__file__).resolve().parents[2]
UPGRADE_CODE = "{6E1B3F0A-3C8E-4B8B-9E3A-5D3C7A4F2B11}"  # stable across versions: enables upgrades
RUNTIME_EXCLUDE_DLLS = ("tcl", "tk", "_tkinter", "_test", "winsound", "_ssl", "libssl", "libcrypto", "_hashlib",
                        "_wmi", "py.ico", "pyc.ico", "pyd.ico", "python_lib.cat", "_ctypes_test")
STDLIB_EXCLUDE = {"test", "idlelib", "tkinter", "turtledemo", "ensurepip", "site-packages", "__pycache__", "lib2to3",
                  "venv", "pydoc_data"}


def package_version() -> str:
    for line in (REPO / "pyproject.toml").read_text().splitlines():
        if line.startswith("version"):
            return line.split('"')[1]
    raise SystemExit("no version")


def msi_version(v: str) -> str:  # MSI ProductVersion: major.minor.build (numbers only)
    import re
    nums = [int(x) for x in re.findall(r"\d+", v)][:4]
    while len(nums) < 3:
        nums.append(0)
    major, minor, patch = nums[:3]
    dev = nums[3] if len(nums) > 3 else 0
    return f"{major}.{minor}.{patch * 1000 + dev}"


def pe_machine(path: Path) -> int:
    b = path.read_bytes()[:4096]
    pe = int.from_bytes(b[0x3C:0x40], "little")
    return int.from_bytes(b[pe + 4:pe + 6], "little")


def host_arch() -> str:
    """The machine's native architecture, also from an emulated x64 process on ARM64."""
    import ctypes
    from ctypes import wintypes
    proc, native = wintypes.USHORT(), wintypes.USHORT()
    k32 = ctypes.windll.kernel32
    if hasattr(k32, "IsWow64Process2") and k32.IsWow64Process2(k32.GetCurrentProcess(), ctypes.byref(proc), ctypes.byref(native)):
        return "arm64" if native.value == 0xAA64 else "x64"
    return "x64"


def stage(arch: str, runtime: Path, stage_dir: Path, vcvars: str, build_python: str | None = None) -> None:
    pyc = bytecode_python(runtime, arch, build_python)
    binsrc = REPO / "src" / "whyfs" / "_bin" / f"win-{arch}"
    for b in ("whyfs-svc.exe", "whyfs-collect-win.exe"):
        if not (binsrc / b).exists():
            raise SystemExit(f"missing {binsrc / b}: run native/windows/build.ps1 first")
        shutil.copy2(binsrc / b, stage_dir / b)
    host = host_arch()
    vcarg = arch if arch == host else f"{host}_{arch}"  # native, or cross from this host
    vcall = str(Path(vcvars).parent / "vcvarsall.bat")
    obj = Path(tempfile.mkdtemp())
    subprocess.run(f'cmd /c ""{vcall}" {vcarg} >nul && cl /nologo /O2 /W4 "{REPO}\\src\\whyfs\\native\\windows\\whyfs-launcher.c" '
                   f'/Fe:"{stage_dir}\\whyfs.exe" /Fo:"{obj}\\\\" >nul"', check=True)
    # --- private runtime
    rt = stage_dir / "runtime"
    rt.mkdir()
    want = {"x64": 0x8664, "arm64": 0xAA64}[arch]
    for f in ("python.exe", "pythonw.exe", "python3.dll", f"python{ver_tag(runtime)}.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
        if pe_machine(runtime / f) != want:
            # the ARM64 CPython package carries an x64 vcruntime140_1.dll that no ARM64 image imports
            if f == "vcruntime140_1.dll":
                print(f"skipping {f}: not a {arch} image")
                continue
            raise SystemExit(f"{runtime / f} is not a {arch} image")
        shutil.copy2(runtime / f, rt / f)
    shutil.copy2(runtime / "LICENSE.txt", rt / "PYTHON_LICENSE.txt")
    for f in (runtime / "DLLs").iterdir():
        if f.is_file() and not f.name.lower().startswith(RUNTIME_EXCLUDE_DLLS):
            shutil.copy2(f, rt / f.name)
    tag = ver_tag(runtime)
    # stdlib zip compiled by the bundled interpreter itself (matching .pyc magic)
    helper = obj / "mkzip.py"
    helper.write_text(
        "import sys, zipfile, os\n"
        f"lib, out, excl = sys.argv[1], sys.argv[2], {sorted(STDLIB_EXCLUDE)!r}\n"
        "z = zipfile.PyZipFile(out, 'w', zipfile.ZIP_DEFLATED, optimize=0)\n"
        "for name in sorted(os.listdir(lib)):\n"
        "    p = os.path.join(lib, name)\n"
        "    if name in excl: continue\n"
        "    if os.path.isdir(p) and os.path.exists(os.path.join(p, '__init__.py')): z.writepy(p)\n"
        "    elif name.endswith('.py'): z.writepy(p)\n"
        "z.close()\n")
    subprocess.run([pyc, "-I", str(helper), str(runtime / "Lib"), str(rt / f"python{tag}.zip")], check=True)
    (rt / f"python{tag}._pth").write_text(f"python{tag}.zip\n.\n..\\lib\n")
    # --- whyfs package
    pkg = stage_dir / "lib" / "whyfs"
    shutil.copytree(REPO / "src" / "whyfs", pkg, ignore=shutil.ignore_patterns("__pycache__", "_bin", "native", "*.so", "*.c"))
    subprocess.run([pyc, "-I", "-m", "compileall", "-q", str(pkg)], check=True)  # the bytecode the launcher loads
    shutil.copy2(REPO / "LICENSE", stage_dir / "LICENSE")
    # the machine scope policy's defaults (docs/MACHINE_MODE.md); additions: %ProgramData%\whyfs\scope.conf
    sys.path.insert(0, str(REPO / "src"))
    from whyfs.scope import defaults_text
    (stage_dir / "scope-default.conf").write_text(defaults_text(True), encoding="utf-8")
    (stage_dir / "THIRD_PARTY_NOTICES.txt").write_text(
        "whyfs for Windows bundles third-party components that are not part of the Licensed Work:\n\n"
        f"* CPython {runtime_version(runtime)} runtime (runtime\\): Python Software Foundation License Version 2;\n"
        "  full text in runtime\\PYTHON_LICENSE.txt (includes the licenses of components CPython bundles:\n"
        "  libffi, zlib, bzip2, xz, expat, SQLite (public domain), mpdecimal).\n"
        "* Microsoft Visual C++ runtime (runtime\\vcruntime140*.dll): redistributed under the Microsoft\n"
        "  Visual Studio license terms for redistributable code.\n"
        "* SQLite used by the collector: Windows' own System32\\winsqlite3.dll (not redistributed).\n")


def ver_tag(runtime: Path) -> str:
    return next(p.stem[6:] for p in runtime.glob("python3??.dll") if p.stem[6:].isdigit())


def runtime_version(runtime: Path) -> str:
    """ProductVersion of the runtime's python3XY.dll (read from the PE resource: the runtime
    may be for another architecture and cannot always be executed here)."""
    import ctypes
    from ctypes import wintypes
    dll = str(runtime / f"python{ver_tag(runtime)}.dll")
    ver = ctypes.windll.version
    size = ver.GetFileVersionInfoSizeW(dll, None)
    buf = ctypes.create_string_buffer(size)
    ver.GetFileVersionInfoW(dll, 0, size, buf)
    val, n = ctypes.c_wchar_p(), wintypes.UINT()
    trans, tn = ctypes.c_void_p(), wintypes.UINT()
    ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(trans), ctypes.byref(tn))
    lang, cp = ctypes.cast(trans, ctypes.POINTER(wintypes.WORD * 2)).contents
    ver.VerQueryValueW(buf, f"\\StringFileInfo\\{lang:04x}{cp:04x}\\ProductVersion", ctypes.byref(val), ctypes.byref(n))
    return val.value.strip()


def bytecode_python(runtime: Path, arch: str, build_python: str | None) -> str:
    """The interpreter that byte-compiles the bundled stdlib and whyfs.  Bytecode is
    architecture-independent but version-specific: the runtime itself when this host can run
    it, else a host interpreter of exactly the same version (checked, never assumed)."""
    if not build_python:
        if arch != host_arch():
            raise SystemExit(f"building the {arch} MSI on a {host_arch()} host needs --build-python "
                             f"(a {runtime_version(runtime)} interpreter for this host)")
        return str(runtime / "python.exe")
    have = subprocess.run([build_python, "-c", "import sys;print(sys.version.split()[0])"],
                          capture_output=True, text=True, check=True).stdout.strip()
    want = runtime_version(runtime)
    if have != want:
        raise SystemExit(f"--build-python is {have}, the bundled runtime is {want}: bytecode would not match")
    return build_python


def build_msi(stage_dir: Path, out: Path, arch: str, version: str) -> Path:
    mver = msi_version(version)
    msi = out / f"whyfs-{version}-{arch}.msi"
    if msi.exists():
        msi.unlink()
    product_code = "{" + str(uuid.uuid4()).upper() + "}"
    db = msilib.init_database(str(msi), schema, "whyfs", product_code, mver, "Jonathan Tyler Montgomery")
    msilib.add_tables(db, sequence)
    platform = "x64" if arch == "x64" else "Arm64"
    si = db.GetSummaryInformation(20)
    si.SetProperty(msilib.PID_TEMPLATE, f"{platform};1033")
    si.SetProperty(msilib.PID_WORDCOUNT, 2)  # compressed, long file names
    si.SetProperty(msilib.PID_TITLE, "whyfs installer")
    si.SetProperty(msilib.PID_SUBJECT, f"whyfs {version} ({arch})")
    si.SetProperty(msilib.PID_REVNUMBER, product_code)
    si.Persist()
    msilib.add_data(db, "Property", [
        ("UpgradeCode", UPGRADE_CODE), ("ALLUSERS", "1"), ("ARPNOMODIFY", "1"),
        ("ARPCOMMENTS", "Records where files in your workspaces came from: whyfs why / impact / history."),
        ("ARPHELPLINK", "mailto:licensing@tenzorpipe.org"), ("MSIFASTINSTALL", "1"),
        ("SecureCustomProperties", "WHYFSOLDER;WHYFSNEWER"),
    ])
    # major upgrades: remove any older whyfs before installing this one
    msilib.add_data(db, "Upgrade", [(UPGRADE_CODE, None, mver, None, 256 | 1, None, "WHYFSOLDER"),
                                    (UPGRADE_CODE, mver, None, None, 2, None, "WHYFSNEWER")])
    msilib.add_data(db, "LaunchCondition", [("NOT WHYFSNEWER", "A newer version of whyfs is already installed."),
                                            ("VersionNT >= 603", "whyfs needs Windows 10 or later.")])
    cab = CAB("whyfs")
    root = Directory(db, cab, None, str(stage_dir), "TARGETDIR", "SourceDir")
    feature = Feature(db, "Complete", "whyfs", "whyfs CLI, collector service and runtime", 1, directory="INSTALLDIR")
    feature.set_current()
    pf = Directory(db, cab, root, str(stage_dir), "ProgramFiles64Folder", "PFiles")
    inst = Directory(db, cab, pf, str(stage_dir), "INSTALLDIR", "whyfs")
    comp_flags = 256  # 64-bit components (x64 and ARM64 install to the native Program Files)
    file_keys = {}

    def add_tree(d: Directory, src: Path):
        d.start_component(d.logical, feature, comp_flags)
        for p in sorted(src.iterdir()):
            if p.is_file():
                file_keys[str(p.relative_to(stage_dir))] = d.add_file(p.name)
        for p in sorted(src.iterdir()):
            if p.is_dir():
                sub = Directory(db, cab, d, str(p), p.name.replace("-", "_")[:30] or "d", p.name)
                add_tree(sub, p)
    add_tree(inst, stage_dir)
    cab.commit(db)
    svc = file_keys["whyfs-svc.exe"]
    # 3090 = exe from the File table (18) + deferred (1024) + no impersonation (2048): runs as SYSTEM
    msilib.add_data(db, "CustomAction", [("WhyfsServiceInstall", 3090, svc, "install"),
                                         ("WhyfsServiceUninstall", 3090 | 64, svc, "uninstall")])  # 64: ignore exit code
    msilib.add_data(db, "InstallExecuteSequence", [
        ("WhyfsServiceUninstall", 'REMOVE~="ALL" OR WHYFSOLDER', 1950),   # before StopServices/RemoveFiles
        ("WhyfsServiceInstall", 'NOT REMOVE~="ALL"', 6100),               # after InstallFiles (4000)
    ])
    # Major upgrade: remove the older product completely *before* installing this one.  msilib's
    # standard sequence runs RemoveExistingProducts after InstallFinalize, where removing the
    # old product (different component GUIDs, same paths, its own service-uninstall action)
    # deletes the files and service this install just put in place.
    # Downgrades: FindRelatedProducts must run before LaunchConditions (100), or WHYFSNEWER is
    # still unset when "NOT WHYFSNEWER" is evaluated and an older MSI installs beside a newer one.
    for sql in ("UPDATE InstallExecuteSequence SET Sequence=1401 WHERE Action='RemoveExistingProducts'",
                "UPDATE InstallExecuteSequence SET Sequence=25 WHERE Action='FindRelatedProducts'",
                "UPDATE InstallUISequence SET Sequence=25 WHERE Action='FindRelatedProducts'"):
        v = db.OpenView(sql)
        v.Execute(None)
        v.Close()
    msilib.add_data(db, "Environment", [("WhyfsPath", "=-*PATH", "[~];[INSTALLDIR]", inst.component)])
    db.Commit()
    return msi


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arch", default="x64", choices=("x64", "arm64"))
    ap.add_argument("--runtime", default=r"C:\Python313")
    ap.add_argument("--out", default=str(REPO / "dist"))
    ap.add_argument("--vcvars", default=r"C:\BuildTools2022\VC\Auxiliary\Build\vcvars64.bat")
    ap.add_argument("--version", help="override the package version (upgrade tests only)")
    ap.add_argument("--build-python", help="host interpreter of the runtime's exact version, to byte-compile "
                                           "when the runtime's architecture cannot run on this host")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    stage_dir = Path(tempfile.mkdtemp(prefix=f"whyfs-msi-{a.arch}-"))
    stage(a.arch, Path(a.runtime), stage_dir, a.vcvars, a.build_python)
    msi = build_msi(stage_dir, out, a.arch, a.version or package_version())
    size = sum(f.stat().st_size for f in stage_dir.rglob("*") if f.is_file())
    print(f"built {msi} ({msi.stat().st_size / 2**20:.1f} MiB; payload {size / 2**20:.1f} MiB from {stage_dir})")


if __name__ == "__main__":
    main()
