# Windows ARM64 build artifacts (not runtime-validated)

Built on the x64 development host.  They could not be executed there: an x64 PC cannot run
ARM64 Windows code.  They are ready to install on a native Windows 11 ARM64 machine (see
docs/PLATFORM_VALIDATION.md).

| Artifact | SHA-256 |
|---|---|
| `whyfs-0.9.0.dev1-arm64.msi` | `5e24f215b24f2af61c087cba4de66ced5a602127b8148742039974dae965ee04` |
| `whyfs-collect-win.exe` (arm64) | `66fa467d30e3896e211a6ca262644d8166351fa60bf2142be21bed5db94fff9f` |
| `whyfs-svc.exe` (arm64) | `d556e4f1d027d0e26977803a2656c4a7213829863667e54ad9b706c0c56858b7` |
| bundled runtime: `pythonarm64` 3.13.5 NuGet package | `671600f1b07a7bd8a5a3889768893ebac5d5e3fa1138a847124ab8ce48cef3a6` |

Build: `native\windows\build.ps1 -Arch arm64` (MSVC 14.44 `x64_arm64`, `/guard:cf`, 0
warnings), then:

```
make_msi.py --arch arm64 --runtime <pythonarm64 3.13.5>\tools --build-python C:\Python313\python.exe
```

Runtime provenance: `pythonarm64` 3.13.5 from nuget.org, downloaded with the user's approval
on 2026-09-26.
- `python.exe` carries a valid Authenticode signature from the Python Software Foundation.
- The nuspec authors field is "Python Software Foundation".
- The package is repository-signed by NuGet.org.

Byte-compilation used the host's CPython 3.13.5 (x64).  Bytecode is
architecture-independent; the builder checks the exact version against the runtime DLL's
ProductVersion.

Checks performed on the MSI (administrative extraction, `msiexec /a`):
- **All 26 PE images are ARM64 (machine 0xAA64).**  The ARM64 CPython package also ships an
  x64 `vcruntime140_1.dll`.  No ARM64 image imports it (checked with `dumpbin
  /dependents`), so the builder refuses foreign-architecture runtime DLLs and skips that one.
- Layout identical to the x64 MSI: `whyfs.exe`, `whyfs-svc.exe`, `whyfs-collect-win.exe`,
  `runtime\` (isolated `._pth`), `lib\whyfs\`, LICENSE and notices.
- Summary-information platform `Arm64;1033`, 64-bit components; same UpgradeCode as x64.

Not yet done, because it needs ARM64 hardware:
- install, service lifecycle, ETW collection;
- A–H corpus, why/impact/history;
- the functional gate, secret gate, event loss, uninstall/upgrade and performance.
