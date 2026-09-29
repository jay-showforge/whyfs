Final WhyFS 1.0.0 artifact check.

Run:            https://github.com/jay-showforge/whyfs/actions/runs/36510467027
Commit:         f6c6010cd09858584766f3e454f2c5c87b57f2ee (LICENSE Change Date 2030-09-28; product code = 57d60e4)
Workflow:       .github/workflows/release-validation.yml (workflow_dispatch, unchanged)
Runners:        windows-2022 (x64), windows-11-arm (ARM64), ubuntu-24.04 (x86-64), ubuntu-24.04-arm (aarch64)
Result:         all four jobs success
Normal CI:      test.yml run https://github.com/jay-showforge/whyfs/actions/runs/36510466786 success

<platform>/ci-results/   the run's own evidence (downloaded artifact)
<platform>/dist/         the exact packages (downloaded; not committed, hashes in docs/RELEASE_ARTIFACTS.md)
embedded-license/        LICENSE extracted from a copy of each package, plus embedded_license_check.json.
                         MSI: msiexec /a (administrative extraction, installs nothing); .deb: dpkg-deb.
                         Each original package was hashed before and after inspection: unchanged.

Negative control (run before the final check): the same script on the superseded 57d60e4
packages reported the old placeholder in all four (FAIL), as expected.

Incident, recorded for provenance: an earlier attempt to extract the MSI cabinet with the
Windows SDK's MsiDb.exe wrote to the LOCAL downloaded copy of the superseded 57d60e4 ARM64 MSI
(results/release-validation-d2d7984/windows-arm64/dist, not committed).  That local copy was
restored by re-downloading it from run 36500071218; its SHA-256 is again
5d5182cc1718eea411a58c50fdfba751594f57c0993d52bec4b8b284425f7882, as recorded.  The final
artifacts were only ever inspected through copies.
