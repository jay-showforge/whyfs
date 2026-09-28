# WhyFS 1.0.0 release artifacts

The release artifacts are the packages built by the `native-validation` workflow from the
1.0.0 release commit, on native runners of each architecture.  The same run installs and
tests those packages: clean install, upgrade, the product, outage, corpus and secret gates,
and performance.  The source archive is `git archive` of the same commit.

An artifact is never rebuilt after its hash is recorded.  A rebuild is a new artifact: it
needs a new run and new hashes, and the old ones are invalidated here.

The hashes, the run and the per-artifact test results are recorded in the evidence commit that
follows the release commit (the table below and `results/release-1.0.0/`).

| Artifact | Built on | SHA-256 |
|---|---|---|
| `whyfs-1.0.0-x64.msi` | `windows-2022` (x64) | recorded after the release build |
| `whyfs-1.0.0-arm64.msi` | `windows-11-arm` (ARM64) | recorded after the release build |
| `whyfs_1.0.0_amd64.deb` | `ubuntu-24.04` (x86-64) | recorded after the release build |
| `whyfs_1.0.0_arm64.deb` | `ubuntu-24.04-arm` (ARM64) | recorded after the release build |
| `whyfs-1.0.0-src.tar.gz` | `git archive --prefix=whyfs-1.0.0/` of the release commit | recorded after the release build |
