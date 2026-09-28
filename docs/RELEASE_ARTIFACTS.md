# WhyFS 1.0.0 release artifacts

The release artifacts are the packages built by the `native-validation` workflow from the
1.0.0 release commit, on native runners of each architecture.  The same run installs and
tests those packages: clean install, upgrade, the product, outage, corpus and secret gates,
and performance.  The source archive is `git archive` of the same commit.

An artifact is never rebuilt after its hash is recorded.  A rebuild is a new artifact: it
needs a new run and new hashes, and the old ones are invalidated here.

## Status: candidates, NOT approved

The release run 36377152638 on commit b5562df failed one gate: Windows x64 process spawn
×300, +5.16 % against the < 5 % criterion
([PLATFORM_VALIDATION.md](PLATFORM_VALIDATION.md#release-run-36377152638-commit-b5562df-the-100-release-commit-fail-on-one-check)).
These artifacts are therefore **release candidates, not release artifacts**.  They are recorded
so they can be identified; they must not be distributed as WhyFS 1.0.0.  Each one passed its own
platform's clean-install test in that run.

| Artifact | Built on | SHA-256 |
|---|---|---|
| `whyfs-1.0.0-x64.msi` | `windows-2022` (x64), run 36377152638 | `2874b19328a9c953109694e25e8c4209eb0d5edc30de8acf43cf754ead467202` |
| `whyfs-1.0.0-arm64.msi` | `windows-11-arm` (ARM64), run 36377152638 | `108d35de75585f98dc1d8f3545469fa75170a0c9c68fbf1317bf80f58e66f3f0` |
| `whyfs_1.0.0_amd64.deb` | `ubuntu-24.04` (x86-64), run 36377152638 | `d6d38b367a753c56580dfb641b504d430db72e4586964cfde4c2ec29e7f37b78` |
| `whyfs_1.0.0_arm64.deb` | `ubuntu-24.04-arm` (ARM64), run 36377152638 | `9ae10c8fa85c09abc40d7170208940277e9a65da8f0f5406f4fc861977f4aa3e` |
| `whyfs-1.0.0-src.tar.gz` | `git archive --format=tar.gz --prefix=whyfs-1.0.0/ b5562df` (reproducible) | `0159812a4633933c948ed158118ef6e54f9a59e7f90b2e1a607e6e326e9d7529` |

The packages themselves are not committed (`*.msi`, `*.deb` are ignored).  They are the
`dist/` folders of the run's uploaded artifacts.
