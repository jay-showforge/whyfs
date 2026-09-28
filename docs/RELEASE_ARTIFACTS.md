# WhyFS 1.0.0 release artifacts

The release artifacts are the packages built by the `native-validation` workflow from the
1.0.0 release commit, on native runners of each architecture.  The same run installs and
tests those packages: clean install, upgrade, the product, outage, corpus and secret gates,
and performance.  The source archive is `git archive` of the same commit.

An artifact is never rebuilt after its hash is recorded.  A rebuild is a new artifact: it
needs a new run and new hashes, and the old ones are invalidated here.

## Status: NO approved release artifacts (authoritative run 36449450012, commit 80dabe3)

The authoritative release-candidate run failed one check of the frozen 1.0 contract: Windows
ARM64 MSVC +5.18 % (part A, < 5 %).  Its packages are recorded to identify them and are **NOT
approved**.  Each passed its own platform's clean-install test in that run.

| Artifact | Built on | SHA-256 |
|---|---|---|
| `whyfs-1.0.0-x64.msi` | `windows-2022` (x64), run 36449450012 | `0dee433f2e9670901f32e53449595f61ce1fa275d628348ea918449d42355be3` |
| `whyfs-1.0.0-arm64.msi` | `windows-11-arm` (ARM64), run 36449450012 | `cdcc05be1d22e75d0141f5694983da24b6f9535e043b0db1951be21569c1ac1f` |
| `whyfs_1.0.0_amd64.deb` | `ubuntu-24.04` (x86-64), run 36449450012 | `60afd76140c349073e5df44ebead6bab83db21021f1355ec183c3e929b7fc29c` |
| `whyfs_1.0.0_arm64.deb` | `ubuntu-24.04-arm` (ARM64), run 36449450012 | `0b2ab64f01561a649763ba764857784168eb7fb7ab3939e3f90efb5320862719` |
| `whyfs-1.0.0-src.tar.gz` | `git archive --format=tar.gz --prefix=whyfs-1.0.0/ 80dabe3` (reproducible) | `31ebee6bbb62e8acbc58babc339d3119a7ed5f5e7ebd06feb70ce39e238144b4` |

## Invalidated: the 37f7e7a candidates (never approved)

The final release run 36395424116 on release candidate 37f7e7a failed two performance checks:
Windows x64 process spawn ×300 (+6.48 %) and Linux x86-64 static ×300 (+5.50 %)
([PLATFORM_VALIDATION.md](PLATFORM_VALIDATION.md#final-release-run-36395424116-commit-37f7e7a-the-release-candidate-fail)).
Its packages are recorded to identify them and are **NOT approved**: they must not be
distributed as WhyFS 1.0.0.  Each one passed its own platform's clean-install test in that run.

| Artifact | Built on | SHA-256 |
|---|---|---|
| `whyfs-1.0.0-x64.msi` | `windows-2022` (x64), run 36395424116 | `7801f421a2e5822681ba50267bae9012e127d9e86372ad03d7bf6e2a41dee29f` |
| `whyfs-1.0.0-arm64.msi` | `windows-11-arm` (ARM64), run 36395424116 | `f056e677186edee0f32beaf7acddded41af219e5c4d6dd46ff3c95c24e21982e` |
| `whyfs_1.0.0_amd64.deb` | `ubuntu-24.04` (x86-64), run 36395424116 | `4e930710907dcdb9ed17ae4ef9aac3fa1210e4ddad24a3361c1094a576885d26` |
| `whyfs_1.0.0_arm64.deb` | `ubuntu-24.04-arm` (ARM64), run 36395424116 | `08a4cdce23896731c27dd01bfa9e7d934610cce26352409f708bc0b9c2c33df8` |
| `whyfs-1.0.0-src.tar.gz` | `git archive --format=tar.gz --prefix=whyfs-1.0.0/ 37f7e7a` (reproducible) | `08bc96933e0c011c4031cd8aa295ce21090eaf9e8b3ec65431e41a1bde0d37af` |

## Invalidated: the b5562df candidates (never approved)

The release run 36377152638 on b5562df failed Windows x64 process spawn ×300 (+5.16 %).  Its
packages were recorded only to identify them and are **invalid**: they must not be distributed.
Their hashes are kept below for that purpose.

| Artifact | Built on | SHA-256 |
|---|---|---|
| `whyfs-1.0.0-x64.msi` | `windows-2022` (x64), run 36377152638 | `2874b19328a9c953109694e25e8c4209eb0d5edc30de8acf43cf754ead467202` |
| `whyfs-1.0.0-arm64.msi` | `windows-11-arm` (ARM64), run 36377152638 | `108d35de75585f98dc1d8f3545469fa75170a0c9c68fbf1317bf80f58e66f3f0` |
| `whyfs_1.0.0_amd64.deb` | `ubuntu-24.04` (x86-64), run 36377152638 | `d6d38b367a753c56580dfb641b504d430db72e4586964cfde4c2ec29e7f37b78` |
| `whyfs_1.0.0_arm64.deb` | `ubuntu-24.04-arm` (ARM64), run 36377152638 | `9ae10c8fa85c09abc40d7170208940277e9a65da8f0f5406f4fc861977f4aa3e` |
| `whyfs-1.0.0-src.tar.gz` | `git archive --format=tar.gz --prefix=whyfs-1.0.0/ b5562df` (reproducible) | `0159812a4633933c948ed158118ef6e54f9a59e7f90b2e1a607e6e326e9d7529` |

The packages themselves are not committed (`*.msi`, `*.deb` are ignored).  They are the
`dist/` folders of the run's uploaded artifacts.
