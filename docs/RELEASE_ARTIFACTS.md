# WhyFS 1.0.0 release artifacts

The release artifacts are the packages built by the `native-validation` workflow from the
1.0.0 release commit, on native runners of each architecture.  The same run installs and
tests those packages: clean install, upgrade, the product, outage, corpus and secret gates,
and performance.  The source archive is `git archive` of the same commit.

An artifact is never rebuilt after its hash is recorded.  A rebuild is a new artifact: it
needs a new run and new hashes, and the old ones are invalidated here.

## Superseded, never published: the 57d60e4 candidates ([run 36500071218](https://github.com/jay-showforge/whyfs/actions/runs/36500071218))

Their product validation stands.  They are superseded only because the LICENSE they embed
(`/usr/share/doc/whyfs/copyright`, and `LICENSE` in the MSI) predates the Change Date.  The
final artifacts are rebuilt from the license-final commit.


- **How they were built and tested:** on the four native hosted runners, from commit 57d60e4.
  Each passed its own platform's exact-artifact tests in that run: MSI clean install 32/32 and
  upgrade 16/16, or `.deb` 24/24.
- **Not published and not code-signed.**
- **Superseded** by the license-final artifacts.
- **An artifact is never rebuilt after its hash is recorded.**

| Artifact | Built on | SHA-256 |
|---|---|---|
| `whyfs-1.0.0-x64.msi` | `windows-2022` (x64) | `beecc859da3d4bc13e2d15e8a9b76b5e8c0e5bf1868b2fd0f1efe88f5caee53e` |
| `whyfs-1.0.0-arm64.msi` | `windows-11-arm` (ARM64) | `5d5182cc1718eea411a58c50fdfba751594f57c0993d52bec4b8b284425f7882` |
| `whyfs_1.0.0_amd64.deb` | `ubuntu-24.04` (x86-64) | `8017cd9d863764dd27b8b6c165823b328039319938c781449e5c2d527374d5e0` |
| `whyfs_1.0.0_arm64.deb` | `ubuntu-24.04-arm` (ARM64) | `3f14bd61d6b46f5dac105c74f75f54c866f2baef2db6a8c4bb33ef7b08eadcc2` |
| `whyfs-1.0.0-src.tar.gz` | `git archive --format=tar.gz --prefix=whyfs-1.0.0/ 57d60e4` (reproducible) | `b9c0bd642f3e3e2127eab9fe9f51f7fa9b5c21d58ad746620e41a9ef0126ddd5` |

## Invalidated: the 71bee51 candidates (never approved)

The authoritative run under the measurability rule failed one precommitted check: Windows ARM64
`label` CLI median 108.8 ms (< 100 ms).  Its packages are recorded to identify them and are
**NOT approved**.  Each passed its own platform's clean-install test in that run.

| Artifact | Built on | SHA-256 |
|---|---|---|
| `whyfs-1.0.0-x64.msi` | `windows-2022` (x64), run 36462972085 | `6f7a3f7a10bc0c529a6ae622a23f089b8ee0baabb2845765031b7ce54a2b47b2` |
| `whyfs-1.0.0-arm64.msi` | `windows-11-arm` (ARM64), run 36462972085 | `5aa7f47daddfe72013cad1ea1fe15c6905a535357b45d89a0bdde056d88b86a2` |
| `whyfs_1.0.0_amd64.deb` | `ubuntu-24.04` (x86-64), run 36462972085 | `e64292b62ff9960d73c6b8ce329df3d35e1c18c669962037a1ee6ead9a01cf6c` |
| `whyfs_1.0.0_arm64.deb` | `ubuntu-24.04-arm` (ARM64), run 36462972085 | `386d9a404738bf54e08de71d47f36e08ad1c0115321073ad3ef293a2d7d311cf` |
| `whyfs-1.0.0-src.tar.gz` | `git archive --format=tar.gz --prefix=whyfs-1.0.0/ 71bee51` (reproducible) | `2aa1296584dfd709364fe3a02c9c743a0b6e56c982fd17dd017bbe1ac34ed8ce` |

## Invalidated: the 80dabe3 candidates (never approved)

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
