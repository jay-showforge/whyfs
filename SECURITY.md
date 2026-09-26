# Security and privacy

whyfs observes process/file metadata. That is useful precisely because it can also be sensitive.

## Defaults

- provenance remains local in `.whyfs/whyfs.db`
- no file contents are captured
- workspace-only path evidence by default
- `--all-files` is explicit opt-in
- common secret-looking command-line values are redacted before storage

## eBPF alpha privileges

The v0.2 BCC backend requires Linux BPF/performance tracing privileges. During alpha testing this commonly means running the daemon under `sudo`. Treat that as a meaningful security boundary: inspect the source before running it privileged, keep the daemon workspace-scoped, and do not expose its database to untrusted users.

The pre-hook/capture path never executes recovery or arbitrary workload commands. It observes kernel events and persists metadata only.

## Command-line secrets

Redaction is defense-in-depth, not a guarantee. Arbitrary applications can place secrets in unusual argument formats or paths. Prefer environment variables, file descriptors, or platform secret stores for secrets rather than command-line arguments.

## Raw evidence

Human-view noise suppression never deletes raw evidence. This improves auditability but means the database can reveal filenames/process relationships even when the default CLI hides them.

## Symlinks and path scope

The eBPF user-space resolver uses real paths where possible. A path that resolves outside the configured workspace is excluded unless `--all-files` is enabled. Race-free path confinement across every Linux filesystem edge case remains part of the alpha security review.
