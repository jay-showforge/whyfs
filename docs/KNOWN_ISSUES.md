# Known issues

## KI-1: the daemon records its own `daemon.json` replace (provenance noise)

- **Observed:** 2026-09-26, `results/v02-daemon-gap/`, every G/K session in `dbcounts.json`.
- **What:** each `whyfs daemon start` writes `.whyfs/daemon.json` atomically: write `daemon.json.tmp`, then rename it over `daemon.json`. That happens after the collector is attached, and `.whyfs/` is inside the watched workspace, so exactly **one `rename` event per daemon start** is stored as provenance.
- **Impact:** noise only. The event describes whyfs's own state file, not user activity. The cost is negligible (one event per daemon lifetime), and no lineage query result for user files changes.
- **Status:** open, recorded separately on purpose. It is not bundled with any performance change.
- **Possible fixes, not decided:**
  - write the state file before attaching the BPF programs;
  - have the collector drop events whose path lies under the workspace's own `.whyfs/` directory.

  Either needs its own regression test. The second must not hide user files that happen to be named `.whyfs`, since the state directory is identified by path and ownership.
