# Prior art and positioning

whyfs is packaging work around a long-established systems idea, not a claim to have invented provenance.

## Research lineage

- PASS (Provenance-Aware Storage Systems, USENIX ATC 2006): automatic process/file provenance at the storage-system layer.
- CamFlow / Linux Provenance Modules: practical whole-system provenance on Linux.
- W3C PROV: interoperable model for entities, activities, and provenance relations.

## Current adjacent projects (2026)

### AgentFS
AgentFS is a filesystem/runtime explicitly designed for AI agents, storing agent files, state, tool-call history, and snapshots in SQLite. Its boundary is the agent filesystem itself.

whyfs is interested in ordinary host programs and files whether or not an agent framework is involved.

### trace-file-lineage
Trace File Lineage offers strong local file-origin tooling, especially for Python/notebook workflows. It can reconstruct candidates for old files and can record explicit command runs as verified provenance.

whyfs deliberately avoids language parsing in the core path. The target is dynamic OS-level evidence from arbitrary process trees, eventually with an always-on Linux collector.

## The wedge

The project succeeds only if a user can install/enable it and immediately get a better answer to:

> Why is this file here?

The research field can be mature while that product surface is still underserved. If a current project reaches the same host-level, always-on, low-overhead query experience first, whyfs should integrate, differentiate on a real measured gap, or stop.
