# Invalidated treatment condition

- Collection: all 20 sessions completed; all ten BASELINE sessions are valid and retained for the replacement comparison.
- Defect: the treatment namespace exposed the legacy `/usr/bin/whyfs` CLI in addition to the frozen typed MCP inventory.
- Observed impact: eight treatment runs used only legacy CLI; case 05 mixed legacy CLI and typed calls; case 08 used typed calls only. The treatment therefore was not the specified typed-interface-only condition.
- Invalidated runs: all ten treatment sessions. Their transcripts, usage, direct diagnostic, run order, and integrity evidence remain preserved here.
- Replacement rule: each invalid treatment run may be replaced once with a new fixture and fresh session. Valid baseline sessions will not be rerun.
- Corrective action: deny `/usr/bin/whyfs` in treatment namespaces while leaving the unmodified `/usr/bin/whyfs-mcp` transport available to Codex.

No WhyFS product, task prompt, fixture definition, independent oracle, fact criterion, or scoring rule was changed after seeing the results.
