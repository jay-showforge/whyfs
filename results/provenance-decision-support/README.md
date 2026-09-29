# Provenance decision-support benchmark evidence

This directory publishes the completed evidence for the WhyFS provenance decision-support
benchmark.  The experiment is about recovering observed provenance facts and supporting file
decisions; it is not a general coding-agent efficiency benchmark.

Start with:

- [FINAL_REPORT.md](FINAL_REPORT.md) — result, case-level analysis, claim boundary, and verdict;
- [METHODOLOGY.md](METHODOLOGY.md) — frozen design and scoring approach;
- [CASES.md](CASES.md) and [ORACLE.json](ORACLE.json) — prompts and independently constructed
  ground truth;
- [RESULTS.csv](RESULTS.csv), [FACT_SCORING.json](FACT_SCORING.json),
  [INVESTIGATION_BURDEN.json](INVESTIGATION_BURDEN.json), and
  [PAIRED_SUMMARY.json](PAIRED_SUMMARY.json) — scored results;
- [PRIMARY_RUN_MANIFEST.json](PRIMARY_RUN_MANIFEST.json), [transcripts/](transcripts/), and
  [raw/usage/](raw/usage/) — the 20 valid primary runs and actual Codex usage records;
- [DIRECT_RETRIEVAL_DIAGNOSTIC.json](DIRECT_RETRIEVAL_DIAGNOSTIC.json) — non-agent interface
  characterization;
- [EVIDENCE_MANIFEST.sha256](EVIDENCE_MANIFEST.sha256) — SHA-256 hashes for copied source
  artifacts;
- [PUBLICATION_VERIFICATION.json](PUBLICATION_VERIFICATION.json) — copy verification,
  credential-scan coverage, and publication exclusions.

## Evidence provenance

The completed bundle's 93 files were copied byte-for-byte from the frozen local result, and every
copy was checked against its source SHA-256.  The report-referenced first invalid treatment attempt
is also published intact under
[invalidated/legacy-cli-accessible-attempt/](invalidated/legacy-cli-accessible-attempt/).  Its 77
files were independently hash-checked.  The invalidation metadata explains why those runs were
excluded; no valid unfavorable outcome was removed.

All completed raw transcripts are included.  A credential-shaped scan covering OpenAI and GitHub
tokens, AWS access keys, bearer credentials, private-key headers, and long credential assignments
found no matches.  The recorded benchmark scan is in [CREDENTIAL_SCAN.json](CREDENTIAL_SCAN.json).
No evidence artifact was omitted for privacy or credential reasons.

The `Remote state` section in the frozen final report records the state when the benchmark ended.
This later documentation publication does not alter the measurements or regenerate any value.

## Product boundary

The benchmark used experimental candidate
`c0be4efcdc7811e5fc0dd4c72ba80a514cc3dc42` and package SHA-256
`465ac0988641114f54d8481fb7e2a6320194a9e752b310bdd3e54593953b15ac`.  This evidence publication
does not merge that candidate or its native typed-tool implementation into `main`; those tools are
not a released or supported WhyFS 1.0.0 feature.

The previous general coding-agent conclusion remains unchanged:

**AGENT-EFFICIENCY LINE CLOSED — CURRENT EVIDENCE DOES NOT SUPPORT THE GENERAL SAVINGS CLAIM**
