# Case matrix

## case01 — generated-inventory-summary

Target: `reports/inventory-summary.txt`

Decision: Edit data/stock.csv and regenerate; do not treat a direct output edit as durable.

Required facts: `latest_writer`="python3 tools/make_inventory.py"; `observed_input`="data/stock.csv"; `complete`=true; `generated_relationship`=true

## case02 — python-node-multistage-lineage

Target: `site/device-card.html`

Decision: Change specs/device.yaml and rerun both stages; normalized.json is generated intermediate.

Required facts: `latest_writer`="node tools/render-card.js"; `direct_input`="work/normalized.json"; `upstream_source`="specs/device.yaml"; `intermediate`="work/normalized.json"; `complete`=true

## case03 — badge-one-to-many

Target: `theme/badge.toml`

Decision: All three observed outputs may be affected; the observed set is not a global completeness proof.

Required facts: `dependent`="web/assets/badge.svg"; `dependent`="mobile/assets/badge.json"; `dependent`="docs/badge.txt"; `observed_only`=true

## case04 — runtime-config-move-lineage

Target: `config/runtime-current.ini`

Decision: Treat the current path as the moved file with continuous observed lineage, not unrelated.

Required facts: `created_by`="python3 tools/prepare-runtime.py"; `moved_from`="scratch/runtime-draft.ini"; `same_identity_lineage`=true; `dependent`="reports/runtime-use.txt"; `complete`=true

## case05 — sequential-index-overwrite

Target: `state/live-index.json`

Decision: The current version came from rebuild-index.py; changing bootstrap-index.py does not address that latest write.

Required facts: `latest_writer`="python3 tools/rebuild-index.py"; `latest_input`="records/current.json"; `earlier_writer`="python3 tools/bootstrap-index.py"; `multiple_writers`=true; `complete`=true

## case06 — pre-observation-vendor-cache

Target: `cache/vendor-snapshot.bin`

Decision: Preserve unknown original creation while reporting the later observed read/use.

Required facts: `origin_unknown`=true; `reason`="before_recording"; `dependent`="analysis/cache.sha256"; `complete`=false

## case07 — registered-review-session

Target: `artifacts/`

Decision: Attribute only review.md and findings.json to the registered session; supplied task is recorded context, not inferred intent.

Required facts: `session_file`="artifacts/review.md"; `session_file`="artifacts/findings.json"; `agent`="AuditBot"; `supplied_task`="Review dependency licenses for release"; `not_session_file`="artifacts/ambient.log"

## case08 — manual-artifact-in-dist

Target: `dist/release-note.txt`

Decision: Change the authored input and repeat the install/copy operation; directory convention is not execution evidence.

Required facts: `latest_writer`="/usr/bin/install"; `observed_input`="authored/manual-release.txt"; `packaging_script_not_observed`=true; `complete`=true

## case09 — empty-observed-dependents-safety

Target: `scratch/unused-seed.dat`

Decision: Do not call it globally safe to delete merely because no dependents were observed.

Required facts: `latest_writer`="python3 tools/materialize-seed.py"; `observed_dependents`=[]; `observed_only`=true; `not_proof_of_safety`=true

## case10 — competing-node-exporters

Target: `public/channel.json`

Decision: The blue exporter actually ran; the red exporter’s capability is not evidence of execution.

Required facts: `latest_writer`="node tools/export-blue.js"; `observed_input`="configs/channel.json"; `other_generator_executed`=false; `complete`=true
