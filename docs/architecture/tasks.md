# Architecture task pool

Candidates need a real caller and contract audit before implementation. Keep each migration and its old implementation's removal together.

| Area | Evidence or question | Status |
| --- | --- | --- |
| CLI reference rendering | [Dispatch provides a fresh Clap definition](decisions/0002-inject-reference-command-factory.md). Output and error contracts own the shared help text. The former layer exception is gone. | Implemented, review pending |
| Published command metadata | [Parser and output consume one command catalog](decisions/0003-share-command-declarations.md). The final CLI layer exception is gone. | Implemented, review pending |
| Layer graph | [The layer checker rejects undocumented cycles](decisions/0004-enforce-module-cycle-boundaries.md) and exports the dependency graph from the same scan. | Implemented, review pending |
| CLI input sources | [Input owns platform opening and both stdin rules](decisions/0005-centralize-cli-input-sources.md). Bounded readers share the capped read primitive and apply the relevant input contract. | Implemented, review pending |
| CLI output channels | [The terminal scopes capture text batching](decisions/0006-scope-text-output-batches.md). JSON, NDJSON, and staged files retain their separate publication contracts. | Implemented, review pending |
| Offline analysis settings | [Core translates caller settings into pipeline options](decisions/0008-convert-analysis-settings-in-core.md). Collector sessions and direct callers retain their stage plans. | Implemented, review pending |
| Offline analysis collectors | Trace scope selection, provenance, and resource accounting for collector-specific reimplementations. | Investigate |
| Capture normalization | [Report totals come from the reader budget and capture writer](decisions/0007-report-writer-owned-normalization-totals.md). Both formats share report finalization. | Implemented, review pending |
| Capture rewrite and merge | Trace metadata-preserving rewrite and mapping, source provenance, ordering, and interface rollover. Public mapping accepts an existing writer, so check how to report per-operation totals. | Investigate |
| Native and workflow I/O | Inventory providers, timeout and retry loops, worker leases, cancellation boundaries, and the exact safeguards that own each path. Keep admission and spending with policy and operation owners. | Investigate |
| CLI settings | [Help and diagnostics read canonical values](decisions/0009-derive-cli-settings-labels.md). Preset names come from Clap, and timeout help uses the runtime default and parser bound. | Implemented, review pending |
| Logging and observability | Compare terminal errors, diagnostic snapshots, and workflow evidence. Preserve the data and delivery guarantees of each channel. | Investigate |
| CI cache configuration | [The CI workflow defines shared workspace cache steps](decisions/0010-share-ci-workspace-cache-steps.md). All jobs expand to their previous definitions. | Implemented, review pending |
| Testing and build | Compare workspace features, CI matrix inputs, platform prerequisites, output validators, and release assembly. | Investigate |
| Kernel decomposition | The documented core model is mutually referential. Any change to public traits, registry paths, or packet representations needs a compatibility and migration proposal. | Pending confirmation if a breaking change is needed |
| Native contract split | Backend selection currently uses explicit provider-to-platform exceptions. A backend ownership split that affects custom providers or platform support needs a migration proposal. | Pending confirmation if a breaking change is needed |
