# Architecture task pool

Audit callers and contracts before implementation. Keep each migration and its old implementation's removal together. The pull request tracks review and CI status.

| Area | Evidence or question | Status |
| --- | --- | --- |
| CLI reference rendering | [Dispatch provides a fresh Clap definition](decisions/0002-inject-reference-command-factory.md). Output and error contracts own the shared help text. The former layer exception is gone. | Implemented |
| Published command metadata | [Parser and output consume one command catalog](decisions/0003-share-command-declarations.md). The final CLI layer exception is gone. | Implemented |
| Layer graph | [The layer checker rejects undocumented cycles](decisions/0004-enforce-module-cycle-boundaries.md) and exports the dependency graph from the same scan. | Implemented |
| Upward dependency approvals | [Crate roots own dependency approvals](decisions/0012-document-upward-dependency-approvals.md). The checker enforces those approvals and rejects unused entries. | Implemented |
| CLI input sources | [Input owns platform opening and both stdin rules](decisions/0005-centralize-cli-input-sources.md). Bounded readers share the capped read primitive and apply the relevant input contract. | Implemented |
| CLI output channels | [The terminal scopes capture text batching](decisions/0006-scope-text-output-batches.md). JSON, NDJSON, and staged files retain their separate publication contracts. | Implemented |
| Offline analysis settings | [Core translates caller settings into pipeline options](decisions/0008-convert-analysis-settings-in-core.md). Collector sessions and direct callers retain their stage plans. | Implemented |
| Offline analysis collectors | Core session, scope, and provenance own shared behavior. Direct physical inventory accepts untimed records and has different stage requirements from reconstructing collectors. | Audited |
| Capture normalization | [Report totals come from the reader budget and capture writer](decisions/0007-report-writer-owned-normalization-totals.md). Both formats share report finalization. | Implemented |
| Capture rewrite | [Mapping reports the writer's per-operation byte delta](decisions/0011-report-rewrite-byte-deltas.md). Existing output is excluded from the rewrite report. | Implemented |
| Signed frame timestamps | [Core decomposes signed Unix time once](decisions/0014-share-signed-frame-time.md). The CLI owns narrowing to its published `i64` range and its text representation. | Implemented |
| Hexadecimal byte codec | [Core owns strict pair decoding and compact printing](decisions/0015-share-hex-byte-pairs.md). Input grammars and limits stay with their owning contracts. | Implemented |
| CI source ownership | [Checkers name owners by repository-relative paths](decisions/0016-name-source-owners-in-repository-paths.md). Coupling and output-schema rules consume one production source snapshot. | Implemented |
| Offline analysis defaults | [Core defaults drive matching CLI analysis settings](decisions/0017-use-core-analysis-defaults.md). The CLI retains publication and presentation limits. | Implemented |
| Projection budget default | [The CLI field projector owns the encoded row budget default and help](decisions/0017-use-core-analysis-defaults.md). Commands keep their field conflicts and resource reporting. | Implemented |
| CLI link-type spellings | [One CLI vocabulary drives link-type help, aliases, and parsing](decisions/0018-own-link-type-spellings-in-cli.md). Core keeps numeric values and registry bindings. | Implemented |
| Output type ownership | [Registry paths name explicit type definitions](decisions/0019-register-output-types-at-their-definition.md). Re-exports remain implementation details. | Implemented |
| Capture merge | The shared read budget already owns aggregate counts. Merge owns per-source positions, timestamp order, and interface provenance and rollover. Metadata-preserving rewrite, selection, and merge have distinct output contracts. | Audited |
| Native and workflow I/O | Core owns deadline state. Netio owns bounded native waits and lease retention. Workflow runtime uses the application thread cleanup API. The two capacity budgets serve separate lifecycles. | Audited |
| Separate cache lifetimes | Route lookups memoize successful provider calls for one exchange. Neighbor answers have client time and capacity bounds with optional operation pinning. The interface cache retains one selector and ID. | Audited |
| CLI settings | [Help and diagnostics read canonical values](decisions/0009-derive-cli-settings-labels.md). Preset names come from Clap, and timeout help uses the runtime default and parser bound. | Implemented |
| Logging and observability | Typed diagnostics feed the terminal and versioned envelope. Resource snapshots and workflow evidence have separate schemas and delivery guarantees. | Audited |
| CI cache configuration | [The CI workflow defines shared workspace cache steps](decisions/0010-share-ci-workspace-cache-steps.md). All jobs expand to their previous definitions. | Implemented |
| Testing and build | Workspace, release, and fuzz caches have distinct artifacts. CI owns coverage and mutation gates. [Staged-input mutation exclusions target their platform adapters and retry condition](decisions/0013-preserve-staged-input-mutation-coverage.md). Existing Python validators share repository parsing and file helpers. | Audited |
| Permissions and authentication | Workflow policy owns live admission and scope narrowing. Netio TLS verification owns peer identity and trust. Native capability errors report platform availability. | Audited |
| Capture projection diagnostics | Capture declares the projection budget active without checking `--field`. Read and dissect declare it active only when columns are selected. Decide whether the published `enabled` field should change for capture before aligning the declarations. | Pending confirmation |
| Kernel decomposition | The documented core model is mutually referential. Any change to public traits, registry paths, or packet representations needs a compatibility and migration proposal. | Pending confirmation if a breaking change is needed |
| Native contract split | Backend selection currently uses explicit provider-to-platform exceptions. A backend ownership split that affects custom providers or platform support needs a migration proposal. | Pending confirmation if a breaking change is needed |
