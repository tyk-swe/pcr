# Architecture task pool

Candidates need a real caller and contract audit before implementation. Keep each migration and its old implementation's removal together.

| Area | Evidence or question | Status |
| --- | --- | --- |
| CLI reference rendering | Documentation generation calls the application parser factory. Help text and exit code references also read the app directly. Dispatch already has the root definition and can supply the document generator through its execution interface. | Next |
| Published command metadata | The command registry owns IDs, parser paths, output formats, and dispatch. Its output-facing API creates an upward dependency. Compare a metadata-only declaration with the current registry macro and preserve one declaration per command. | Investigate after reference rendering |
| Layer graph | The direction check permits same-layer dependencies and does not expose a reference graph. Reuse its source extraction to surface cycles at documented boundaries and distinguish deliberate groups from new edges. | Investigate |
| CLI input and output | Compare the bounded reader entry points and text, JSON, NDJSON, and staged-file paths. Separate genuine repetitions from format-specific byte budgets, deadlines, and persistence guarantees. | Investigate |
| Offline analysis | Check how collectors apply a session, time and scope selection, provenance, and resource accounting. Review any collector-specific reimplementation before adopting a shared primitive. | Investigate |
| Capture files | Trace selection, normalization, merge, and rewrite through record and metadata ownership. Keep original timestamp precision and section/interface scope where promised. | Investigate |
| Native and workflow I/O | Inventory providers, timeout and retry loops, worker leases, cancellation boundaries, and the exact safeguards that own each path. Keep admission and spending with policy and operation owners. | Investigate |
| Configuration and logging | Trace CLI presets and option defaults through diagnostic snapshots, errors, and terminal rendering. Determine where defaults or severity classifications are declared twice. | Investigate |
| Testing and build | Compare workspace features, CI matrix inputs, platform prerequisites, output validators, and release assembly. Check any duplicate inventory for consumer or contract reasons before reducing it. | Investigate |
| Kernel decomposition | The documented core model is mutually referential. Any change to public traits, registry paths, or packet representations needs a compatibility and migration proposal. | Pending confirmation if a breaking change is needed |
| Native contract split | Backend selection currently uses explicit provider-to-platform exceptions. A backend ownership split that affects custom providers or platform support needs a migration proposal. | Pending confirmation if a breaking change is needed |
