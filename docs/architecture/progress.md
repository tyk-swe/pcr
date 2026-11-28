# Architecture progress

The baseline is `d09e9091c`. The isolated worktree started from the current default branch. Runtime, library, file, and output schema compatibility are required for each batch.

| Batch | Scope | Evidence |
| --- | --- | --- |
| Inventory | Map package dependencies, module boundaries, state and contract ownership, and the current architecture and verification gates. | Cargo metadata confirms the local crate graph. The production layer and coupling checks pass at the baseline. The layer scan found mutual references in the core model, native provider dispatch, and the CLI. |
| CLI reference | Remove the command-to-application dependency. Move shared help to the output and exit-code owners, and provide the command factory through dispatch. | Offline root help, both reference topics, and 57 generated files matched the baseline byte for byte. The documentation tests, focused offline CLI test, CLI Clippy, and layer and coupling checks passed. |
| Published commands | Generate output metadata and the grouped parser from one catalog. Remove per-command format declarations and the last CLI layer exception. | The public API probe matched all 43 published IDs, serialized names, ordered supported formats, and unsupported-format messages. The offline CLI matched the baseline reference files and JSON packet build. Registry tests, CLI Clippy, and schema checks passed. |
| Module cycles | Extend the existing layer check to reject undocumented cycle groups and stale approvals, then expose the same graph as DOT. | The graph contains 94 documented boundaries and 446 distinct cross-boundary references. The two existing cycle groups match their crate-root entries. Tests cover cycle introduction, expansion, removal, and production graph output. |
| CLI input sources | Share platform file opening and centralize stdin recognition. Preserve the regular-file checks for scope files and key logs. | `packetcraftr files read --dissect -- -/. < capture.pcap` produced the same decoded DNS record as the baseline. The 26 focused input tests, the piped capture regression, and CLI Clippy passed. |
