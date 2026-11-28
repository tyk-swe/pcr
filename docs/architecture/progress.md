# Architecture progress

The baseline is `d09e9091c`. The isolated worktree started from the current default branch. Runtime, library, file, and output schema compatibility are required for each batch.

| Batch | Scope | Evidence |
| --- | --- | --- |
| Inventory | Map package dependencies, module boundaries, state and contract ownership, and the current architecture and verification gates. | Cargo metadata confirms the local crate graph. The production layer and coupling checks pass at the baseline. The layer scan found mutual references in the core model, native provider dispatch, and the CLI. |
| CLI reference | Remove the command-to-application dependency. Move shared help to the output and exit-code owners, and provide the command factory through dispatch. | Offline root help, both reference topics, and 57 generated files matched the baseline byte for byte. The documentation tests, focused offline CLI test, CLI Clippy, and layer and coupling checks passed. |
| Published commands | Generate output metadata and the grouped parser from one catalog. Remove per-command format declarations and the last CLI layer exception. | The public API probe matched all 43 published IDs, serialized names, ordered supported formats, and unsupported-format messages. The offline CLI matched the baseline reference files and JSON packet build. Registry tests, CLI Clippy, and schema checks passed. |
