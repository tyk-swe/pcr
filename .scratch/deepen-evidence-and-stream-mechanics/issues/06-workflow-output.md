# Deepen CLI workflow output conversion and driver

Status: open
Blocked by: none
Spec: ../spec.md §§ Implementation Decisions 5; Testing Decisions

Move each workflow family's event/summary/report conversion into `output`; reduce live-command driver adapters to entry points plus renderer over one converted result; remove per-command event/completion emitters. Move fuzz-live and connect preparation/runtime/executor/session to provider composition. Preserve v6 wire types/formats/exit codes; assert schema-conformant NDJSON/aggregate conversions and existing recording-hook/process contracts. Coordinate potential CLI command-file overlap with ticket 03.
