# GATE-02: Publish expert gate verdicts and CI exit codes

Status: resolved (499427ea; all listed tests green)
Blocked by: GATE-01
Size: small–medium
Spec: [all CLI behavior, output, EG01–EG16](../spec.md)

## What to build

1. Add the three options and dependency/range validation in
   `commands/expert/arguments.rs`. Default report-only use stays unchanged.
2. In `commands/expert.rs`, feed every session finding to the gate before
   applying the existing report selector. Evaluate after finishing events and
   successful session completion. Preserve selected renderer state/counters.
3. Convert the report via CLI-owned DTOs, add the exact text terminal line,
   and publish the normal aggregate/complete record. Return status 1 only
   after successfully publishing fail/inconclusive; propagate output errors.
4. Add CLI `expert_gate_contracts.rs`, v7 conformance cases, examples for all
   verdicts, help/man/completion assertions, and README/task/exit-table updates.
   Explain hidden findings, retention omissions, minimum coverage, and the
   limited meaning of a pass.

## Acceptance and validation

- [x] EG01–EG16 are covered, including filtered-out EOF-only TCP findings,
  separate incomplete-IP evidence, and a hidden warning that still fails.
- [x] All output modes agree on verdict/counts/exit status, and fail or
  inconclusive produces a complete record without an error record.
- [x] Execution and broken-output failures retain their original classification.
- [x] Existing `--code` and min-severity semantics and selected counters stay
  unchanged; no implicit code catalog or new per-code gating is introduced.
- [x] Gate criteria are not mislabeled as resource ceilings or presets.

```sh
cargo test --locked -p packetcraftr-cli --no-default-features --test expert_gate_contracts --test offline_workflow_contracts --test aggregate_schema_conformance --test ndjson_conformance --test process_contracts --test generated_documentation_contracts
```

## Comments

The current `CommandExit::status(1)`/forwarding-verification pattern is the
implementation precedent; a completed negative gate is not a CliError.
