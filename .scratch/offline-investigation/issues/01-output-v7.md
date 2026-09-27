# BASE-01: Prepare the complete v7 output family

Status: resolved (a2796199; validated per the commands below — all green)
Blocked by: none
Size: medium, shared contract work
Spec: [batch contract](../spec.md), plus every linked feature spec's Output section

## What to build

1. Read all four feature output definitions before editing schemas. Add
   `schemas/packetcraftr.output.v7.schema.json` with `$id`
   `urn:packetcraftr:output:v7`, copied from v6 and extended for the exact new
   split result, HTTP transaction/body-export fields and event, and expert gate.
   Keep strict envelopes/enums and existing forward-compatible result objects.
   v6 and `examples/consumers/fixtures/v6-forwarding.json` stay unchanged.
2. Change the current producer constant to `SCHEMA_V7` and value
   `packetcraftr.output/v7`; migrate envelopes, embedded test schema, and
   version assertions. Current pre-feature HTTP reports supply
   `transactions: []`, `transaction_summary: null`, `body_export: null`;
   expert reports supply `gate: null`. Add CLI-owned types for those fields
   according to the feature specs; no placeholder success values.
3. Move current `examples/documents/output-*.json` to v7 content and add
   complete hand-authored feature examples under that directory. Later
   feature tickets must validate real serializers against those definitions.
   Add a frozen `examples/consumers/fixtures/v7-forwarding.json`.
4. Keep the reference forwarding consumer able to read both v6 and v7 by
   explicit family dispatch to the unchanged forwarding semantics. Reject
   other families. In NDJSON, the first record selects the family for the
   entire stream; reject a later v6/v7 switch. Exercise both frozen fixtures,
   their mutation suites, and mixed-family streams.
5. Update release packaging/verifier requirements to include both frozen
   fixtures and the v7 schema; retain v6 schema packaging. The current binary
   and current examples identify v7. Document v6 archival compatibility and
   v7 migration without relabeling historical evidence.
6. Add the private prepared-completion and prepared-aggregate seams specified
   in the batch's “Prepare artifact reports before publication” section.
   Test no writes/state changes during preparation, envelope/newline/resource
   sizing, same-encoder/sequence enforcement, normal write/flush failure state,
   and error publication after a prepared success is discarded. Existing
   complete/aggregate APIs retain their behavior; no staging is done here.

## Exact edit inventory

- `crates/packetcraftr-cli/src/output/{contract,envelope,http,expert}.rs`,
  `src/output/stream.rs`, `src/output/stream/tests.rs`,
  `src/rendering/machine.rs`, `src/test_support.rs`.
- CLI tests: `aggregate_schema_conformance`, `ndjson_conformance`,
  `published_schema_conformance`, `published_example_matrix`,
  `machine_contracts`, `process_contracts`, `forwarding_verification_contracts`,
  `output_conversion_contracts`.
- `examples/consumers/forwarding.py`, both frozen fixture families,
  `scripts/{test-output-consumer,check-native-capture,test-native-capture,verify-archive,test-verify-archive}.py`,
  `.github/workflows/release.yml`, current output examples.
- `README.md`, `docs/consumer-compatibility.md`,
  `docs/migration-unreleased.md`, `CHANGELOG.md` Unreleased.

Use `rg 'output/v6|output\.v6|SCHEMA_V6|v6-forwarding'` to audit remaining
references. Classify each as current or historical; this is not a global
replacement. Completions and man pages are generated from command definitions.

## Acceptance and validation

- [x] v6 schema and frozen v6 fixture have no diff; both consumers pass.
- [x] v7 schema describes the entire decided batch, with no unconstrained
  placeholder records. New enums reject unknown values and wrong types.
- [x] Current real output validates as v7; current forwarding behavior and
  exit semantics are unchanged.
- [x] All current examples and new feature examples validate against v7.
- [x] Archive checks require the correct current assets and retain history.
- [x] Prepared terminal reports validate the actual decorated envelope before
  artifact publication and leave normal error publication available on abort.

Run:

```sh
cargo test --locked -p packetcraftr-cli --no-default-features --test aggregate_schema_conformance --test ndjson_conformance --test published_schema_conformance --test published_example_matrix --test machine_contracts --test process_contracts --test forwarding_verification_contracts --test output_conversion_contracts
python3 scripts/test-output-consumer.py
python3 scripts/test-forwarding-regression.py
python3 scripts/test-native-capture.py
python3 scripts/test-verify-archive.py
cargo test --locked -p packetcraftr-cli --no-default-features --lib output::stream
cargo test --locked -p packetcraftr-cli --no-default-features --lib rendering::machine
```

Request applicable serialized-contract CODEOWNERS review when implementation
is proposed: `@tyk-swe @rkdxodud-tyk`. This document does not send that request.

## Comments

The schema is designed up front so individual feature implementations cannot
invent incompatible field shapes. BASE-02 is the release completion gate.
