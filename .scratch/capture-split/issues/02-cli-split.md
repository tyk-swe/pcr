# SPLIT-02: Add the split command and bounded artifact publication

Status: ready-for-agent
Blocked by: SPLIT-01
Size: medium
Spec: [user behavior, resources, publication, output, SP01–SP17](../spec.md)

## What to build

1. Add `commands/split.rs`, `split/{arguments,rendering}.rs`, an optional
   private staging helper, and CLI-owned `output/split.rs`. Register one
   `commands!` variant and implement Spec with portable/offline/cancellation/
   duration/resource declarations.
2. Open/snapshot input under existing bounds, call core planning, validate all
   fixed destination names, then generate one staged compressed part at a time.
   Add a saved-capture compression help type rather than claiming all output
   is PCAPNG. Enforce shared encoded-byte accounting below the compressor,
   with the typed refusal latch preserving policy classification through codec
   errors. Validate the duration and other semantic ranges before source I/O.
3. Add sealed closed-path staging and extract the small ordered-publication
   helper described in the spec. Adapt follow to that helper while preserving
   follow's outcomes and error reporting. Keep sync/commit/cleanup failures
   injectable in private owner tests; tests must not create production files.
4. Build/prepare the complete report using BASE-01's prepared-output seam before
   any commit. Publish in order,
   roll back prior files only on commit/interruption failure, and preserve files
   after successful commits if stdout later fails.
5. Implement v7 report conversion, new examples, generated help and resource
   preset values. Add task documentation explaining source metadata duplication
   and parts that may cut through streams/datagrams.

## Acceptance and validation

- [ ] SP01–SP17 are covered. CLI owns compressed-input SP06, SP08, SP10–SP15,
  duration validation in SP17, and the composed process variants of SP01–SP07;
  core owns the byte-equivalence/replay cases listed in SPLIT-01.
- [ ] `capture_split_contracts.rs` process tests cover stdin, compression,
  exact filenames, schema-valid results, empty source, collisions, and late
  malformed input with no destinations.
- [ ] Private staging tests cover compressor finish, sync, commit, cleanup,
  cancellation/deadline and bounded open handles; no one-handle-per-part leak.
- [ ] Existing follow publication and staged-output tests pass unchanged in
  behavior; no accidental broad refactor of other artifact commands.
- [ ] Every flag has help, resource diagnostics/preset coverage, and correct
  range validation; new command exists in generated completions/man pages.

```sh
cargo test --locked -p packetcraftr-cli --no-default-features --test capture_split_contracts --test compressed_capture_contracts --test capture_stdin_contracts --test aggregate_schema_conformance --test ndjson_conformance --test generated_documentation_contracts --test resource_diagnostic_contracts
cargo test --locked -p packetcraftr-cli --no-default-features --lib staged_output
cargo test --locked -p packetcraftr-cli --no-default-features --lib commands::follow::write
cargo test --locked -p packetcraftr-cli --no-default-features --lib commands::split
```

## Comments

The output directory is user-owned and pre-existing. Never delete it as cleanup;
delete only unpublished staging and the exact files committed by this invocation.
