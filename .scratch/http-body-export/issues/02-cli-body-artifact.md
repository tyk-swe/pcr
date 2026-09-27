# HTTP-B02: Stage, validate, and publish one HTTP body artifact

Status: resolved (c2601d48; all listed tests green)
Blocked by: HTTP-B01, HTTP-T02
Size: medium
Spec: [CLI behavior, failures, output, HB01–HB17](../spec.md)

## What to build

1. Add paired `--body-message`/`--write` arguments to HTTP and the private body
   assembly owner. Validate option pairing before source I/O. Use `StagedFile`
   and one buffered sink with incremental SHA-256 and cancellation checks.
2. Track the selected terminal message separately from aggregate retention.
   Finish whole-capture inspection, validate status/byte count and report
   serialization charge, then sync/check/persist in the specified order.
   Implement the caller-owned `EventOutput`/private inspect refactor and
   `charge` method prescribed by the spec; keep sink and message evidence in
   disjoint local owners. Use BASE-01's prepared success envelope at commit.
3. Convert the exact failure table into typed command-local errors preserving
   underlying HTTP/I/O sources. Do not treat a per-message parse issue from a
   different message as a global execution failure.
4. Publish the v7 `body_export` DTO only in successful terminal reports.
   Preserve message/transaction output and document how to list then select
   invocation-local message IDs with identical selector settings.

## Acceptance and validation

- [x] HB01–HB17 have appropriate core/CLI coverage; CLI tests assert exact
  file contents/digests and destination absence on each failure path.
- [x] Public process regressions cover binary bodies, stdin/compressed input,
  late corrupt input, existing destinations, and all three output formats.
- [x] Injected private writer/publication failures cover sync/persist and
  cancellation races without depending on privileged filesystem behavior.
- [x] Body/report budgets remain distinct; metadata charge occurs before
  persistence; selected evidence is not inferred from retained JSON rows.
- [x] Generated documentation and examples accurately name coded body bytes.

```sh
cargo test --locked -p packetcraftr-cli --no-default-features --test http_contracts --test aggregate_schema_conformance --test ndjson_conformance --test published_example_matrix --test generated_documentation_contracts --test resource_diagnostic_contracts
cargo test --locked -p packetcraftr-cli --no-default-features --lib commands::http
cargo test --locked -p packetcraftr-cli --no-default-features --lib staged_output
cargo test --locked -p packetcraftr-cli --no-default-features --lib commands::application_output
cargo test --locked -p packetcraftr-cli --no-default-features --test dns_read_contracts
```

## Comments

An unwritable report after successful persistence leaves the artifact in place,
matching existing writer commands; explain this in command help and migration docs.
