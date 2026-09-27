# HTTP-T02: Expose HTTP transaction evidence in the CLI

Status: resolved (4428bf92; all listed tests green)
Blocked by: HTTP-T01
Size: small–medium
Spec: [user behavior and complete output definition](../spec.md)

## What to build

1. Add `--transactions` and precise help to `commands/http/arguments.rs`;
   opt the existing collector into transactions only when set.
2. Extend `commands/http.rs` and its rendering module to pass transaction
   events through `EventOutput`, aggregate them, and publish the optional
   terminal transaction summary. Use CLI-owned DTO conversions from BASE-01.
3. Implement the prescribed NDJSON event and text line. Keep normal message
   and issue evidence, including failures occurring after a paired header row.
4. Generate JSON/NDJSON examples showing an informational response, a signed
   interval, and an unanswered request. Add the flag to task documentation and
   explain invocation-local message IDs and capture-observed timing.

## Acceptance and validation

- [x] HT01–HT14 are observable through CLI `http_contracts`, with schema
  assertions placed in aggregate/NDJSON conformance targets; HT15 remains a
  core public-API regression.
- [x] Every emitted payload uses v7; disabled mode has an empty transactions
  array and null transaction summary; enabled empty analysis has zero counts.
- [x] NDJSON sequences/terminal behavior, forward message references, and EOF
  ordering follow the spec, including broken-output failure.
- [x] Text, JSON, NDJSON, gzip/Zstd input, stdin, stream selection, and epoch
  bounds exercise the same core behavior and output byte allowance.
- [x] Control characters in existing captured text remain escaped.

```sh
cargo test --locked -p packetcraftr-cli --no-default-features --test http_contracts --test aggregate_schema_conformance --test ndjson_conformance --test published_example_matrix --test generated_documentation_contracts --test resource_diagnostic_contracts
```

## Comments

HTTP-B02 depends on this ticket to avoid parallel redesign of HTTP terminal
reports and command assembly.
