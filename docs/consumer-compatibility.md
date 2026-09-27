# Consumer compatibility policy

The pending machine contract is `packetcraftr.output/v7`. It supersedes v6
(the family that superseded the unreleased v3–v5 drafts) by adding the
shared shapes the offline-investigation features publish: capture `split`
results, HTTP `transactions`/`transaction_summary`/`body_export` plus
`http_transaction` stream events, and the expert `gate` verdict. Forwarding
semantics are unchanged from v6: missing values do not satisfy ordinary
preservation, and check-specific evidence states are explicit.

## Versioning and immutable evidence

A contract family identifies names, units, meanings, enum interpretations,
ordering, and terminal semantics—not only JSON shape. Incompatible changes
require a new family even if an old schema would accept the JSON.

A release archive freezes its exact schema snapshots. Keep the archive and its
release checksum together. v7 uses `urn:packetcraftr:output:v7`; resolve it to
the bundled local schema, not a moving branch or network fetch. The release
packager copies every file under `schemas/`, and the verifier requires both the
current v7 output schema and the archived v6 schema and its frozen fixture.
Never modify an already published archive in place, and never relabel
historical v6 evidence.

Consumers should tolerate unknown object members, but must not guess meanings
for unknown verdicts, check kinds, evidence states, or contract families.
Examples are fixtures, not a replacement for serializing actual Rust payloads;
the aggregate schema-conformance suite retains that role.

## Fields, omission, and identifiers

Numbers documented as counts or bytes are nonnegative integers, not booleans.
Duration arguments use their documented units; timestamps retain seconds and
nanoseconds without inferring clock synchronization. `frame` references are
one-based and capture-local; envelope `sequence` is zero-based and output-local.
Conversation numbers, when requested, are capture-global before selection.

A missing optional metadata field means it was not provided. Null evidence
state on an expectation means there is no ingress-side operand; an `absent`
state is an explicit decoder-view observation. These are not interchangeable.
A missing `source` in a library-constructed report is not a verified input hash.

Summary counters cover all accepted evidence. Retention only changes detail
lists and omission counts. `fail` and `inconclusive` both produce CLI exit 1
after a successfully published forwarding report. An error envelope is instead
an execution failure. Neither process exit nor a partial list alone is a verdict.

## Streams and the reference consumer

NDJSON requires contiguous sequences starting at zero, complete newline-ended
records, and exactly one terminal `complete` or `error`. EOF without terminal,
a sequence gap, duplicate JSON keys, or another record after terminal is rejected.
Per-record and whole-stream bounds are separate.

```sh
set +e
packetcraftr --output ndjson verify-forwarding before.pcap after.pcap \
  --identity ipv4.identification --preserve ipv4.ttl > report.ndjson
status=$?
set -e
python3 examples/consumers/forwarding.py --format ndjson --exit-code "$status" < report.ndjson
```

The consumer validates the subset of v6 and v7 it interprets, including evidence
states, counter relationships, omission totals, requested-check coverage, and
verdict consistency. The first record of an NDJSON stream selects the schema
family and a mid-stream switch is rejected; anything else requires explicit
migration. It does not claim to replace complete JSON Schema validation.
Its own successful exit means the report was interpreted, not that forwarding
passed. Read `execution` and `verdict`, or use the regression harness's explicit
test contract.

The frozen v6 and v7 fixtures and their mutations are exercised by
`scripts/test-output-consumer.py`.
The Rust CLI tests continue validating real serializers against v7.

## Rust API adoption

The crates remain unpublished (`publish=false`). Public struct fields and enum
variants are source-compatibility commitments: review additions/removals before
a stable release rather than assuming JSON compatibility implies Rust compatibility.

For a reproducible local Git dependency, first commit the reviewed source.
From that checkout, use the exact revision in a separate project:

```sh
repository="$(git rev-parse --show-toplevel)"
revision="$(git rev-parse HEAD)"
consumer="$(mktemp -d)"
cat > "$consumer/Cargo.toml" <<EOF
[package]
name = "my-packet-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
packetcraftr-core = { git = "file://$repository", rev = "$revision" }
EOF
mkdir "$consumer/src"
printf 'fn main() { let _ = packetcraftr_core::protocol::builtin::registry(); }\n' > "$consumer/src/main.rs"
cargo build --manifest-path "$consumer/Cargo.toml"
```

For shared projects, replace the local URL with the chosen repository URL and
ensure the same full revision exists there. Do not substitute `main` for a pin.
Commit the consumer's lockfile. Workspace lockfiles do not govern downstream
resolution.

`scripts/check-external-consumer.py` creates a temporary independent workspace,
resolves cached dependencies offline, and tests the public policy-gated,
injected-provider workflow without native features. It never imports internal
test modules or accesses the network through those providers.
