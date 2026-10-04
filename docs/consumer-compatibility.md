# Consumer compatibility policy

## Versioning and immutable evidence

A contract family identifies names, units, meanings, enum interpretations,
ordering, and terminal semantics—not only JSON shape. Incompatible changes
require a new family even if an old schema would accept the JSON.

A release archive freezes its exact schema snapshots. Keep the archive and its
release checksum together. Resolve a schema's `$id` (for example that of the
[output schema](../schemas/packetcraftr.output.v6.schema.json)) to the bundled
local file, not a moving branch or network fetch. The release packager copies
every file under `schemas/`, and the verifier requires the output schema.
Never modify an already published archive in place.

Consumers should tolerate unknown object members, but must not guess meanings
for unknown verdicts, check kinds, evidence states, or contract families.
Examples are fixtures, not a replacement for serializing actual Rust payloads;
the `aggregate_schema_conformance` suite does that.

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

The consumer validates the subset of the output contract it interprets,
including evidence states, counter relationships, omission totals,
requested-check coverage, and verdict consistency. It does not claim to replace
complete JSON Schema validation. Its own successful exit means the report was
interpreted, not that forwarding passed. Read `execution` and `verdict`, or use
the regression harness's explicit test contract.

The frozen fixture under `examples/consumers/fixtures/` is the independent
consumer example. The Rust CLI tests validate real serializers against the
schema.

## Rust API adoption

The crates remain unpublished (`publish=false`). Public struct fields and enum
variants are source-compatibility commitments: review additions/removals before
a stable release rather than assuming JSON compatibility implies Rust compatibility.

For a reproducible local Git dependency, first commit the reviewed source, then
pin its exact revision (`git rev-parse HEAD`) from a separate project:

```toml
[dependencies]
packetcraftr-core = { git = "file:///path/to/checkout", rev = "FULL_COMMIT_SHA" }
```

For shared projects, replace the local URL with the chosen repository URL and
ensure the same full revision exists there. Do not substitute `main` for a pin.
Commit the consumer's lockfile. Workspace lockfiles do not govern downstream
resolution.

`scripts/check-external-consumer.py` creates a temporary independent workspace,
resolves cached dependencies offline, and tests the public policy-gated,
injected-provider workflow without native features. It never imports internal
test modules or accesses the network through those providers.
