# Consumer compatibility policy

## Versioning and immutable evidence

A contract family identifies names, units, meanings, enum interpretations,
ordering, and terminal semantics—not only JSON shape. Incompatible changes
require a new family even if an old schema would accept the JSON.

A release archive freezes its exact schema snapshots. Keep the archive and its
release checksum together. Resolve a schema's `$id` (for example that of the
[output schema](../schemas/packetcraftr.output.v9.schema.json)) to the bundled
local file, not a moving branch or network fetch. The release packager copies
every file under `schemas/`, and the verifier requires the output schema.
Never modify an already published archive in place.

Consumers should tolerate unknown object members, but must not guess meanings
for unknown verdicts, check kinds, evidence states, or contract families.
Examples are fixtures, not a replacement for serializing actual Rust payloads;
the CLI's `aggregate_schema_conformance` tests do that.

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

## Output family v9

`packetcraftr.output/v9` is the current production family. It preserves every
v8 meaning and adds host discovery:

- a required `hosts` list on raw scan results and connect reports, and one
  `host` stream record per target before `complete`. Each host states whether
  discovery ran (`discovery`: `not_requested`, `skipped`, `responded`, or
  `no_response`) and whether the scan stage probed it (`scan`: `scanned`,
  `skipped`, or `not_requested`). `no_response` is an uncertain observation,
  never absence, and `not_requested` or `skipped` claims no reachability;
- `reasons` for each responded host, each with a `kind`, the `evidence` behind
  it (`wire`, `socket`, or `cache`), and its `basis` (`direct`, `cached`, or
  `possible_proxy`). A `possible_proxy` basis flags a link address that also
  answered for another address of the same family, as a target or a gateway;
  it does not assert a cause;
- an optional `neighbor` outcome (`resolved`, `silent`, `routed`, or
  `not_applicable`). A routed target's `next_hop` is its gateway, sent no
  request; its link address, present only when already cached, is never the
  target's identity;
- an optional `reverse_dns` lookup with the PTR `names` the server answered.
  Names are observations, not authenticated identity;
- a required `stage` (`discovery` or `scan`) on probe, `probe_sent`,
  `connect_probe`, and failed-probe records. Endpoints and their `counts`
  cover the scan stage only; and
- a required `discovery` object in `plan`.

[Scanner evidence](scanner-evidence.md#host-observations) defines the host
vocabulary.

## Output family v8

`packetcraftr.output/v8` is frozen. It preserves every v7 meaning and adds
scanner port planning and inference:

- a required `plan` on raw scan results, NDJSON scan `complete`, and connect
  summaries: the requested and selected scan `method` (with the reason when
  automatic selection chose it), the `port_catalog` data set and version that
  names and hints came from, the `excluded_endpoints` count, and, when curated
  UDP payloads were requested, their data set and the `applied` and
  `overridden` ports;
- a `port_hint` on endpoints whose port has a catalog name. A hint is not
  service identification;
- an `inference` on endpoints: a PacketcraftR `state` (`open`, `closed`,
  `filtered`, `open_or_filtered`, `unknown`, or absent when only operational
  failures were observed), the `rule` that decided it, and every attempt
  sequence in exactly one of `supporting`, `conflicting`, `unanswered`, or
  `failed`. Attempt `classification` values and the endpoint `classification`
  aggregate keep their v7 meaning; consumers must not substitute one for the
  other;
- a required `unattributed` list on raw scan results, and `unattributed` stream
  records, for correlated `late`, `duplicate`, and `ambiguous` frames that no
  attempt outcome carries;
- one `endpoint` (raw) or `connect_endpoint` (connect) stream record per
  endpoint before `complete`, naming the probe sequences it aggregates; and
- an optional `ports` selection on `target_list` results and terminals.

Inference states map to Nmap's for comparison only:
[scanner evidence](scanner-evidence.md#port-inference) has the rule table and
mapping.

## Output family v7

`packetcraftr.output/v7` is frozen. It preserves every v6 meaning and adds:

- the `target_list` branch of `scan` (`--list`), discriminated by
  `method: "target_list"` in aggregate results, `target` stream records, and
  the `complete` terminal; and
- an optional `scope` object (`zone` text plus resolved `interface` identity)
  on scoped targets in scan/connect probes, endpoints, sent evidence, and
  failure records, plus the exact `retained_evidence_bytes` charge on scan,
  connect, and traceroute summaries.

The frozen `packetcraftr.output/v6` and `packetcraftr.output/v7` families stay
bundled for previously published evidence; new output never reuses their
identities. The reference consumer accepts all three families.

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
