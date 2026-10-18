# Consumer compatibility policy

## Versioning and immutable evidence

A contract family covers names, units, meanings, enums, ordering, and terminal
semantics, not only JSON shape. Incompatible changes require a new family even
when an older schema accepts their shape.

Current producers and consumers use one contract per family:
[output/v1](../schemas/packetcraftr.output.v1.schema.json),
[packet/v1](../schemas/packetcraftr.packet.v1.schema.json), and
[rewrite/v1](../schemas/packetcraftr.rewrite.v1.schema.json).
The [baseline reset](reset-v1.md) intentionally replaces historical meanings of v1;
old documents require explicit migration or regeneration.
Resolve `$id` to the bundled local file, never moving `main` or a network fetch.
Tolerate unknown object members, but reject unknown families, verdicts, check
kinds, or evidence states.

## Fields, omission, and identifiers

Counts and byte fields are nonnegative integers. Durations use documented units;
second/nanosecond timestamps imply no clock synchronization. Frame references
are one-based/capture-local, envelope sequences zero-based/output-local, and
conversation numbers capture-global before selection.

Missing metadata, null ingress operand on an expectation, and explicit decoder
`absent` are distinct. Summary counters include accepted evidence regardless of
retained detail/omissions. Forwarding fail/inconclusive returns exit 1 after
publication; an error envelope is execution failure.
Security commands likewise publish successful results before returning exit 1
for an explicitly selected `--fail-on` or `--fail-incomplete` gate.

## Scan measurements and acquisition quality

Raw probe `measurement` distinguishes `response`, `no_reply` with explicit
`coverage`, and `unavailable`. Streamed pipeline no-reply measurements carry
`pending` coverage until `observation_quality` qualifies the existing attempts
in its inclusive sequence interval and stage; gaps are allowed. It changes
only pending no-reply measurements; final `unknown` or `incomplete` coverage is
never upgraded. A terminal error leaves unqualified attempts unusable for
negative inference. Qualification precedes endpoint inference and successful
completion. Aggregate probes already carry final coverage.

Only `no_reported_loss` and transport-owned `transport_timeout` support silence
rules. `unknown`, `incomplete`, and `pending` enter inference's `failed` partition.
Positive correlated replies remain valid under capture loss. Locally shortened
host windows leave their no-reply coverage unknown. Custom capture providers
default to unknown acquisition quality; zero counters do not change
that contract. Zero local drop counts establish neither end-to-end visibility
nor a remote cause. Source-global drops conservatively qualify all negative
observations in the capture interval, without claiming which response was lost.

RTT `sent` partitions into `received`, `lost` (qualified no reply), and
`unavailable` (local failure or insufficient acquisition quality). `lost` does
not identify a network or remote cause. TCP operation-wide `deadline_expired`
is unavailable; a completed transport `timed_out` remains qualified silence.

## Statistics

Statistics publish `table: "overview"` with total protocol/endpoint/conversation
counts and the corresponding retained leaderboards. Explicit `--sort frames|bytes`
ranks statistics before truncation, with the other volume metric and natural key
as tie-breakers. Existing default ordering is unchanged; overview defaults to
frames. CSV is a separate flat-table format and does not use the JSON envelope.
`--sort duration` ranks conversations by duration, then frames, bytes, and natural
key. `--min-frames` filters rows before ranking and truncation without changing
overview totals or distinct counts. Fragment tables reject these options and
`--top`; use `--max-ip-outcomes` for retained fragment outcomes.
See [statistics](statistics.md) for exact headers, units, and omission semantics.

## SCTP and IP-protocol inventory

The scan contract covers SCTP `init` and `cookie_echo` (`plan.sctp_scan`,
`ports.sctp_scan`, and per-probe `sctp_scan: {mode, chunk_type}`), standalone IP-protocol (`0..=255`)
inventory (`ip_protocol` on endpoints/probes/sends/failures and `ip_protocols` on
`target_list` reports), extra host-discovery probe discriminators (`icmp_request`
for `timestamp`/`netmask` and `tcp_scan` for `tcp-ack`), host reason kinds
(`sctp_init_ack`, `sctp_abort`, `sctp_other`, `icmp_timestamp_reply`,
`icmp_netmask_reply`, `ip_protocol_payload`, `icmp_protocol_unreachable`), and
`sctp_init.*`, `sctp_cookie_echo.*`, and `ip_protocol.*` inference rules.

## TCP diagnostic scans

TCP diagnostic scans include `syn`, `ack`, `window`, `fin`, `null`, `xmas`,
`maimon`, and `custom`. Raw scans with TCP scan endpoints publish `plan.tcp_scan`
(`{mode, flags}`); each raw scan-stage TCP probe and `probe_sent` record carries
the same object (`--list` publishes `ports.tcp_scan`), while discovery TCP
probes always carry `{mode: syn, flags: 2}`. Correlated direct TCP replies carry
`tcp_window` (`0..=65535`). Inference `state` includes `unfiltered`, and `rule`
includes `tcp_<mode>.*`. See [TCP diagnostics](tcp-diagnostics.md).

## OS identification

`network identify-os` publishes aggregate results and `os_preparation`,
`os_probe`, `os_additional`, `os_undecoded`, `diagnostic`, and `complete` stream
records. Outcomes are `matched`, `ambiguous`, `unknown`, or `inconclusive` with
ordinal `qualified` confidence and candidate provenance tied to
`packetcraftr.os-fingerprints/v1` and `packetcraftr.os-probes/v1`. See
[OS identification](os-identification.md).

## TLS service identification

Service identification supports explicit TLS wrapping (`tls_failed`, probe
`tls` with `server_name`,
`handshake_complete`, negotiated cipher/version, DER `certificates_hex`, and
`unauthenticated: true`, plus `usage.tls`), SMTP/FTP identification fields, and
sourced candidate metadata (`hostname`, `device_type`, wildcard-version `cpe`).
See [service identification](service-identification.md).

## Service identification

Explicit `identify` publishes aggregate `records` and NDJSON `identify_endpoint`
events with `excluded`/`unknown`/`matched`/`ambiguous`/`malformed`/`truncated`/
`budget_exhausted` outcomes, exact request/response hex, observed claims,
candidates with corpus/probe/rule/field provenance, and ordinal `claim`/`protocol`
confidence.

## Traceroute

Raw scans can publish `traceroute` plans, host-order trace results,
`traceroute_probe`/`undecoded`/`host` stream events, and separate fresh `hops`
and sourced `reused_hops` claims. Standalone `network traceroute` uses its own
result shape.
See [trace semantics](scanner-evidence.md#traceroute-stage).

## Scheduling

Required `scheduling` on scan/connect results and terminals records fixed/adaptive
mode, effective config, `observed_peak_window`, `retries_started`, suspected
rate-limit conditions, `incomplete` hosts, and connect operation/process ceilings.

## Host discovery

Scan results include host records, discovery plans, and `discovery`/`scan` stage
discriminators on probes, sends, and failures, plus neighbor (`direct`/`cached`/
`possible_proxy` or routed `next_hop`) and reverse-DNS evidence. See
[host semantics](scanner-evidence.md#host-observations).

## Scan plans and inference

Scan/connect plans record requested and selected methods, reasons, catalog
versions, exclusions, and curated UDP ports. Results include per-endpoint
[port inference](scanner-evidence.md#port-inference)
(`state`, `rule`, and disjoint `supporting`/`conflicting`/`unanswered`/`failed`
sequence partitions), unattributed frames, and list-mode ports.

## Target lists

`target_list` reports use `method: target_list`. Scan evidence/failures carry
optional declared zones and resolved interface scopes. Retention is accounted
by exact `retained_evidence_bytes`.

## Streams and the reference consumer

NDJSON requires contiguous zero-based sequences, newline-ended records (at most
16 MiB including newline), and exactly one `complete` or `error` terminal.

```sh
set +e
packetcraftr --output ndjson analyze verify-forwarding before.pcap after.pcap \
  --identity ipv4.identification --preserve ipv4.ttl > report.ndjson
status=$?
set -e
python3 examples/consumers/forwarding.py --format ndjson --exit-code "$status" < report.ndjson
```

The forwarding consumer accepts only output/v1 and checks states, counter/omission
relationships, requested checks, and verdict coherence. Its exit 0 means the
report was valid, not that forwarding passed; inspect `execution` and `verdict`.

## Rust API adoption

Crates are unpublished (`publish=false`). Public struct/enum changes can break
Rust callers despite compatible JSON. Pin a full reviewed commit and commit the
consumer lockfile:

```toml
[dependencies]
packetcraftr-core = { git = "file:///path/to/checkout", rev = "FULL_COMMIT_SHA" }
```

Never substitute `main` for a pin. `scripts/check-external-consumer.py` tests
public policy-gated injected-provider workflows in a detached workspace.
