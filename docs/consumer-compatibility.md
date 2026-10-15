# Consumer compatibility policy

## Versioning and immutable evidence

A contract family covers names, units, meanings, enums, ordering, and terminal
semantics, not only JSON shape. Incompatible changes require a new family even
when an older schema accepts their shape.

Current producers emit [output/v17](../schemas/packetcraftr.output.v17.schema.json)
and [packet/v2](../schemas/packetcraftr.packet.v2.schema.json). Beta.3 used
output/v2 and packet/v1; output v6–v16 remain frozen for historical evidence.
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

## Output family v17

Adds statistics `table: "overview"` with total protocol/endpoint/conversation
counts and the corresponding retained leaderboards. Explicit `--sort frames|bytes`
ranks statistics before truncation, with the other volume metric and natural key
as tie-breakers. Existing default ordering is unchanged; overview defaults to
frames. CSV is a separate flat-table format and does not use the JSON envelope.
See [statistics](statistics.md) for exact headers, units, and omission semantics.

## Output family v16

Adds SCTP `init` and `cookie_echo` scanning (`plan.sctp_scan`, `ports.sctp_scan`,
and per-probe `sctp_scan: {mode, chunk_type}`), standalone IP-protocol (`0..=255`)
inventory (`ip_protocol` on endpoints/probes/sends/failures and `ip_protocols` on
`target_list` reports), extra host-discovery probe discriminators (`icmp_request`
for `timestamp`/`netmask` and `tcp_scan` for `tcp-ack`), new host reason kinds
(`sctp_init_ack`, `sctp_abort`, `sctp_other`, `icmp_timestamp_reply`,
`icmp_netmask_reply`, `ip_protocol_payload`, `icmp_protocol_unreachable`), and
`sctp_init.*`, `sctp_cookie_echo.*`, and `ip_protocol.*` inference rules.

## Output family v15

Adds TCP diagnostic scans (`syn`, `ack`, `window`, `fin`, `null`, `xmas`,
`maimon`, `custom`). Raw scans with TCP scan endpoints publish `plan.tcp_scan`
(`{mode, flags}`); each raw scan-stage TCP probe and `probe_sent` record carries
the same object (`--list` publishes `ports.tcp_scan`), while discovery TCP
probes always carry `{mode: syn, flags: 2}`. Correlated direct TCP replies carry
`tcp_window` (`0..=65535`). Inference `state` gains `unfiltered`, and `rule`
gains `tcp_<mode>.*`. See [TCP diagnostics](tcp-diagnostics.md).

## Output family v14

Adds standalone `identify-os` aggregate results and `os_preparation`,
`os_probe`, `os_additional`, `os_undecoded`, `diagnostic`, and `complete` stream
records. Outcomes are `matched`, `ambiguous`, `unknown`, or `inconclusive` with
ordinal `qualified` confidence and candidate provenance tied to
`packetcraftr.os-fingerprints/v1` and `packetcraftr.os-probes/v1`. See
[OS identification](os-identification.md).

## Output family v13

Adds explicit TLS wrapping (`tls_failed`, probe `tls` with `server_name`,
`handshake_complete`, negotiated cipher/version, DER `certificates_hex`, and
`unauthenticated: true`, plus `usage.tls`), SMTP/FTP identification fields, and
sourced candidate metadata (`hostname`, `device_type`, wildcard-version `cpe`).
See [service identification](service-identification.md).

## Output family v12

Adds explicit `identify` aggregate `records` and NDJSON `identify_endpoint`
events with `excluded`/`unknown`/`matched`/`ambiguous`/`malformed`/`truncated`/
`budget_exhausted` outcomes, exact request/response hex, observed claims,
candidates with corpus/probe/rule/field provenance, and ordinal `claim`/`protocol`
confidence.

## Output family v11

Adds optional raw-scan `traceroute` plans, host-order trace results,
`traceroute_probe`/`undecoded`/`host` stream events, and separate fresh `hops`
versus sourced `reused_hops` claims. Standalone `traceroute` keeps its shapes.
See [trace semantics](scanner-evidence.md#traceroute-stage).

## Output family v10

Adds required `scheduling` on scan/connect results and terminals: fixed/adaptive
mode, effective config, `observed_peak_window`, `retries_started`, suspected
rate-limit conditions, `incomplete` hosts, and connect operation/process ceilings.

## Output family v9

Adds required host records, discovery plans, and `discovery`/`scan` stage
discriminators on probes, sends, and failures, plus neighbor (`direct`/`cached`/
`possible_proxy` or routed `next_hop`) and reverse-DNS evidence. See
[host semantics](scanner-evidence.md#host-observations).

## Output family v8

Adds scan/connect plans (`requested_method`, `selected_method`, reason, catalog
version, exclusions, curated UDP ports), per-endpoint [port inference](scanner-evidence.md#port-inference)
(`state`, `rule`, and disjoint `supporting`/`conflicting`/`unanswered`/`failed`
sequence partitions), unattributed frames, and list-mode ports.

## Output family v7

Adds `target_list` (`method: target_list`), optional declared zone and resolved
interface scope on scan evidence/failures, and exact `retained_evidence_bytes`.

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

The forwarding consumer accepts v6–v15 and checks states, counter/omission
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
