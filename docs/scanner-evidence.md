# Scanner evidence and claims model

This document is the [M1][m1] evidence model. It defines the four claim
vocabularies scanner milestones use and assigns every field of the current
scan output to exactly one of them, so later milestones extend a layer instead
of overloading one. It describes behavior as of the reviewed revision; it adds
no scanner capability and changes no output.

The four vocabularies are:

- **Attempt observations.** What one probe or socket operation observed: a
  correlated reply, an ICMP error, silence within its window, a late or
  unattributed frame, or a socket call's own result.
- **Port inference.** A scan-method-dependent conclusion drawn from one
  endpoint's attempts, together with the rule that produced it. No current
  output publishes this layer. Conflicting attempts remain visible beside any
  future inference.
- **Host observations.** Evidence that a host answered, by which probe, and
  whether the evidence is direct, a cached next hop, or a proxy reply. No
  current output publishes a host record.
- **Operational failures.** A missing backend, a refused permission, a
  policy limit, an exhausted budget, an operation deadline, or a
  cancellation. These are never expressed as network observations.

Everything else in the output is *metadata supporting a layer*, not a fifth
claim vocabulary: coordinates that identify which attempt a record describes,
timestamps and counters that bound the observation, routing and capture
provenance, retained bytes, and accounting totals. The field tables below name
each field's role explicitly.

## Attempt observations

One record per probe or socket attempt. The claim-bearing fields are the
status/outcome, the classification, the reason, the responder, and any
subordinate application check; everything else on the record is coordinate or
provenance metadata for that observation.

### Packet scan attempts (`scan` events and `endpoints[].probes[]`)

Published as the `probe` stream event and as `endpoints[].probes[]` in the
aggregate `scan` result, from
[`ProbeEvidence`][scan-report] via [`output::scan::Probe`][scan-output].

| Field | Role |
| --- | --- |
| `sequence` | Metadata: operation-local coordinate identifying the attempt. |
| `protocol` | Metadata: derived from transport and address family (`tcp`, `udp`, `icmpv4`, `icmpv6`). |
| `destination`, `destination_port` | Metadata: the addressed endpoint the attempt targeted. |
| `attempt` | Metadata: retry ordinal for this endpoint. |
| `status` | Attempt observation: `response` if a checksum-valid, protocol-consistent reply was attributed within the attempt's window, else `timeout`. |
| `classification` | Attempt observation: the per-attempt value from the classification vocabulary below. |
| `responder` | Attempt observation: the address that actually answered. It can differ from `destination` — an ICMP error reports the intermediate hop that sent it, and a next-hop neighbor answer is not the target answering. |
| `sent_at`, `received_at`, `latency` | Metadata: timing of the attempt and its attributed reply. |
| `frame` | Metadata: the retained captured reply bytes, when retained evidence kept them. |
| `reason` | Attempt observation: the fixed correlation string behind the classification (see below), or `no checksum-valid, protocol-consistent response before the deadline` for silence. |
| `application` | Attempt observation, subordinate: the UDP profile check outcome described below. |

The per-attempt `classification` values are attempt observations with fixed
meanings from [`classify_response`][scan-evidence] over
[`correlation::observe`][correlation]:

| Correlated response | `classification` | `reason` |
| --- | --- | --- |
| TCP RST from the endpoint | `closed` | `correlated TCP reset` |
| TCP SYN/ACK acknowledging the probe's sequence + 1 | `open` | `correlated TCP SYN/ACK` |
| Other TCP flags from the endpoint | `unknown` | `correlated TCP response with inconclusive flags` |
| UDP reply reversing the full transport tuple | `open` | `correlated UDP response from the requested endpoint` |
| ICMP echo reply | `open` | `correlated ICMP echo reply` |
| ICMP port unreachable quoting the probe | `closed` | `ICMPv4 port unreachable` / `ICMPv6 port unreachable` |
| ICMP administratively prohibited | `filtered` | `ICMPv4 administratively prohibited` / `ICMPv6 policy or administrative rejection` |
| ICMP destination unreachable | `unreachable` | `ICMPv4 destination unreachable` / `ICMPv6 destination unreachable` |
| ICMP time exceeded before the endpoint | `filtered` | `ICMPv4 time exceeded before reaching the endpoint` / `ICMPv6 time exceeded before reaching the endpoint` |
| No valid response inside the window | `timeout` | `no checksum-valid, protocol-consistent response before the deadline` |

Responses carrying checksum-failure diagnostics produce no observation. A
captured frame that fails to decode is retained as `undecoded` evidence; a
decoded frame that matches no sent probe uniquely is `unsolicited` and is not
published as probe evidence. Neither overrides a `timeout`: silence inside the
window is itself the observation. A response arriving after its round's window
is unattributed evidence, not a late `received`.

### Connect scan attempts (`connect_probe` events and `endpoints[].probes[]`)

Published as the `connect_probe` stream event and as `endpoints[].probes[]` in
the `tcp_connect` aggregate, from [`connect::ProbeEvidence`][connect-report]
via [`output::scan::connect::Probe`][connect-output].

| Field | Role |
| --- | --- |
| `sequence` | Metadata: operation-local coordinate. |
| `address`, `port` | Metadata: the socket endpoint attempted. |
| `attempt` | Metadata: retry ordinal. |
| `attempted` | Attempt observation: whether the provider issued the socket call at all. `false` means no network claim exists for this record. |
| `connect_succeeded` | Attempt observation: the socket call's result; `null` means no result was available by the deadline. |
| `outcome` | Attempt observation: the connect outcome vocabulary below. |
| `classification` | Attempt observation: `outcome` mapped onto the shared six-value classification vocabulary (`connected`→`open`, `refused`→`closed`, `timed_out`/`deadline_expired`→`timeout`, `unreachable`→`unreachable`, `local_error`→`unknown`). |
| `scheduled_at`, `finished_at`, `elapsed` | Metadata: attempt timing. |
| `local` | Metadata: the local socket address the kernel bound. |
| `error` | Metadata: the failing socket call's `kind`, `os_code`, and `message`, when a socket error produced the outcome. |
| `method` (on `connect_probe` events and the summary) | Metadata: constant `tcp_connect`. |

The connect `outcome` values are set in
[`connect::engine`][connect-engine] and [`Outcome::classification`][connect-report]:

| `outcome` | Meaning |
| --- | --- |
| `connected` | The TCP handshake completed; the returned peer endpoint matched the attempt. |
| `refused` | The socket call failed with `ConnectionRefused`. |
| `timed_out` | The socket call itself failed with `TimedOut` — a socket timeout observed by the connect operation, including the provider's own per-connect deadline converted to that kind. |
| `unreachable` | The socket call failed with `NetworkUnreachable` or `HostUnreachable`. |
| `local_error` | The socket call failed with any other I/O error, including provider cancellation converted to `Interrupted`. |
| `deadline_expired` | The attempt's deadline elapsed: either the in-flight connect was cancelled when its timeout passed with no socket result, or the socket call returned but took longer than the attempt timeout. |

`timed_out` and `deadline_expired` are deliberately distinct: the first is the
socket call's own timeout result, the second is the operation's deadline
ending the attempt. Neither is the operation-level deadline or cancellation,
which are operational failures published as errors, not attempt outcomes.

### Application checks on attempts

The `application` member carries a subordinate attempt observation from an
operator-supplied [UDP profile document][udp-document]:

| `status` | Meaning |
| --- | --- |
| `not_observed` | The profile was configured but no UDP application reply was observed (or the reply's addressing did not reverse the request's outer IP/UDP tuple). |
| `unchecked` | A UDP reply was observed and the profile configures no response checks. |
| `confirmed` | The configured response checks (DNS header/question echo or bounded byte checks) matched the reply payload. |
| `rejected` | The reply payload was observed and the configured checks did not match. |

`profile` names the operator document and `reason` carries the check's own
string. `confirmed` means the configured checks matched — it is never an
authentication or an identity claim, and a rejection is a failed check on that
attempt, not a verdict on the service.

## The endpoint aggregate is not port inference

Each `endpoints[]` record groups the attempts for one `(address, port)` (packet
scan) or socket address (connect scan) under `address`, `transport`, `port`,
and `probes` — all coordinate metadata — plus one `classification`.

That endpoint `classification` is the **highest-ranked attempt outcome** the
endpoint collected, under the fixed order
`open > closed > filtered > unreachable > unknown > timeout`
([`Classification::rank`][scan-report], applied by `promote`). It is a legacy
convenience aggregate over attempt observations. It is **not** the port
inference vocabulary: it has no scan-method semantics, carries no inference
rule, and must not be read as one. Scan-dependent inferred states publish in a
new output family when [M6][m6] first produces them, per the
[consumer compatibility policy][compatibility].

The `complete` stream event's `counts` (`open`, `closed`, `filtered`,
`unreachable`, `unknown`, `timeout`) tally the winning classification per
endpoint — the same highest-ranked outcome the endpoint aggregate reports —
not every attempt ([`scan::engine`][scan-engine] iterates the per-endpoint
winners). They are accounting metadata over the attempt vocabulary, not new
claims.

## Transmission and capture metadata

These fields carry provenance for the layers above; none of them is a claim
about the target:

- `probe_sent` events (`Sent`): the confirmed transmission record — `frame`
  (`bytes_hex`, `length`) is the actual wire bytes sent and `route` is the
  materialized route plan and any neighbor-resolution evidence (`plan.route`,
  `mode`, `lookup_destination`, `final_destination`, `visited_destinations`,
  `packet_source`, `neighbor_source`, `neighbor_target`, `destination_mac`,
  `source_mac`, `neighbor_vlan_tags`, `synthesized_ethernet`, and
  `neighbor.mac_address`, `attempts`, `cache_hit`, `captured`,
  `evidence_truncated`, `capture_statistics`). `udp_profile` names the
  operator document that shaped the payload. A sent record proves the provider
  committed the materialized bytes it reports — it does not prove a physical
  packet left the host, much less that the target received one.
- `undecoded` events and the aggregate `undecoded` list: retained captured
  frames (`timestamp`, `captured_length`, `original_length`, `link_type`,
  `interface`, `direction`, `bytes_hex`) that could not be decoded within
  bounds — preserved wire evidence, not an observation.
- `diagnostic` events and the envelope `diagnostics` list: decoder and
  executor diagnostics (`code`, `severity`, `message`, `layer`, `field`) such
  as checksum failures — integrity metadata about the evidence.
- Timestamps (`sent_at`, `received_at`, `scheduled_at`, `finished_at`, and
  frame `timestamp`) publish as `unix_seconds`/`nanoseconds` pairs; durations
  (`latency`, `elapsed`, `planned_duration`) and `dropped`/`received` counters
  are nonnegative values in their documented units.
- `rtt` (`sent`, `received`, `lost`, `min`, `avg`, `max`): round-trip
  accounting. `sent` counts confirmed transmissions, `received` replies
  attributed inside their windows, and `lost` is `sent - received`, which
  includes replies the capture backend dropped before delivery.
- `stats` on the envelope (`packets_attempted`, `packets_completed`, `bytes`,
  `elapsed`, `capture`): execution accounting. The nested `capture` counters
  (`received_frames`, `received_bytes`, `dropped_frames`, `dropped_bytes`,
  `overflow_events`, `receiver_dropped_frames`) bound how much evidence the
  capture path delivered or lost.
- `resolved_addresses`, `target`, `planned_duration`, `socket_stats`
  (`connections_scheduled`, `connections_attempted`, `connections_succeeded`,
  `elapsed`, `rtt`), and the envelope fields `schema`, `command`, `mode`,
  `sequence`, `event`, `resources`: operation metadata.

## Operational failures

Policy refusals, missing backends, budget exhaustion, operation deadlines, and
cancellation publish as the error envelope (`status: "error"` with `code`,
`kind`, `message`, `causes`, `context`, `remediation`), never as attempt or
host observations. In a stream the error is the terminal `error` event.

A failed packet scan attaches its partial evidence under `error.scan`
([`Failure`][scan-output] from [`PipelineFailure`][scan-error]):

| Field | Role |
| --- | --- |
| `stats` | Metadata: execution accounting up to the failure. |
| `pending[].sent` | Metadata: each confirmed transmission still awaiting attribution (a `probe_sent`-shaped record). |
| `pending[].response` | Metadata: a captured response for that probe that was not yet attributed, if one was retained. |
| `failed_probe` | Metadata: the probe coordinates (`sequence`, `destination`, `destination_port`, `transport`, `attempt`) at which execution failed. |
| `capture_sources[]` | Metadata: per-source capture state — `interface` (`name`, `index`), `ready`, `shutdown_confirmed`, `statistics_valid`, `statistics` — recording how much evidence the failure preserved. |

Error codes keep failure kinds distinct from observations: authorization and
policy failures report `policy.*`/`capability.*` codes, backend and socket
failures `io.*`, and incoherent evidence `internal.*`. A socket call that
timed out (`timed_out`) or an attempt whose deadline expired
(`deadline_expired`) stays an attempt outcome; the operation deadline
(`policy.scan_duration_limit`) and cancellation (`io.cancelled`) are
operational failures and are never written as `timeout` observations.

## v7 scopes, target lists, and retention charges

`packetcraftr.output/v7` carries every v6 meaning unchanged and adds two
published shapes. A `scope` object (`zone` declaration text plus the resolved
`interface` identity) can appear on scan and connect probes, endpoints, sent
evidence, and `error.scan` failure records; it is part of target identity —
the same address on different interfaces is a different target — not a fifth
claim vocabulary. `retained_evidence_bytes` on the raw scan aggregate and
`complete`, connect `socket_stats`, and the traceroute report is an
accounting field: the exact retained wire-frame bytes (raw, traceroute) or
per-probe struct plus error-string charge (connect), not classification
evidence.

`scan --list` publishes `method: "target_list"` records: aggregate results
and `target` stream records carry each selected `address`, optional `scope`,
and every `origins` entry (`index`, `source`, and manifest `line`), plus
`duplicates` and `resolution_performed`. `resolution_performed: true` means
DNS resolution ran during planning and may have sent traffic; it is
operational metadata, not a port-state claim.

## Host observations and port inference

Neither vocabulary has a producer yet. The layers exist in the model so that
[M5][m5] host records and [M6][m6] inferred port states add fields in their
own shapes — with their own enums in a new output family for inference —
instead of re-encoding `classification`, `responder`, or `reason` values that
already mean attempt outcomes.

[compatibility]: consumer-compatibility.md
[connect-engine]: ../crates/packetcraftr/src/scan/connect/engine.rs
[connect-output]: ../crates/packetcraftr-cli/src/output/scan/connect.rs
[connect-report]: ../crates/packetcraftr/src/scan/connect/report.rs
[correlation]: ../crates/packetcraftr/src/correlation.rs
[m1]: roadmap/m01-claims-evidence.md
[m5]: roadmap/m05-host-discovery.md
[m6]: roadmap/m06-port-planning-inference.md
[scan-engine]: ../crates/packetcraftr/src/scan/engine.rs
[scan-error]: ../crates/packetcraftr/src/scan/error.rs
[scan-evidence]: ../crates/packetcraftr/src/scan/evidence.rs
[scan-output]: ../crates/packetcraftr-cli/src/output/scan.rs
[scan-report]: ../crates/packetcraftr/src/scan/report.rs
[udp-document]: ../crates/packetcraftr-core/src/document/udp_profiles.rs
