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
  endpoint's attempts, together with the rule that produced it. Output/v8
  publishes it as each endpoint's `inference` ([port inference](#port-inference)).
  Conflicting attempts remain visible beside it.
- **Host observations.** Evidence that a host answered, by which probe, and
  whether the evidence is direct, a cached neighbor entry, or a possible proxy
  reply. Output/v9 publishes one host record per target
  ([host observations](#host-observations)).
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
| `stage` | Metadata: `discovery` or `scan`; both stages share one sequence space. |
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
| `stage` | Metadata: `discovery` or `scan`, as for packet attempts. |
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

Each `endpoints[]` record groups the attempts for one
`(address, transport, port)` (packet scan) or socket address (connect scan) under `address`, `transport`, `port`,
and `probes` — all coordinate metadata — plus one `classification`.

That endpoint `classification` is the **highest-ranked attempt outcome** the
endpoint collected, under the fixed order
`open > closed > filtered > unreachable > unknown > timeout`
([`Classification::rank`][scan-report], applied by `promote`). It is a legacy
convenience aggregate over attempt observations. It is **not** the port
inference vocabulary: it has no scan-method semantics, carries no inference
rule, and must not be read as one. Scan-dependent inferred states publish
beside it as `inference` in output/v8, per the
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
| `failed_probe` | Metadata: the probe coordinates (`sequence`, `stage`, `destination`, `destination_port`, `transport`, `attempt`) at which execution failed. |
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

## v8 port planning and inference

`packetcraftr.output/v8` ([M6][m6]) carries every v7 meaning unchanged and adds:

| Field | Role |
| --- | --- |
| `plan.method` | Metadata: the `requested` and `selected` scan method, and the `reason` automatic selection chose it. An explicit method is never replaced. |
| `plan.port_catalog` | Metadata: the catalog data set and version that names, presets, and hints came from. |
| `plan.excluded_endpoints` | Metadata: endpoints removed by `--exclude-ports` after expansion and before planning. |
| `plan.curated_udp_payloads` | Metadata: the curated payload data set and version, and the UDP ports where it was `applied` or `overridden` by an operator profile. |
| `endpoints[].port_hint` | Metadata: the catalog name for the endpoint's transport and port. It is a hint, not service identification. |
| `endpoints[].inference` | Port inference: the [inferred state](#port-inference). |
| `unattributed[]` | Attempt observation: a correlated frame no attempt outcome carries (`late`, `duplicate`, or `ambiguous`), with the probe `sequence` when one probe is implicated. |
| `endpoint` / `connect_endpoint` events | Metadata: the endpoint aggregate and inference, naming its probe sequences instead of repeating the attempts. |
| `ports` (target list) | Metadata: the exact expanded endpoints a scan of the selection would probe. |

Unattributed frames share the `--max-undecoded` count and the evidence frame
and byte budgets with undecodable frames; the first one omitted warns
`scan.unattributed_limit`. A duplicate is the losing reply for a probe that
also has a winning one, a late reply arrived after its probe's window or
outcome, and an ambiguous reply correlates with more than one probe. None
changes an attempt outcome or an inference.

## Port inference

An inference concludes one endpoint's state from all of its attempts. It is
published beside, never instead of, the attempts' own outcomes. Each attempt
maps to one rule by the scan method; the highest-ranked rule decides the
`state`, and the earliest attempt wins a tie, so delivery order never changes
the conclusion. Every attempt's probe sequence then lands in exactly one list:

- `supporting`: its own rule concludes the decided state;
- `unanswered`: it was silent and silence concludes a different state;
- `conflicting`: its reply concludes a different state; or
- `failed`: an operational failure, which concludes no state.

| Rank | TCP SYN (raw TCP) | UDP (raw UDP) | TCP connect |
| --- | --- | --- | --- |
| 6 | `tcp_syn.syn_ack` → `open` | `udp.reply` → `open` | `tcp_connect.connected` → `open` |
| 5 | `tcp_syn.reset` → `closed` | `udp.port_unreachable` → `closed` | `tcp_connect.refused` → `closed` |
| 4 | `tcp_syn.icmp_unreachable` (any destination unreachable) → `filtered` | `udp.icmp_unreachable` (administratively prohibited or other unreachable) → `filtered` | `tcp_connect.unreachable` → `filtered` |
| 3 | `tcp_syn.time_exceeded` → `filtered` | `udp.time_exceeded` → `filtered` | — |
| 2 | `tcp_syn.unclassified_reply` (other TCP, UDP, or echo reply) → `unknown` | `udp.unclassified_reply` (TCP or echo reply) → `unknown` | — |
| 1 | `tcp_syn.silence` → `filtered` | `udp.silence` → `open_or_filtered` | `tcp_connect.timed_out` → `filtered` |
| 0 | — | — | `local_error` or `deadline_expired` → no state, rule `operational_failure` |

The rule is scan-dependent where the attempt vocabulary is not. An ICMP port
unreachable is a `closed` attempt classification for both transports, but it
infers `closed` only for UDP; for a TCP SYN it means a device refused on the
port's behalf, so the inference is `filtered`. A silent UDP port stays
`open_or_filtered` until a reply or ICMP error decides it, and a silent
attempt beside a decisive reply is `unanswered`, not a conflict. ICMP echo
endpoints are portless and carry no inference. When every attempt failed
operationally, `state` is absent and the rule is `operational_failure`: a
socket deadline or exhausted local capacity is never a port state. A
connect scan retries a connection the socket provider has no capacity to admit
instead of recording it.

PacketcraftR's labels map to Nmap's for comparison only:

| PacketcraftR | Nmap |
| --- | --- |
| `open`, `closed`, `filtered` | the same names |
| `open_or_filtered` | `open\|filtered` |
| `unknown` | no equivalent label |
| state absent (`operational_failure`) | no equivalent label |

PacketcraftR has no `unfiltered` label, which needs an ACK or window scan
([M12][m12]), and no `closed|filtered`, which is idle-scan specific.

## Host observations

[M5][m5] host discovery publishes one record per selected target, in selection
order: `hosts[]` in raw scan results and connect reports, and a `host` stream
record before `complete` ([library][discovery-host], [output][host-output]).
Host records use their own fields instead of re-encoding the attempt
`classification`, `responder`, or `reason` of the discovery probes they cite.

| Field | Role |
| --- | --- |
| `discovery` | Host observation: `responded` when at least one reason exists, `no_response` when discovery ran and none does, `not_requested` when the request omitted discovery, and `skipped` when it skipped discovery explicitly. |
| `scan` | Metadata: `scanned`, `skipped` (discovery found no response and the request left such hosts out), or `not_requested` (discovery-only). |
| `reasons[]` | Host observation: why the host counts as responded. |
| `reasons[].kind` | The reply behind the reason: a discovery probe's typed reply (`icmp_echo_reply`, `tcp_syn_ack`, `tcp_reset`, `udp_payload`, `icmp_port_unreachable`, and the other attempt replies), `tcp_connected` or `tcp_refused` from an ordinary socket, or `neighbor_reply` or `neighbor_cache`. |
| `reasons[].evidence` | `wire` for a captured reply, `socket` for an operating-system connect result, and `cache` for a neighbor cache entry. |
| `reasons[].basis` | `direct` for the host's own answer, `cached` for a neighbor cache entry an earlier reply left, and `possible_proxy` for a link address that also answered for another address of the same family, as a target or as a gateway. |
| `reasons[].probe`, `link_address`, `observed_at` | Metadata: the discovery probe sequence or the neighbor link address the reason rests on, and when it was observed. |
| `neighbor` | Host observation: the explicit ARP or NDP outcome (`resolved`, `silent`, `routed`, or `not_applicable`), the request `attempts`, the host's `link` when resolved, and the `next_hop` when routed. A link `entry` is `fresh` or `cached`. |
| `reverse_dns` | Enrichment observation: the PTR question, its status and outcome, and the `names` the server answered. |
| `probes` | Metadata: the discovery probes, embedded in JSON and listed by sequence in `host` stream records. |

The record keeps these rules:

- A reason needs a reply from the target itself. A discovery probe's reply
  from another responder, such as a router's ICMP error, is kept on the probe
  but gives the host no reason.
- A TCP reset, an ICMP port unreachable from the host, and a refused
  connection are host responsiveness even though the port is closed.
- `no_response` means the host stayed silent to every selected discovery
  probe within its budget. It is uncertain, never absent.
- `not_requested` and `skipped` are labels, not measurements.
- A routed target is sent no neighbor request. Its gateway appears under
  `neighbor.next_hop`, with a link address only when the neighbor cache
  already holds one, and never as the target's link or a reason. A target whose own neighbor reply carries the same link address
  as another address of the same family, whether a target or a next hop, is
  flagged `possible_proxy`; PacketcraftR does not assert a cause. A dual-stack
  host answering for one IPv4 and one IPv6 address, or a gateway that is
  itself a target, stays `direct`.
- Ordinary-socket discovery (`--connect`) publishes `socket` evidence only.
  The operating system reports the endpoint's own answer; which device sent it
  is not observable through a socket.
- Reverse names and link addresses are observations. They are never
  authenticated identity, and no vendor label is published until a vendor
  data set has a provenance record under the [data policy][data-policy].

Every discovery probe carries `stage: "discovery"` and every scan probe
`stage: "scan"` in one sequence space. Endpoints and their `counts` hold only
scan-stage probes; discovery probes appear only in host records.

[compatibility]: consumer-compatibility.md
[connect-engine]: ../crates/packetcraftr/src/scan/connect/engine.rs
[connect-output]: ../crates/packetcraftr-cli/src/output/scan/connect.rs
[connect-report]: ../crates/packetcraftr/src/scan/connect/report.rs
[correlation]: ../crates/packetcraftr/src/correlation.rs
[data-policy]: scanner-data-policy.md
[discovery-host]: ../crates/packetcraftr/src/scan/discovery/host.rs
[host-output]: ../crates/packetcraftr-cli/src/output/scan/host.rs
[m1]: roadmap/m01-claims-evidence.md
[m5]: roadmap/m05-host-discovery.md
[m6]: roadmap/m06-port-planning-inference.md
[m12]: roadmap/m12-tcp-diagnostic-scans.md
[scan-engine]: ../crates/packetcraftr/src/scan/engine.rs
[scan-error]: ../crates/packetcraftr/src/scan/error.rs
[scan-evidence]: ../crates/packetcraftr/src/scan/evidence.rs
[scan-output]: ../crates/packetcraftr-cli/src/output/scan.rs
[scan-report]: ../crates/packetcraftr/src/scan/report.rs
[udp-document]: ../crates/packetcraftr-core/src/document/udp_profiles.rs
