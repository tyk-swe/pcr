# Scanner evidence and claims model

Four vocabularies stay distinct: **attempt observations**, **method-dependent
port inference**, **host observations**, and **operational failures**. Coordinates,
timing, routes, capture state, and accounting support them; none independently
proves identity. The [consumer policy](consumer-compatibility.md) owns versioned
shapes and [native validation](native-validation.md) owns runtime verification.

## Attempt observations

### Packet scan attempts (`scan` events and `endpoints[].probes[]`)

A probe records operation-local sequence, discovery/scan stage, endpoint/transport,
retry ordinal, submission/ingress time, and optional retained frame or application
check. `response` requires a checksum-valid, protocol-consistent, uniquely
attributed reply within its window; otherwise `timeout`.

| Correlated response | `classification` | `reason` |
| --- | --- | --- |
| TCP RST from the endpoint | `closed` | `correlated TCP reset` |
| TCP SYN/ACK acknowledging `sequence + 1` | `open` | `correlated TCP SYN/ACK` |
| Other TCP flags from the endpoint | `unknown` | `correlated TCP response with inconclusive flags` |
| UDP reply reversing the transport tuple | `open` | `correlated UDP response from the requested endpoint` |
| SCTP INIT ACK matching the initiate tag | `open` (`unknown` for `cookie_echo`) | `correlated SCTP INIT ACK` |
| SCTP ABORT matching the verification tag | `closed` | `correlated SCTP ABORT` |
| Other SCTP chunk matching the verification tag | `unknown` | `correlated SCTP response with inconclusive chunk` |
| ICMP echo / timestamp / address mask reply | `open` | `correlated ICMP echo reply` / `correlated ICMP timestamp reply` / `correlated ICMP address mask reply` |
| Direct IP-protocol response matching protocol number | `open` | `correlated IP protocol response` |
| ICMP port unreachable quoting the probe | `closed` (`unreachable` for TCP/SCTP diagnostics) | `ICMPv4 port unreachable` / `ICMPv6 port unreachable` |
| ICMP protocol unreachable / unrecognized next header quoting the probe | `closed` (`unreachable` for SCTP `cookie_echo`) | `ICMPv4 protocol unreachable` / `ICMPv6 unrecognized next header` |
| ICMP administratively prohibited | `filtered` | `ICMPv4 administratively prohibited` / `ICMPv6 policy or administrative rejection` |
| ICMP destination unreachable | `unreachable` | `ICMPv4 destination unreachable` / `ICMPv6 destination unreachable` |
| ICMP time exceeded before the endpoint | `filtered` | `ICMPv4 time exceeded before reaching the endpoint` / `ICMPv6 time exceeded before reaching the endpoint` |
| No valid response inside the window | `timeout` | `no checksum-valid, protocol-consistent response before the deadline` |

Checksum failures produce no observation. Undecodable, unsolicited, late,
duplicate, and ambiguous replies stay unattributed and never overwrite a timeout.

Direct IP-protocol replies carry no attempt identifier. Bounded transmission
history for each interface, address pair, and protocol lasts until the operation
ends. A reply compatible with an earlier transmission stays unattributed even
after its packet evidence is evicted, across serial execution, adaptive waves,
and discovery-to-scan transitions. Quoted ICMP errors retain their independent
header identity and can still provide an attributable outcome.

### Connect scan attempts (`connect_probe` events and `endpoints[].probes[]`)

Connect evidence (`method: tcp_connect`) records socket outcomes rather than wire
capture; `attempted=false` creates no network claim.

| Outcome | Observation / legacy classification |
| --- | --- |
| `connected` | Handshake completed with matching peer / `open` |
| `refused` | `ConnectionRefused` / `closed` |
| `timed_out` | Socket call `TimedOut` / `timeout` |
| `unreachable` | `NetworkUnreachable` or `HostUnreachable` / `unreachable` |
| `local_error` | Other I/O error / `unknown` |
| `deadline_expired` | Attempt elapsed/cancelled without timely result / `timeout` |

`deadline_expired` and `local_error` are unavailable observations for adaptive
control and port inference. They do not count as transport silence or trigger
remote-loss backoff. A socket `timed_out` result remains transport silence.

Raw no-reply events carry typed acquisition coverage. A pipeline publishes
`pending` silence while capture remains active, then publishes an
`observation_quality` qualification for its stage and inclusive sequence
interval after shutdown. A terminal error leaves provisional negatives unusable
for inference. Aggregate collectors apply qualification only to pending no-reply
measurements before port inference; final unknown/incomplete coverage stays.
Only `no_reported_loss` supports raw silence rules. A local host ceiling that
shortens an attempt leaves its no-reply coverage unknown and the host incomplete.
Permissive overflow marks
negative observations `incomplete`; custom providers default to `unknown` even
with zero counters. Both enter inference's `failed` partition. Positive uniquely
correlated replies remain valid. Default overflow `Fail` rejects incomplete
runs. Local counters do not prove end-to-end visibility or identify which
response was lost. See [scan measurement contract](consumer-compatibility.md#scan-measurements-and-acquisition-quality).

### Application checks on attempts

| UDP profile status | Meaning |
| --- | --- |
| `not_observed` | No correctly addressed UDP application reply |
| `unchecked` | Reply observed; no configured response checks |
| `confirmed` | Configured DNS or bounded byte checks matched (not service identification) |
| `rejected` | Reply observed; configured checks did not match |

## Endpoint aggregate, timing, and operational failures

- **Endpoint aggregate vs. inference:** Endpoint identity is address, transport,
  port, and resolved scope. Legacy `classification` selects `open > closed >
  filtered > unreachable > unknown > timeout` and is separate from
  [port inference](#port-inference).
- **Transmission and capture timing:** `probe_sent` confirms native acceptance,
  not wire departure or receipt. `transmit::Timing::freshness_marker()` marks
  submission start (after socket setup) and `completed()` marks acceptance
  return; replies captured inside that interval with valid monotonic ingress are
  eligible. RTT partitions `sent = received + lost + unavailable`: `lost` counts only
  qualified no-reply intervals, and `unavailable` covers local failures or
  insufficient acquisition quality. Neither metric identifies a remote cause.
  `retained_evidence_bytes` charges retained wire bytes (raw/trace) or probe
  structures/error strings (connect), not RSS.
- **Operational failures:** Policy, capability, budget, operation-deadline, and
  cancellation failures emit error envelopes/terminals (`policy.*`, `capability.*`,
  `io.*`, `internal.*`), never host or port observations. Partial `error.scan`
  retains execution stats, pending confirmed sends, and per-interface capture state.

## Port inference

Highest-ranked rule wins; earliest attempt breaks ties regardless of delivery
order. Every sequence belongs to one disjoint partition: `supporting` (same
concluded state), `unanswered` (silence concluding another state), `conflicting`
(reply concluding another state), or `failed` (operational, no state).

| Rank | TCP SYN (raw TCP) | UDP (raw UDP) | TCP connect |
| --- | --- | --- | --- |
| 6 | `tcp_syn.syn_ack` → `open` | `udp.reply` → `open` | `tcp_connect.connected` → `open` |
| 5 | `tcp_syn.reset` → `closed` | `udp.port_unreachable` → `closed` | `tcp_connect.refused` → `closed` |
| 4 | `tcp_syn.icmp_unreachable` → `filtered` | `udp.icmp_unreachable` → `filtered` | `tcp_connect.unreachable` → `filtered` |
| 3 | `tcp_syn.time_exceeded` → `filtered` | `udp.time_exceeded` → `filtered` | — |
| 2 | `tcp_syn.unclassified_reply` → `unknown` | `udp.unclassified_reply` → `unknown` | — |
| 1 | `tcp_syn.silence` → `filtered` | `udp.silence` → `open_or_filtered` | `tcp_connect.timed_out` → `filtered` |
| 0 | — | — | `local_error` / `deadline_expired` → no state (`operational_failure`) |

TCP diagnostic modes use the same ranks (reset 5, ICMP unreachable 4, time
exceeded 3, other reply 2, silence 1) with rule IDs `tcp_<mode>.<reason>`:

| Mode | reset | ICMP unreachable | time exceeded / other reply | silence |
| --- | --- | --- | --- | --- |
| `tcp_ack` | `unfiltered` | `filtered` | `unknown` | `filtered` |
| `tcp_window` | `reset_nonzero` → `open`; `reset_zero` → `closed`; no window → `unknown` | `filtered` | `unknown` | `filtered` |
| `tcp_fin`, `tcp_null`, `tcp_xmas`, `tcp_maimon` | `closed` | `filtered` | `unknown` | `open_or_filtered` |
| `tcp_custom` | `tcp_custom.reply` → `unknown` (any TCP/ICMP reply) | | | `tcp_custom.silence` → `unknown` |

SCTP (`init` and `cookie_echo`) and IP-protocol (`ip`) modes use the same
ranking order:

| Mode | Direct positive reply | ABORT / protocol unreachable | ICMP unreachable | Time exceeded | Other reply | Silence |
| --- | --- | --- | --- | --- | --- | --- |
| `sctp_init` | `sctp_init.init_ack` → `open` | `sctp_init.abort` → `closed` | `sctp_init.icmp_unreachable` → `filtered` | `sctp_init.time_exceeded` → `filtered` | `sctp_init.unclassified_reply` → `unknown` | `sctp_init.silence` → `filtered` |
| `sctp_cookie_echo` | `sctp_cookie_echo.unclassified_reply` → `unknown` | `sctp_cookie_echo.abort` → `closed` | `sctp_cookie_echo.icmp_unreachable` → `filtered` | `sctp_cookie_echo.time_exceeded` → `unknown` | `sctp_cookie_echo.unclassified_reply` → `unknown` | `sctp_cookie_echo.silence` → `open_or_filtered` |
| `ip_protocol` | `ip_protocol.reply` → `open` | `ip_protocol.protocol_unreachable` → `closed` | `ip_protocol.icmp_unreachable` → `filtered` | `ip_protocol.time_exceeded` → `filtered` | `ip_protocol.unclassified_reply` → `unknown` | `ip_protocol.silence` → `open_or_filtered` |

For diagnostic probes, attempt classification is `closed` for FIN-family resets,
`unknown` for other direct TCP replies, `unreachable` for ICMP port-unreachable,
and `timeout` for silence. `unfiltered` (ACK reset) never means `open`. See
[TCP diagnostics](tcp-diagnostics.md).

| PacketcraftR | Nmap comparison only |
| --- | --- |
| `open` / `closed` / `filtered` / `unfiltered` | Same names |
| `open_or_filtered` | `open\|filtered` |
| `unknown` / absent operational state | No equivalent |

## Host observations

| Field | Meaning |
| --- | --- |
| `discovery` | `responded`, `no_response` (uncertain), `not_requested`, or `skipped` |
| `scan` | `scanned`, `skipped`, adaptive `incomplete`, or `not_requested` |
| `reasons` | Target-sourced reply kind with wire/socket/cache evidence and `direct`/`cached`/`possible_proxy` basis |
| `neighbor` | `resolved`/`silent`/`routed`/`not_applicable`, interface, attempts/time, fresh/cached link or gateway `next_hop` |
| `reverse_dns` | PTR status/outcome/names (`names_truncated` under shared evidence limit) |
| `probes` | Embedded discovery probes in JSON; probe sequences in stream records |

Only target-sourced replies (including closed-port resets, socket refusals, and
target port-unreachable) produce host reasons; router errors stay on probes, and
routed gateway MACs stay under `next_hop`. Same-family addresses sharing a link
address on one interface within a request report `possible_proxy`.

## Scheduling and traceroute stage

### Scheduling summary

`scheduling` reports fixed/adaptive mode, effective config, `observed_peak_window`,
`retries_started`, `suspected_response_rate_limit` conditions, `incomplete` hosts,
and connect ceilings. Unsent/omitted probes count as neither starts nor outcomes.

### Traceroute stage

Raw-only `network scan --traceroute` traces host-order results after scan and before PTR
under remaining budgets. Selection prefers target SYN/ACK, then reset, then echo
(lowest sequence tie), or explicit `--traceroute-strategy`/`--traceroute-port`
fallback; missing evidence or scoped targets report `not_traced`. Fresh `hops`
are observations; `reused_hops` cite source host/probes/time/age and are claims.

## OS fingerprint evidence

Standalone `identify-os` separates raw observations from qualified OS-family
candidates (`matched`, `ambiguous`, `unknown`, `inconclusive` with ordinal
`qualified` confidence). See [OS identification](os-identification.md).
