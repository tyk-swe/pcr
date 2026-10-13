# Scanner evidence and claims model

Four vocabularies stay distinct: **attempt observations**, **method-dependent
port inference**, **host observations**, and **operational failures**. Coordinates,
timing, routes, capture state, and accounting support them; none independently
proves identity. The [consumer policy](consumer-compatibility.md) owns versioned
shapes and the [roadmap](roadmap/README.md) owns acceptance.

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
| ICMP echo reply | `open` | `correlated ICMP echo reply` |
| ICMP port unreachable quoting the probe | `closed` | `ICMPv4 port unreachable` / `ICMPv6 port unreachable` |
| ICMP administratively prohibited | `filtered` | `ICMPv4 administratively prohibited` / `ICMPv6 policy or administrative rejection` |
| ICMP destination unreachable | `unreachable` | `ICMPv4 destination unreachable` / `ICMPv6 destination unreachable` |
| ICMP time exceeded before the endpoint | `filtered` | `ICMPv4 time exceeded before reaching the endpoint` / `ICMPv6 time exceeded before reaching the endpoint` |
| No valid response inside the window | `timeout` | `no checksum-valid, protocol-consistent response before the deadline` |

Checksum failures produce no observation. Undecodable, unsolicited, late,
duplicate, and ambiguous replies stay unattributed and never overwrite a timeout.

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
  eligible. RTT `lost = sent - received` includes backend loss.
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

TCP diagnostic modes (v15) use the same ranks (reset 5, ICMP unreachable 4, time
exceeded 3, other reply 2, silence 1) with rule IDs `tcp_<mode>.<reason>`:

| Mode | reset | ICMP unreachable | time exceeded / other reply | silence |
| --- | --- | --- | --- | --- |
| `tcp_ack` | `unfiltered` | `filtered` | `unknown` | `filtered` |
| `tcp_window` | `reset_nonzero` → `open`; `reset_zero` → `closed`; no window → `unknown` | `filtered` | `unknown` | `filtered` |
| `tcp_fin`, `tcp_null`, `tcp_xmas`, `tcp_maimon` | `closed` | `filtered` | `unknown` | `open_or_filtered` |
| `tcp_custom` | `tcp_custom.reply` → `unknown` (any TCP/ICMP reply) | | | `tcp_custom.silence` → `unknown` |

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
See [M7](roadmap/m07-adaptive-scheduling.md).

### Traceroute stage

Raw-only `scan --traceroute` traces host-order results after scan and before PTR
under remaining budgets. Selection prefers target SYN/ACK, then reset, then echo
(lowest sequence tie), or explicit `--traceroute-strategy`/`--traceroute-port`
fallback; missing evidence or scoped targets report `not_traced`. Fresh `hops`
are observations; `reused_hops` cite source host/probes/time/age and are claims.
See [M11](roadmap/m11-scan-informed-traceroute.md).

## OS fingerprint evidence

Standalone `identify-os` separates raw observations from qualified OS-family
candidates (`matched`, `ambiguous`, `unknown`, `inconclusive` with ordinal
`qualified` confidence). See [OS identification](os-identification.md).
