# Scanner evidence and claims model

Four vocabularies stay distinct: **attempt observations**, **method-dependent
port inference**, **host observations**, and **operational failures**. Coordinates,
timing, routes, capture state, and accounting support them; none independently
proves identity. This guide defines meanings; the [consumer policy](consumer-compatibility.md)
owns versioned shapes and the [roadmap](roadmap/README.md) owns acceptance.

## Attempt observations

### Packet scan attempts (`scan` events and `endpoints[].probes[]`)

A probe records operation-local sequence, discovery/scan stage, endpoint/transport,
retry ordinal, submission/ingress time, and optional retained frame/application
check. Status response requires a checksum-valid protocol-consistent uniquely
attributed reply in its window; otherwise timeout. Responder is the actual
answering address, not necessarily destination. Reason/classification describe
that attempt, not service identity or aggregate inference:

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

Checksum failures produce no observation. Undecodable captures remain undecoded;
unsolicited/nonunique, late, duplicate, and ambiguous replies cannot overwrite
a timeout or count as an in-window received response.

### Connect scan attempts (`connect_probe` events and `endpoints[].probes[]`)

Connect evidence has numeric address/port, sequence/stage/attempt, attempted,
connect_succeeded (null without timely result), timing, local socket, and optional
error kind/OS code/message. `method` is tcp_connect, never wire capture.
`attempted=false` creates no network claim.

| Outcome | Observation / legacy classification |
| --- | --- |
| connected | Handshake completed with matching peer / open |
| refused | ConnectionRefused / closed |
| timed_out | Socket call TimedOut, including provider timeout / timeout |
| unreachable | NetworkUnreachable or HostUnreachable / unreachable |
| local_error | Other I/O error, including provider Interrupted / unknown |
| deadline_expired | Attempt elapsed/cancelled without timely result, or returned too late / timeout |

Socket timeout and attempt deadline are distinct. Operation deadline/cancellation
are operational errors, not these outcomes.

### Application checks on attempts

| UDP profile status | Meaning |
| --- | --- |
| not_observed | No correctly addressed UDP application reply |
| unchecked | Reply observed; no configured response checks |
| confirmed | Configured DNS/header/question or bounded byte checks matched |
| rejected | Reply observed; configured checks did not match |

Profile/reason identifies the check. Confirmation is not authentication or
identification; rejection is not a service verdict.

## The endpoint aggregate is not port inference

Endpoint identity is address/transport/port/resolved scope. Legacy classification
chooses the highest-ranked attempt: open > closed > filtered > unreachable >
unknown > timeout. Counts tally endpoint winners, not attempts. This deterministic
summary must not be substituted for the separate method-dependent inference.

## Transmission and capture metadata

`probe_sent` confirms native acceptance of the exact reported frame and
materialized route/neighbor evidence; it proves neither wire departure nor target
receipt. Undecoded frames preserve timestamp/length/link/interface/direction/bytes;
diagnostics qualify integrity. Times retain second/nanosecond pairs; durations
and counters use documented nonnegative units without inferred clock sync.

RTT sent counts confirmed transmissions; received counts attributed in-window
replies; lost=sent−received includes backend loss. Execution/capture counters report
attempted/completed packets, bytes, queue/receiver drops, and overflow. Connect
socket and PTR stats remain distinct. Unavailable/zero drop counters do not prove
complete acquisition.

### Successful native submission intervals

`transmit::Timing::freshness_marker()` starts successful exact-byte native
submission; `completed()` marks acceptance return. Socket setup precedes the
start. Matching captures inside the interval are eligible subject to integrity,
identity, ingress, and deadline checks. Missing monotonic ingress or older captures
are ineligible. Neither marker proves exact wire time, causality, or host identity;
latency includes submission time.

## Operational failures

Policy, capability, budget, operation-deadline, and cancellation failures use error
envelopes/terminal errors, never network/host observations. `policy.*`/
`capability.*`, `io.*`, and `internal.*` retain different classifications/sources.
A socket TimedOut or attempt deadline is not policy.scan_duration_limit or
io.cancelled.

Partial `error.scan` keeps execution stats, pending confirmed sends/possible
responses, failed-probe coordinates/stage, and each capture source's readiness,
shutdown confirmation, statistics validity/counters. Failure never erases prior
accepted evidence or implies absent traffic.

## v7 scopes, target lists, and retention charges

Declared zone/resolved interface scope is target identity, not another claim
vocabulary. Same address on different interfaces is distinct. Target-list records
retain address/scope, every declaration origin/index/line, duplicates, and
resolution_performed. Listing sends no target/neighbor packets; authorized hostname
resolution is not network-free.
Retained_evidence_bytes charges exact retained wire bytes for raw/trace and probe
structures/error strings for connect, not classification, total allocation, or RSS.
These v7 additions persist in current v15.

## v8 port planning and inference

Plans publish requested/selected method, automatic reason, catalog/version,
exclusions, and curated UDP applied/overridden ports. Port hints are names, not
identification. Explicit raw/connect methods never fall back; automatic selection
reads build capture/transmit capability, not runtime privilege. Typed mixed
TCP/UDP endpoints share operation budgets and preserve transport identity.
Late/duplicate/ambiguous frames are unattributed evidence. List mode may publish
ports. These v8 additions persist in current v15.

## Port inference

Inference uses all attempts beside their original outcomes. Highest-ranked rule
wins; earliest attempt breaks a tie, independent of delivery order. Every sequence
belongs to exactly one partition: supporting (same concluded state), unanswered
(silence concluding another state), conflicting (reply concluding another state),
or failed (operational, no state).

| Rank | TCP SYN (raw TCP) | UDP (raw UDP) | TCP connect |
| --- | --- | --- | --- |
| 6 | `tcp_syn.syn_ack` → `open` | `udp.reply` → `open` | `tcp_connect.connected` → `open` |
| 5 | `tcp_syn.reset` → `closed` | `udp.port_unreachable` → `closed` | `tcp_connect.refused` → `closed` |
| 4 | `tcp_syn.icmp_unreachable` (any destination unreachable) → `filtered` | `udp.icmp_unreachable` (administratively prohibited or other unreachable) → `filtered` | `tcp_connect.unreachable` → `filtered` |
| 3 | `tcp_syn.time_exceeded` → `filtered` | `udp.time_exceeded` → `filtered` | — |
| 2 | `tcp_syn.unclassified_reply` (other TCP, UDP, or echo reply) → `unknown` | `udp.unclassified_reply` (TCP or echo reply) → `unknown` | — |
| 1 | `tcp_syn.silence` → `filtered` | `udp.silence` → `open_or_filtered` | `tcp_connect.timed_out` → `filtered` |
| 0 | — | — | `local_error` or `deadline_expired` → no state, rule `operational_failure` |

TCP diagnostic modes (v15) use the same ranks (reset 5, ICMP unreachable 4, time
exceeded 3, other reply 2, silence 1) and the same partitions. Rule IDs are
`tcp_<mode>.<reason>`; every state is a stack-dependent heuristic:

| Mode | reset | ICMP unreachable | time exceeded / other reply | silence |
| --- | --- | --- | --- | --- |
| `tcp_ack` | `unfiltered` | `filtered` | `unknown` | `filtered` |
| `tcp_window` | `reset_nonzero` → `open`; `reset_zero` → `closed`; no window → `unknown` | `filtered` | `unknown` | `filtered` |
| `tcp_fin`, `tcp_null`, `tcp_xmas`, `tcp_maimon` | `closed` | `filtered` | `unknown` | `open_or_filtered` |
| `tcp_custom` | `tcp_custom.reply` → `unknown` for any TCP or ICMP reply | | | `tcp_custom.silence` → `unknown` |

Which response decides among replies to one probe is ranked separately from the
attempt classification: reset 5, correlated ICMP unreachable 4, time exceeded 3,
other direct segment 2, so a valid reset is never displaced by router evidence
received in the same window. Attempt classification stays separate: a direct TCP
reply to an ACK, window, or custom probe (reset, SYN/ACK, or other segment), and
any SYN/ACK or other TCP segment answering a diagnostic probe, is `unknown`; a
FIN-family reset is `closed`; correlated ICMP keeps its classification
(administratively prohibited `filtered`, other destination unreachable
`unreachable`, time exceeded `filtered`) except that port-unreachable is
`unreachable` for every diagnostic mode; silence is `timeout`. A custom probe's
`unknown` for any reply is an inference, not an attempt classification.
Contradictory windows across attempts keep the earliest, rank-tied attempt and
report the other as conflicting. Operational failures never imply a state. Window
and FIN-family conclusions differ by operating system and middlebox and are not
reliable open/closed detection.

For the original SYN and UDP probes, a port-unreachable classification is closed, but SYN
inference is filtered while UDP inference is closed. Silent UDP infers
open_or_filtered; beside a decisive reply, silence is unanswered, not conflict.
Echo is portless with no inference. Operational-only attempts have absent state
under operational_failure. Connect capacity backpressures, never invents a state.

| PacketcraftR | Nmap comparison only |
| --- | --- |
| open / closed / filtered | Same names |
| open_or_filtered | open\|filtered |
| unknown / absent operational state | No equivalent |

`unfiltered` is the ACK-scan conclusion (a correlated reset); it is never open.
See [TCP diagnostics](tcp-diagnostics.md) and
[M12](roadmap/m12-tcp-diagnostic-scans.md); idle-specific closed|filtered is
outside scope.

## Host observations

Discovery publishes host-order hosts/host records separately from attempt fields.

| Field | Meaning |
| --- | --- |
| discovery | responded with a reason; uncertain no_response; not_requested; explicitly skipped |
| scan | scanned, discovery-based skipped, adaptive incomplete, discovery-only not_requested |
| reasons | Reply kind with wire/socket/cache evidence and direct/cached/possible_proxy basis |
| probe / link_address / observed_at | Supporting sequence/link/time; unknown capture time stays absent |
| neighbor | resolved/silent/routed/not_applicable, selected interface, attempts/time, fresh/cached link or gateway next_hop |
| reverse_dns | PTR status/outcome/names, with names_truncated under shared evidence limit |
| probes | Embedded discovery probes in JSON; their sequences in stream records |

Only target-sourced replies give host reasons. Routers' errors stay on probes;
closed-port resets, refusals, and target port-unreachable can prove responsiveness.
Silence is uncertain; not_requested/skipped are not measurements. Sockets expose
endpoint results, not the answering device.

Routed targets send no target neighbor request. Cached gateway link is next_hop,
not target identity/reason; any needed active gateway resolution is independently
authorized and charged. Same-family addresses sharing a link/interface within
one request may be possible_proxy; cause is unknown. IPv4+IPv6 on one host and
a gateway also selected as target do not alone imply proxying. PTR/MAC observations
are unauthenticated; no unreviewed vendor label is attached.

## Scheduling summary

Required scheduling describes fixed/adaptive mode, effective config, peak pending
window, actual retries, typed conditions, incomplete host identities, and connect
operation/process ceilings. Configured/observed concurrency is not throughput.
Unsent/omitted entries count neither as starts nor completions/network outcomes.
Preparation, pacing, callbacks, and transmission spend adaptive host deadlines.

Suspected_response_rate_limit cites host/responder/counts/control+loss sequences;
filtering or ordinary loss remain alternatives and classifications never change.
Discovery/scan share a sequence space; endpoints/counts cover scan only.
[M7](roadmap/m07-adaptive-scheduling.md) owns controller constants and measurements.

## Traceroute stage

Raw-only scan --traceroute traces host-order results after scan, before PTR, under
remaining policy/duration/evidence budgets. Connect/list refuse upfront. Standalone
trace keeps its shapes; trace probes remain attempt observations.

Selection prefers target SYN/ACK, reset, then echo (lowest sequence tie). Router
errors never select; UDP requires explicit strategy because ports change. Missing
observation/fallback or scoped targets are not_traced, without invented probe.
Status complete/incomplete and destination_reached/unreachable/maximum_hops/timeout
summarize actual probes; silent hop is timeout, not absent or unreachable host.

Fresh hops are this host's observations. Reused_hops cite source host/probes/
responders/time/age within operation/max_age, never a new probe. Reconvergence/
ECMP can make reuse wrong. Stream host records follow their probes.
Remaining response/undecoded/unattributed retention is deducted before trace I/O;
insufficient limits may fail after scan. No traceable host deducts nothing.
TCP/UDP trace defaults source 49151, separate from generated scan UDP ports.
Finalized collection validates before scan; neighbour/pacing timing needs allowance.
See [M11 limits and open acceptance](roadmap/m11-scan-informed-traceroute.md).

## OS fingerprint evidence

Standalone `identify-os`, introduced in output/v14 and retained in current v15,
emits observations separately from qualified OS-family candidates. Open/closed prerequisites, omitted responses, contradictions,
late/unrelated captures, and evidence exhaustion remain explicit. Router errors
cannot establish target identity. Candidate provenance cites the independently
versioned original corpus/signature and supporting observation indices.
`qualified` is ordinal; release identity, authenticated identity, probability,
and inferred initial TTL are not supported. `complete` describes execution and
retention; inconclusive suitability can be complete. See
[OS identification](os-identification.md) and
[preserved M10 evidence](roadmap/evidence/m10/README.md).
