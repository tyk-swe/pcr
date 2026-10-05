# M5: Host discovery

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M4][m4] | [M10][m10], [M11][m11], [M13][m13] |

PacketcraftR can already send ICMP echo, TCP SYN, and UDP probes and open
ordinary TCP connections, and it resolves neighbors with bounded ARP and NDP
when it prepares a route. None of that is composed into an answer to "which of
these authorized hosts responded, and how do we know?". There is no discovery
stage, no host-level result, and a neighbor resolution for a gateway says
nothing about the host behind it.

This milestone adds a host-discovery workflow that composes the existing
building blocks and publishes host-level records in the
[M1][m1-vocabulary] host vocabulary.

## Outcome

- A discovery stage can run on its own, before a scan, or be explicitly
  skipped, and the output shows which happened.
- On the local link, ARP and NDP discover hosts directly.
- Configurable ICMP, TCP, and UDP probes are composed per host, with an
  ordinary-socket path when raw I/O is unavailable and explicitly selected.
- Each host has a record with its response reasons and the kind of evidence
  behind them.
- Reverse names and local-link MAC/vendor observations can be added under
  policy.

## Baseline

| | PacketcraftR at `22c7d182d577` | Nmap reference |
| --- | --- | --- |
| Discovery stage | [Scan transports][scan-args] include portless ICMP echo, SYN, UDP, and explicit connect probing; [scan planning][scan-engine] has no separate discovery stage or host-level composition | Discovery-only and skip-discovery controls with combined ICMP/TCP/UDP probes ([host discovery][nmap-discovery]) |
| Local link | [Neighbor resolution][neighbor-resolver] supplies bounded ARP/NDP for route preparation, with attempts, cache-hit, and captured frames in its [result][neighbor-model]; not a host inventory | ARP and neighbor discovery on local networks ([host discovery][nmap-discovery]) |
| Host record | [Scan reports][scan-report] expose resolved addresses and endpoint/probe evidence; no composed host record | Host state and reason ([reference guide][nmap-guide]) |
| Reverse names | A separate DNS workflow accepts reverse questions ([`dns/reverse.rs`][dns-reverse]); scan output has no reverse-name enrichment | Reverse DNS with resolver controls ([target specification][nmap-targets]) |
| MAC and vendor | Not published for scanned hosts | Local MAC and vendor context ([host discovery][nmap-discovery]) |

## Invariants

- Targets and the operation are authorized before any discovery packet,
  including ARP and NDP.
- Silence is an observation. A host that did not answer is not reported as
  absent.
- A gateway's neighbor reply is not a remote host reply, and a routed gateway's
  MAC address is not the target's identity.
- No hidden probes: every probe a discovery sends was selected by the request.

## Scope

### M5.1 Discovery workflow and controls

- A discovery stage with a discovery-only mode and an explicit skip-discovery
  mode.
- Discovery spends its own finite budget inside the operation's limits.
- When discovery is omitted or skipped, host records say so. A skipped host is
  not presented as measured reachable.

### M5.2 Local-link ARP and NDP discovery

- Host inventory for on-link targets, built on the neighbor resolver's bounded
  request, capture, and evidence handling.
- A fresh direct reply, a cached entry, and a next-hop resolution are distinct
  kinds of evidence.

### M5.3 ICMP, TCP, and UDP discovery probes

- Configurable ICMP echo, TCP, and UDP discovery probes, composed per host.
- A closed-but-responsive TCP endpoint counts as host responsiveness.
- An ordinary-socket path is available when raw I/O is unavailable and the
  request explicitly selects it. Its results are socket observations, not wire
  evidence.
- The additional probe families (ACK, ICMP timestamp/netmask, SCTP, and
  IP-protocol) belong to [M13][m13-discovery].

### M5.4 Host records and reasons

- A host-level record carrying response reasons, the probes that produced
  them, and timestamps.
- Each reason states whether it rests on direct host evidence, cached next-hop
  information, or a possible proxy reply.
- Hosts with no response keep an explicit uncertain state.

### M5.5 Reverse-DNS and MAC/vendor enrichment

- Optional reverse-name lookup, subject to the resolution policy and to finite
  budgets.
- Optional local-link MAC observation, with a vendor label when the vendor data
  set exists under the [M1 data policy][m1-data].
- Enrichment is labeled as observation or inference. Names and vendor labels
  are never authenticated identity.

## Change map

| Change | Start here |
| --- | --- |
| Discovery stage and composition | [`scan/engine.rs`][scan-engine], [`probe.rs`][probe] |
| ARP/NDP inventory | [`neighbor/resolver.rs`][neighbor-resolver], [`neighbor/cache.rs`][neighbor-cache], [`neighbor/model.rs`][neighbor-model] |
| Discovery probe packets | [`scan/plan/packet.rs`][scan-packets] |
| Ordinary-socket path | [`scan/connect/engine.rs`][connect-engine], netio [`tcp.rs`][tcp-provider] |
| Reverse names | [`dns/reverse.rs`][dns-reverse] |
| Interface and capture providers | netio [`interface.rs`][netio-interface], [`capture.rs`][netio-capture] |
| Host records | [`scan/report.rs`][scan-report], [`output/scan.rs`][scan-output] |

## Decisions to settle

1. Whether `scan` runs discovery by default (recommended: no; discovery runs
   only when selected and a scan without it labels hosts as not discovered, so
   no probe is hidden).
2. Whether discovery is a stage of the scan workflow or a separate workflow
   (recommended: a stage with a discovery-only mode, so one authorization and
   one budget cover both).
3. What a later stage does with a host that did not answer discovery
   (recommended: an explicit per-request choice, with the default and each
   skipped host visible in the output).
4. Whether reverse lookups use the system resolver or the existing DNS workflow
   (recommended: the DNS workflow, so each query is authorized, bounded, and
   evidenced like any other).
5. The vendor data source (recommended: settle under the
   [M1 data policy][m1-data]; ship MAC observation first and vendor labels only
   once the data set has a provenance record).
6. What evidence marks a reply as a possible proxy (recommended: publish the
   observed responder and link address and flag the cases the fixtures define,
   without asserting a cause).

## Exit criteria

- [ ] A closed-but-responsive TCP endpoint demonstrates host responsiveness in
      the fixtures.
- [ ] Silent and blocked hosts retain uncertainty and are never reported as
      absent.
- [ ] Discovery omission and skipping are visible in host records rather than
      represented as measured reachability.
- [ ] Cached next-hop information, proxy replies, and direct host evidence are
      distinct in host records, and no target identity is inferred from a
      routed gateway's MAC address.
- [ ] The ordinary-socket path runs only when explicitly selected and publishes
      socket observations, not wire evidence.
- [ ] Reverse-DNS and MAC/vendor observations are optional, policy-aware, and
      bounded.
- [ ] The declared discovery matrix passes controlled IPv4 and IPv6 behavior
      and native runtime checks on Linux, macOS, and Windows wherever the
      capability is supported.

[m1-vocabulary]: m01-claims-evidence.md#m11-evidence-vocabulary
[m1-data]: m01-claims-evidence.md#m12-scanner-data-policy
[m4]: m04-target-planning.md
[m10]: m10-os-identification.md
[m11]: m11-scan-informed-traceroute.md
[m13]: m13-sctp-ip-protocol.md
[m13-discovery]: m13-sctp-ip-protocol.md#m134-additional-discovery-probes
[probe]: ../../crates/packetcraftr/src/probe.rs
[scan-engine]: ../../crates/packetcraftr/src/scan/engine.rs
[scan-packets]: ../../crates/packetcraftr/src/scan/plan/packet.rs
[scan-report]: ../../crates/packetcraftr/src/scan/report.rs
[connect-engine]: ../../crates/packetcraftr/src/scan/connect/engine.rs
[neighbor-resolver]: ../../crates/packetcraftr/src/neighbor/resolver.rs
[neighbor-cache]: ../../crates/packetcraftr/src/neighbor/cache.rs
[neighbor-model]: ../../crates/packetcraftr/src/neighbor/model.rs
[dns-reverse]: ../../crates/packetcraftr/src/dns/reverse.rs
[tcp-provider]: ../../crates/packetcraftr-netio/src/tcp.rs
[netio-interface]: ../../crates/packetcraftr-netio/src/interface.rs
[netio-capture]: ../../crates/packetcraftr-netio/src/capture.rs
[scan-args]: ../../crates/packetcraftr-cli/src/commands/scan/arguments.rs
[scan-output]: ../../crates/packetcraftr-cli/src/output/scan.rs
[nmap-guide]: https://nmap.org/book/man.html
[nmap-discovery]: https://nmap.org/book/man-host-discovery.html
[nmap-targets]: https://nmap.org/book/man-target-specification.html
