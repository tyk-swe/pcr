# M5: Host discovery

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M4][m4] | [M10][m10], [M11][m11], [M13][m13] |

PacketcraftR can already send ICMP echo, TCP SYN, and UDP probes and open
ordinary TCP connections, and it resolves neighbors with bounded ARP and NDP
when it prepares a route. Before this milestone none of that was composed into
an answer to "which of these authorized hosts responded, and how do we know?".
There was no discovery stage and no host-level result, and a neighbor
resolution for a gateway said nothing about the host behind it.

This milestone adds a discovery stage to the scan workflow that composes those
building blocks and publishes one host record per target in the
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
- Discovery probe ports come from the [M6][m6-selection] port selection after
  its exclusions, so discovery never probes an excluded port.
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

## Implementation notes

- Discovery is a stage of the scan workflow ([`scan::discovery`][scan-discovery]).
  `Request.discovery` selects the mode (`omitted` by default, `skipped`,
  `before`, or `only`), the discovery probes, whether to resolve neighbors, and
  what happens to hosts that did not answer. The CLI exposes
  `--discovery before|only|skip`, `--discovery-probes icmp,neighbor,tcp,udp`
  (default `icmp`), `--discovery-ports`, and
  `--unresponsive-hosts skip|scan`. Only `skip` and `scan` choices that a
  running stage can honor are accepted, and `--discovery only` takes no
  `--ports`.
- One authorization and one budget cover both stages. The
  [scan engine][scan-engine] plans discovery probes, neighbor requests, and
  scan probes as a single `admit_selection`. The probe count includes every
  ARP or NDP attempt: the explicit `neighbor` probe's retries plus at most
  one implicit resolution per target whose probes materialize a link-layer
  route (the exchanges share a narrowed resolver that sends once per
  neighbor, keeps the answer for the operation, and captures within the
  scan's evidence limits). The wire limit includes a worst-case request
  with the largest VLAN stack, and the worst-case duration includes
  neighbor attempts and the pause between stages, all inside `--max-probes`
  and `--max-duration`. The distinct discovery and scan endpoints count
  toward `--max-ports` as one set. Targets and the operation are authorized
  before the first frame, ARP and NDP included. Discovery probes take
  sequences from 0, and the scan continues the same sequence space and
  shares the evidence budget; hosts the scan skips release their response
  reservations before the scan stage, and the discovery and
  stage-transition pauses are reserved against `--max-duration` before they
  are slept and count in the elapsed statistics.
- Discovery ports come from `--discovery-ports` through the same
  [M6 selection][m6-selection] as `--ports`, with the scan's `--exclude-ports`
  applied. An exclusion prefixed with a transport discovery does not probe
  applies only to the scan.
- The `neighbor` probe ([executor][scan-executor]) plans the route an ICMP
  probe would take and forces a link-layer route when the link supports one;
  otherwise the outcome is `not_applicable`. An on-link target is resolved
  through the [neighbor resolver][neighbor-resolver] and its shared cache,
  one request per `--attempts` paced like a probe, each waiting `--timeout`
  and captured within the scan's evidence limits. That gives `resolved` (fresh
  or cached) or `silent`; a fresh answer is timestamped when its reply was
  captured, and the requests count in the scan statistics. Each request
  frame is checked before it is sent: the address it asks for must be
  authorized and its sources must be the route's own. A routed target is
  `routed` with the gateway's address under `next_hop`. Its gateway is not a
  selected target, so it is sent no request; the next hop carries a link
  address only when the neighbor cache already holds one.
- [Host composition][discovery-host] turns discovery outcomes into reasons.
  A reply counts only when the target itself sent it: an echo reply, a TCP
  SYN/ACK or reset, a UDP reply, or a port unreachable from the host. An ICMP
  error from another responder stays probe evidence and is not a reason. Each
  reason carries its `evidence` (`wire`, `socket`, or `cache`) and `basis`. A
  neighbor reply is `direct`, a cache entry is `cached`, and a link address
  that also answered for another address of the same family, as a target or a
  gateway, is `possible_proxy`. No cause is asserted. A host is `responded`
  with at least one reason and `no_response` otherwise, and `not_requested` or
  `skipped` when no stage ran. Its `scan` disposition is `scanned`, `skipped`,
  or `not_requested`.
- The ordinary-socket path runs TCP discovery through `--connect` and the
  [connect engine][connect-engine]. A refused or completed connection is a
  `socket` reason, and one socket operation covers both stages. ICMP, UDP, and
  neighbor discovery are rejected before any connection with
  `cli.scan_method`, and [`--method auto`][scan-method] counts discovery
  probes when it chooses.
- `--reverse-dns SERVER` (with `--reverse-dns-port`) sends one PTR question per
  looked-up host through the [DNS workflow][scan-reverse] after the scan. That
  covers the responders when discovery ran and every host otherwise. The
  questions are authorized by the same policy, use the scan's attempts and
  timeout, run in batches of at most 256, and share what is left of
  `--max-duration`. The raw method sends UDP with TCP fallback (UDP only under
  route overrides), and `--connect` uses TCP. Each host carries its question's
  status, outcome, response code, and PTR names, with failures recorded per
  host. The lookups' exchange statistics count in the command's reported
  statistics.
- Link addresses are published only from the explicit `neighbor` probe. No
  vendor data set is accepted under the [data policy][data-policy], so no
  vendor label is published.
- Results ship in `packetcraftr.output/v9` ([schema][schema-v9],
  [migration][migration], [compatibility][compatibility-v9]). v9 adds
  `hosts` to scan results, a `host` stream record per target before
  `complete`, `stage` on every probe, sent, connect, and failed-probe record,
  and `plan.discovery`. The [evidence model][evidence-hosts] defines the host
  fields and rules.
- A native Linux run used two throwaway network namespaces joined by a veth
  pair on `192.0.2.0/24` and `2001:db8::/64`. Behind the second namespace,
  `198.51.100.0/24` and `2001:db8:1::/64` were routed to targets that do not
  exist. Replies from the target namespace arrived about 25 µs after each ARP
  request or probe. That is before `send()` returns, so the
  [freshness rule][netio-transmit] discarded them, and every host, the
  responsive one included, stayed `no_response`. An existing
  `send --link-mode layer2` to the same host fails the same way. With a 5 ms
  egress delay on the target namespace, discovery with `icmp,neighbor,tcp/9`
  before a scan of tcp/22 and tcp/80, with `--attempts 2` and `--rate 50`,
  published the following:
  - The dual-stack host was `responded` in both families. Its fresh neighbor
    reply, timestamped at capture, and its echo replies and TCP resets from
    the closed port were all `direct`, and the scan found tcp/22 open and
    tcp/80 closed in both families.
  - The silent on-link targets in each family were asked twice, had `silent`
    neighbor outcomes, stayed `no_response`, and were skipped.
  - The routed targets were sent no neighbor request. Each published its
    gateway as `next_hop`, with the link address cached from the gateway's own
    answer as a target. They stayed `no_response`, and the gateway's ICMP
    unreachable remained probe evidence with no reason.
  - The statistics counted 38 frames: 24 discovery probes, 6 neighbor
    requests, and 8 scan probes.
  - An earlier run flagged the dual-stack host as `possible_proxy`, which led
    to the same-family rule above.

### Known limits

- **Neighbor reply frames are not retained.** The host record publishes the
  outcome, attempts, link address, and observation time, but the ARP or NDP
  frames stay inside the resolver.
- **A layer-2 probe still needs its neighbor.** When the probe route is
  link-layer (`--link-mode layer2`, or a link without layer-3 injection), a
  discovery or scan probe to an on-link host that does not answer ARP or NDP
  fails the request, as scan probes already did. Under the default link mode
  the operating system resolves neighbors for wire probes, and the
  `neighbor` probe records silence without failing.
- **A routed target's next hop is only as complete as the cache.** Its link
  address appears when the gateway answered earlier, for example as a
  selected target; otherwise `next_hop` carries the address alone.
- **Proxy detection is limited to the request.** `possible_proxy` compares
  link addresses only among this request's targets and gateways. A proxy that
  answers for a single target cannot be told apart from the host.
- **Reverse lookups run after the scan** and get only the time the scan left
  in `--max-duration`. A lookup that does not fit is recorded `unattempted`.

## Change map

| Change | Where |
| --- | --- |
| Discovery options, modes, and host composition | [`scan/discovery.rs`][scan-discovery], [`scan/discovery/host.rs`][discovery-host] |
| Stage planning, budget, and sequencing | [`scan/engine.rs`][scan-engine], [`scan/plan.rs`][scan-plan] |
| Neighbor probe | [`scan/executor.rs`][scan-executor], [`neighbor/resolver.rs`][neighbor-resolver] |
| Ordinary-socket path | [`scan/connect/engine.rs`][connect-engine], [`scan/method.rs`][scan-method] |
| Host records | [`scan/report.rs`][scan-report], [`output/scan/host.rs`][host-output] |
| Reverse names | [`dns/reverse.rs`][dns-reverse], [`commands/scan/reverse.rs`][scan-reverse] |
| CLI controls | [`commands/scan/arguments.rs`][scan-args], [`commands/scan.rs`][scan-command] |

## Decisions

Settled at M5 with the recommended positions:

1. **`scan` does not discover by default.** Without `--discovery`, the plan
   reports `omitted`, no discovery probe is sent, and every host record says
   `not_requested`.
2. **Discovery is a stage of the scan workflow** with a discovery-only mode,
   so one authorization, one budget, and one sequence space cover both stages.
3. **What follows a silent host is an explicit choice.**
   `--unresponsive-hosts skip|scan` defaults to `skip`. The choice is published
   in `plan.discovery.unresponsive`, and every host's `scan` disposition
   shows what happened to it.
4. **Reverse lookups use the DNS workflow** against an explicit server, so
   each question is authorized, bounded, and evidenced like any other DNS
   question. The system resolver is not used.
5. **MAC observation ships without vendor labels.** No vendor data set has a
   provenance record under the [M1 data policy][m1-data], so vendor labels
   wait for one.
6. **A possible proxy is flagged, not explained.** Host records publish the
   responder and the link address. A link address that also answered for
   another address of the same family, as a target or a gateway, is
   `possible_proxy`, and the [fixtures][discovery-contracts] define those
   cases.

## Exit criteria

- [x] A closed-but-responsive TCP endpoint demonstrates host responsiveness in
      the fixtures. A TCP reset marks the host `responded` with a `direct` wire
      reason in the [discovery contracts][discovery-contracts] and in both
      families of the [discovery matrix][discovery-matrix]. A refused
      connection does the same through sockets in the
      [CLI contracts][cli-discovery-contracts].
- [x] Silent and blocked hosts retain uncertainty and are never reported as
      absent. In the [matrix][discovery-matrix], silence and a router's
      unreachable keep the host `no_response` with no reason in both families,
      under each choice of what follows.
- [x] Discovery omission and skipping are visible in host records rather than
      represented as measured reachability. Omitted and skipped stages send no
      discovery probe and label each host `not_requested` or `skipped`
      ([library][discovery-contracts], [CLI][cli-discovery-contracts]).
- [x] Cached next-hop information, proxy replies, and direct host evidence are
      distinct in host records, and no target identity is inferred from a
      routed gateway's MAC address. Fresh and cached neighbor answers, a link
      address shared by several targets, and a routed target's gateway are
      separate [contracts][discovery-contracts] and
      [unit cases][discovery-tests]. A gateway's link address appears only
      under `next_hop`.
- [x] The ordinary-socket path runs only when explicitly selected and publishes
      socket observations, not wire evidence. `--connect` discovery reasons
      are `socket`, ICMP, UDP, and neighbor discovery are refused before any
      connection, and automatic selection names the probe that needs the raw
      method ([method tests][method-tests]).
- [x] Reverse-DNS and MAC/vendor observations are optional, policy-aware, and
      bounded. Reverse names come from authorized DNS questions within the
      scan's remaining duration, and an unanswered question is recorded
      without failing the scan ([CLI contracts][cli-discovery-contracts]).
      Link addresses come only from the explicit `neighbor` probe, and no
      vendor label is published.
- [ ] The declared discovery matrix passes controlled IPv4 and IPv6 behavior
      and native runtime checks on Linux, macOS, and Windows wherever the
      capability is supported. The [matrix][discovery-matrix] covers every
      probe, host behavior, and follow-up in both families with fixtures. The
      Linux namespace run passes only with delayed replies, and macOS and
      Windows have not run (see Blockers).

## Blockers

Every fixture criterion has evidence, but the roadmap [close
gates][close-gates] keep M5 `In progress`:

- **Ground truth ([M2][m2]).** Host states are scanner results, so the
  responsive, closed-but-responsive, silent, blocked, routed, and
  shared-link-address scenarios need comparison-corpus entries with
  independent expected outcomes.
- **Runtime evidence ([M3][m3]): native replies faster than the send call
  are not correlated.** The [`transmit::Timing`][netio-transmit] freshness rule
  that [M6][m6] records also discards ARP and NDP replies that arrive before
  `send()` returns. On a direct veth link that hides every host, so the native
  run above needed delayed replies. Deciding what such frames prove belongs
  with native validation in [M3][m3]. Until then no undelayed native scenario
  can show discovery, and nothing has run on macOS or Windows.

[m1-vocabulary]: m01-claims-evidence.md#m11-evidence-vocabulary
[m1-data]: m01-claims-evidence.md#m12-scanner-data-policy
[m2]: m02-ground-truth-benchmarks.md
[m3]: m03-native-validation.md
[m4]: m04-target-planning.md
[m10]: m10-os-identification.md
[m11]: m11-scan-informed-traceroute.md
[m6]: m06-port-planning-inference.md
[m6-selection]: m06-port-planning-inference.md#m62-port-exclusions
[m13]: m13-sctp-ip-protocol.md
[m13-discovery]: m13-sctp-ip-protocol.md#m134-additional-discovery-probes
[close-gates]: README.md#close-gates
[scan-discovery]: ../../crates/packetcraftr/src/scan/discovery.rs
[discovery-host]: ../../crates/packetcraftr/src/scan/discovery/host.rs
[discovery-tests]: ../../crates/packetcraftr/src/scan/discovery/tests.rs
[scan-executor]: ../../crates/packetcraftr/src/scan/executor.rs
[scan-plan]: ../../crates/packetcraftr/src/scan/plan.rs
[scan-method]: ../../crates/packetcraftr/src/scan/method.rs
[method-tests]: ../../crates/packetcraftr/src/scan/method/tests.rs
[discovery-contracts]: ../../crates/packetcraftr/tests/integration/discovery_contracts.rs
[discovery-matrix]: ../../crates/packetcraftr/tests/integration/discovery_matrix.rs
[cli-discovery-contracts]: ../../crates/packetcraftr-cli/tests/integration/discovery_contracts.rs
[scan-reverse]: ../../crates/packetcraftr-cli/src/commands/scan/reverse.rs
[scan-command]: ../../crates/packetcraftr-cli/src/commands/scan.rs
[host-output]: ../../crates/packetcraftr-cli/src/output/scan/host.rs
[netio-transmit]: ../../crates/packetcraftr-netio/src/transmit.rs
[schema-v9]: ../../schemas/packetcraftr.output.v9.schema.json
[migration]: ../migration-unreleased.md#host-discovery-and-outputv9
[compatibility-v9]: ../consumer-compatibility.md#output-family-v9
[evidence-hosts]: ../scanner-evidence.md#host-observations
[data-policy]: ../scanner-data-policy.md
[scan-engine]: ../../crates/packetcraftr/src/scan/engine.rs
[scan-report]: ../../crates/packetcraftr/src/scan/report.rs
[connect-engine]: ../../crates/packetcraftr/src/scan/connect/engine.rs
[neighbor-resolver]: ../../crates/packetcraftr/src/neighbor/resolver.rs
[neighbor-model]: ../../crates/packetcraftr/src/neighbor/model.rs
[dns-reverse]: ../../crates/packetcraftr/src/dns/reverse.rs
[scan-args]: ../../crates/packetcraftr-cli/src/commands/scan/arguments.rs
[nmap-guide]: https://nmap.org/book/man.html
[nmap-discovery]: https://nmap.org/book/man-host-discovery.html
[nmap-targets]: https://nmap.org/book/man-target-specification.html
