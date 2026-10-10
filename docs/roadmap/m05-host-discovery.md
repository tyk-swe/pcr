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

Discovery is an opt-in scan stage (`before`, `only`, or `skip`). One admission
covers target authorization, explicit/implicit neighbor requests, discovery and
scan probes, pacing, bytes, duration, and retained evidence. Sequence numbering
continues across stages; skipped hosts release response reservations before
scanning. Discovery-only requests take no endpoint `--ports`.

Discovery ports use the M6 selection/exclusion rules. Neighbor requests are
final-wire checked and budgeted. An on-link answer can produce a fresh/cached
neighbor observation; routed gateways are next-hop evidence, not host identity,
and are not actively queried unless independently selected. Proxy suspicion is
limited to same-family targets/gateways in the request. No vendor database is
bundled.

Host reasons separate direct wire replies, ordinary-socket responsiveness, and
neighbor evidence; silence/router errors never prove absence or identity.
Reverse DNS is optional and authorized within the remaining operation budget.
See [host observations](../scanner-evidence.md#host-observations), command help, and the
[migration guide][migration] for the current interfaces. These fields were
introduced in output/v9 and are retained in v12.

Historical delayed-reply experiments are superseded by the exact-revision
[Linux acceptance](evidence/m05/README.md); the remaining cross-platform failures
and unavailable checks are recorded below, not counted as passes.

### Known limits

- **Neighbor reply frames are not retained.** The host record publishes the
  outcome, attempts, link address, and observation time, but the ARP or NDP
  frames stay inside the resolver.
- **A layer-2 probe still needs its neighbor.** When the probe route is
  link-layer (`--link-mode layer2`, or a link without layer-3 injection), a
  discovery or scan probe to an on-link host that does not answer ARP or NDP
  fails the request, as scan probes already did — unless the `neighbor`
  probe already proved the silence, in which case the host is sent no IP
  probes, keeps `no_response`, and is `skipped` by the scan stage. Under
  the default link mode the operating system resolves neighbors for wire
  probes, and the `neighbor` probe records silence without failing.
- **A routed target's next hop is only as complete as the cache.** Its link
  address appears when the gateway answered earlier, for example as a
  selected target; otherwise `next_hop` carries the address alone.
- **Proxy detection is limited to the request.** `possible_proxy` compares
  link addresses only among this request's targets and gateways. A proxy that
  answers for a single target cannot be told apart from the host.
- **Reverse lookups run after the scan** and get only the time the scan left
  in `--max-duration`. A lookup that does not fit is recorded `unattempted`.

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
      capability is supported. The [raw matrix][discovery-matrix] and
      [neighbor matrix][neighbor-matrix] cover the independently authored six
      conditions. [Recorded Linux acceptance](evidence/m05/README.md) passes all
      required paths across five profiles: 44 exercised cases, 36 actual typed
      capability refusals, and 168 bounded CLI invocations. The remaining
      environment-dependent macOS/Windows checks were explicitly skipped at
      the user's request; they are not passed runtime checks.

## Remaining native acceptance

Implementation, independent corpus coverage, and the required Linux validation
are complete. The roadmap [close gates][close-gates] keep M5 `In progress`
because broad macOS/Windows native acceptance remains incomplete. The user's
instruction to skip those environment-dependent checks changes this task's
validation scope; it does not establish native parity or close the project's
remaining platform gate.

The completion-marker race is fixed: exact successful submissions admit matching
captures from submission start, immediately before the native send call. Socket
preparation is outside that interval; missing or earlier monotonic ingress stays
ineligible. The deterministic interval regression and clean-revision Linux
immediate-reply runtime pass without imposed reply delays.

The [native discovery launcher](../../scripts/test-host-discovery-native.py)
retains precise unsupported/dependency/isolation results. The reviewed
[host-local run 37968418933](https://github.com/tyk-swe/pcr/actions/runs/37968418933)
recorded macOS ARM fixture contradictions (reserved closed sockets timed out,
and raw IPv4 loopback discovery observed no qualifying replies); those results
remain failures. Windows completed with explicit missing/unsupported raw
capabilities. The remaining macOS Intel execution was cancelled after the skip
instruction. Loopback-only admission cannot prove routed or shared-link behavior;
no driver installation or remote traffic was introduced.

## Independent discovery corpus and runtime route

Dataset `1.3.0` adds six ordered `discovery_scenarios` to the frozen corpus v1
schema: responsive, closed-but-responsive, silent, blocked, routed, and
shared-link-address, each in IPv4 and IPv6. Expectations are authored before
execution; router errors never become host-response reasons. The
[raw matrix][discovery-matrix] checks every IP probe and follow-up choice; the
[neighbor matrix][neighbor-matrix] checks fresh ARP/NDP, cache reuse, silence,
routing, and shared-MAC ambiguity. Existing DNS,
authorization, unified-budget, socket, omitted/skipped, and streaming contracts
remain part of acceptance.

Run the reviewed native route at an exact clean implementation revision:

```sh
# Linux: mapping the invoking owner must be permitted by the managed runtime.
sudo -n env "PATH=$PATH" "CARGO_HOME=$HOME/.cargo" "RUSTUP_HOME=$HOME/.rustup" \
  python3 scripts/test-host-discovery-native.py --reviewed-commit "$(git rev-parse HEAD)" \
  --require-complete --report target/validation/m5-linux/host-discovery.json
```

Both reviewed native workflows accept `scenario=host_discovery`. They retain
commands, bounded output, corpus/source/executable digests, and precise
unavailable paths without changing the historical M3 v3 evidence inventory.
No vendor dataset, external DNS server, remote target, or driver installation
is part of these fixtures. Host-local checks cannot prove routed or shared-link
behavior; the report and gate deliberately preserve that limitation.

[neighbor-matrix]: ../../crates/packetcraftr/tests/integration/discovery_neighbor_matrix.rs
[m1-vocabulary]: m01-claims-evidence.md#m11-evidence-vocabulary
[m1-data]: m01-claims-evidence.md#m12-scanner-data-policy
[m4]: m04-target-planning.md
[m10]: m10-os-identification.md
[m11]: m11-scan-informed-traceroute.md
[m6-selection]: m06-port-planning-inference.md#m62-port-exclusions
[m13]: m13-sctp-ip-protocol.md
[m13-discovery]: m13-sctp-ip-protocol.md#m134-additional-discovery-probes
[close-gates]: README.md#close-gates
[discovery-tests]: ../../crates/packetcraftr/src/scan/discovery/tests.rs
[method-tests]: ../../crates/packetcraftr/src/scan/method/tests.rs
[discovery-contracts]: ../../crates/packetcraftr/tests/integration/discovery_contracts.rs
[discovery-matrix]: ../../crates/packetcraftr/tests/integration/discovery_matrix.rs
[cli-discovery-contracts]: ../../crates/packetcraftr-cli/tests/integration/discovery_contracts.rs
[migration]: ../migration-unreleased.md#host-discovery
