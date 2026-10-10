# M11: Scan-informed traceroute

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M5][m5], [M6][m6] | Path inventory for scanned hosts |

PacketcraftR already has a bounded traceroute with UDP, TCP SYN, and ICMP
strategies. Before this milestone it was a separate workflow: the operator
picked one target and one strategy, and it traced one address. A scan that had
just learned which probe a host answers could not hand that knowledge to a
trace, and tracing twenty hosts behind the same router probed the shared hops
twenty times.

This milestone connects traceroute to scan results and lets one plan trace
several hosts. Standalone traceroute keeps its behavior.

## Outcome

- A trace can use a protocol and endpoint that the scan observed responding.
- Several authorized hosts are traced under one finite plan.
- Path reuse across hosts is evaluated, and where it is used every reused hop
  says where it came from and how fresh it is.

## Invariants

- A cached hop never appears as a fresh observation for another target.
- No hop is invented, and an intermediate router is never treated as the
  destination.
- Standalone traceroute keeps its current strategies, bounds, and evidence.
- Matching Nmap's reverse-TTL algorithm is not required.

## Scope

### M11.1 Probe selection from scan results

A trace can select its protocol and endpoint from what [M5][m5] and [M6][m6]
observed responding for that host. The selection and the observation it rests
on are published with the trace.

### M11.2 Multi-host trace plans

Several authorized hosts are traced under one finite plan, with one operation
budget and per-host bounds. A host that exhausts its bounds is reported as
incomplete.

### M11.3 Bounded path reuse

- Evaluate reusing hops learned for one host when tracing another that shares
  them.
- Reuse is bounded, and each reused hop carries explicit source and freshness
  metadata.
- A reused hop expires. After expiry it is observed again or reported as not
  observed.

## Implementation notes

`Client::trace_hosts` uses the standalone probes, classifier, and evidence runner
for a bounded authorized host plan. Observed probe selection prefers a direct
TCP SYN/ACK, then TCP reset, then ICMP echo, breaking ties by scan sequence. A
router error cannot select a probe. UDP requires an explicit strategy because
its destination port changes per trace probe. No observation/fallback or unsupported
scope produces an explicit `not_traced` outcome, not a guessed probe.

Hosts execute in selection order with shared sequence, pacing, evidence, packet,
byte, and deadline budgets. Reuse is opt-in, bounded by family/scope/freshness,
and retains sourced claims separately from fresh observations. See
[trace evidence][evidence-trace] for record meanings and [known limits](#known-limits)
for reuse and admission constraints.

The raw-only `scan --traceroute` stage runs before reverse DNS and inherits the
scan's remaining allowance. List/connect modes and invalid settings fail before
active work; admission of the remaining trace budget happens after scanning.
Standalone traceroute keeps its contract. Stage fields were introduced in v11
and are retained in current v12 under the [consumer policy][compatibility-v11].

## Recorded fixture and native checks

- The evaluation behind decision 2 runs on the unit-test fixtures, which
  answer from a scripted topology: the [library tests][hosts-tests] and the
  same fixtures through a client and the fake responder in the
  [integration contracts][hosts-contracts]. In every fixture the reported hops
  equal the topology's.

  | Fixture | Without reuse | With reuse |
  | --- | --- | --- |
  | Shared prefix: 4 hosts, 4 shared routers, destination at hop 5 (`reuse_sends_fewer_probes_on_a_shared_prefix_without_a_wrong_hop`) | 20 probes | 11 probes |
  | Divergent: three hosts that share hop 1, hop 1 and 2, and no hop (`reuse_on_diverging_paths_probes_what_differs`) | 15 probes | 14 probes |
  | Shared prefix with `max_age` 1 s while each batch takes 1 s (`reused_hops_expire`) | 20 probes | 20 probes, nothing reused |

  With `max_age` 4 s the same test reuses hop 3 of the second host and probes
  hops 4, 2, 1, and 5 again.
- A native Linux run used a throwaway privileged container with network
  namespaces on documentation addresses. The scanner reached two routers,
  `r1` (192.0.2.2) and `r2` (192.0.2.6); h1 (198.51.100.10, tcp/22 open) and
  h2 (198.51.100.11, closed) sat three hops away behind `r2`, and h3
  (203.0.113.10, closed) two hops away behind `r1`. The routers had ICMP rate
  limiting off, and replies toward the scanner were delayed 5 ms, because the
  then-current [freshness rule][netio-transmit] discarded replies arriving before
  `send()` returned. The binary was a release build with `native-layer2` and
  `native-layer3`. A first run lost h1's SYN/ACK to
  `exchange.integrity_rejected` because the veths offloaded checksums, and
  h1 was correctly reported `not_traced` with `no_responsive_probe`. With
  checksum offload off on the veths, a `--ports 22 --traceroute
  --traceroute-attempts 1` scan published:
  - Every host was `complete` with `destination_reached`, and each was traced
    over tcp/22 with the `observed` scan probe it answered: h1's
    `tcp_syn_ack`, and h2's and h3's `tcp_reset`. The fresh hops were
    192.0.2.2 and 192.0.2.6 before h1 and h2, and 192.0.2.2 before h3, with
    the destination's own reply at the last hop. No router was reported as a
    destination.
  - Without reuse the trace sent 8 probes. With
    `--traceroute-reuse-max-age-ms 30000` it sent 7: h2 probed hop 2, matched
    h1's 192.0.2.6, and reused hop 1 (192.0.2.2) from h1, published in
    `reused_hops` with h1 as its source and an age of about 1.26 s. h3 drew
    its destination's reply at the anchor hop 2, matched 192.0.2.2 at hop 1,
    and reused nothing. With a 1 ms maximum age nothing was reused and the
    trace sent 8 probes.
  - `--discovery only` selected the `icmp_echo_reply` discovery probe for
    every host and gave the same paths and reuse over ICMP.
  - NDJSON streamed three scan `probe` records, then each host's
    `traceroute_probe` records followed by its `traceroute_host` record, then
    the `endpoint`, `host`, and `complete` records. `complete.traceroute`
    carried the plan.
  - `--traceroute-max-probes 2` was refused with `cli.traceroute_limit` after
    the scan and before any trace probe, as the known limit below says.
  - Those counts predate the neighbor-request accounting added later: they
    count trace probes only. The run was not repeated.

## Known limits

- **A reused hop is a sourced claim, not an observation.** Matching one router
  at one hop limit does not prove that two paths share the hops below it.
  On a reconvergent path, or where equal-cost routing sends probes of
  different hosts over different routers, a reused hop can name a router that
  the host's own probes would not show. The unit test
  `a_reused_hop_is_a_sourced_claim_on_reconvergent_paths` pins this. That is
  why reuse is opt-in and why reused hops are published apart from probed ones
  with their source and age.
- **Descending from the anchor can cost more probes** for a host closer than
  the anchor: it probes down from the highest cached hop before it can match.
  In the divergent fixture the second host sends four probes against five
  without reuse, and the third, which shares only hop 1 with an earlier host,
  sends all five and saves nothing.
- **Hosts are traced one after another.** The [M7][m7-fairness] per-host
  interleaving does not apply, and a slow host delays the ones after it.
- **Admission happens after the scan.** A trace plan that does not fit what is
  left of `--max-duration`, that exceeds `--traceroute-max-probes`, or whose
  share of the evidence budget cannot retain a hop's responses fails the
  command after the scan has run, before any trace probe is sent. The scan's
  already-retained response, undecoded, and unattributed frames and bytes are
  deducted from the trace's limits and capture queues, except when no host
  can be traced at all, where nothing is deducted and `not_traced` outcomes
  are reported normally.
- **The default trace source port is disjoint from the scan's.** TCP and UDP
  probes default to 49151, just below the 49152..=65535 range a scan's
  generated UDP probes use, so a replayed scan reply cannot match a trace
  probe's tuple; an explicit `source_port` overrides it on the caller's
  responsibility.
- **A link-layer trace's timeout must outlast one `--rate` interval.** Each
  probe's possible neighbor request spends an interval inside the probe's
  window, so an automatic or link-layer plan whose timeout cannot outlast it
  is refused with `cli.traceroute_limit` before any work; a layer-3 route is
  exempt.
- **Not every scan host has a trace.** The stage declares every scan host,
  including a host discovery found silent, so such a host is traced only when
  `--traceroute-strategy` names a probe, and is `not_traced` otherwise.
- **Native evidence is Linux-only and delayed.** The one native run used
  namespaces with replies delayed past `send()`, before the M5 submission
  change that correlates replies captured during transmission. An undelayed
  run on the updated submission boundary and any run on macOS or Windows
  remains needed (see Blockers).

## Decisions

Settled at M11 with the recommended positions:

1. **A host with no responsive probe is not traced.** Without an explicit
   strategy it is reported `not_traced` with `no_responsive_probe`; nothing
   is guessed.
2. **Path reuse ships only behind an explicit option**
   (`--traceroute-reuse-max-age-ms`, `hosts::Request::reuse`). On the
   evaluation fixtures it sends fewer probes with no wrong hop: 20 against 11
   on a shared prefix and 15 against 14 on diverging paths, and 20 against 20
   once hops expire. The [known limit](#known-limits) on reconvergent paths is
   why it stays off by default.
3. **A reused hop is fresh within one operation and for `max_age`.** The cache
   never outlives the operation, and an expired hop is probed again.
4. **One operation budget with per-host ceilings.** Admission checks that
   every traced host's ceiling (hops times attempts) fits `max_probes` and the
   duration together, and refuses the plan before any capture or send
   otherwise.
5. **Multi-host tracing is a stage of `scan`** built on the traceroute
   workflow's probes, packets, classifier, executor, and runner. The standalone
   `traceroute` command keeps its single-target contract and output shape,
   and `Client::trace_hosts` serves any authorized selection.

## Exit criteria

- [x] Traceroute fixtures cover hop timeouts, destination and unreachable
      termination, protocol selection, multiple hosts, and reuse expiry. The
      [library tests][hosts-tests] cover silent hops, each transport ending at
      the destination, unreachable, exhausted bounds, selection from scan
      results, one budget over several hosts, and expiry; the
      [contracts][hosts-contracts] run them through a client, including a real
      scan feeding the trace.
- [x] No fixture result contains an invented hop or treats an intermediate
      router as the destination. The library tests' shared check compares each
      reported hop with the topology and requires a destination reply to come
      from the destination, and the [contracts][hosts-contracts] check the same. The
      reconvergent case is pinned as a claim, not an observation (see
      [Known limits](#known-limits)).
- [x] Reused hops carry source and freshness metadata and are distinguishable
      from fresh observations. They have a `source`, the source's probe
      sequences, `observed_at`, and `age`, they never appear as probe events,
      and they are separate from `hops` in the output
      ([library tests][hosts-tests], [schema conformance][cli-aggregate],
      [stream conformance][cli-ndjson]).
- [x] Standalone traceroute passes its existing contracts unchanged
      ([`traceroute_contracts.rs`][trace-contract], the standalone unit tests,
      and the [stage contracts][cli-stage] for its version-only output
      change).
- [x] The workflow preserves authorized scope, final-wire checks, timestamps,
      cancellation, evidence ceilings, and platform capability failures.
      Authorization before any capture or send, cancellation and deadline,
      shared evidence ceilings, and timestamps have tests
      ([library][hosts-tests], [contracts][hosts-contracts]). A sent packet
      that differs from its planned probe fails the plan at that probe with no
      further batch
      (`a_sent_packet_that_differs_from_its_probe_fails_the_plan_at_that_probe`).
      The stage needs the raw method, so a platform capability failure
      surfaces in the scan before any trace probe: `scan.rs` runs the raw
      capability check before the scan and never replaces an explicit raw
      method (`explicit_raw_is_never_replaced_by_a_connection` in the
      [method tests][method-tests]), and the stage's usage rejections before
      any probe are in the [stage contracts][cli-stage].
- [ ] Linux, macOS, and Windows support and runtime evidence are recorded
      independently. The Linux namespace run above passes only with delayed
      replies, predating the submission-boundary fix that correlates early
      replies; an undelayed retest and the macOS and Windows runs are still
      open (see Blockers).

## Blockers

The fixture criteria have evidence, but the roadmap [close gates][close-gates]
keep M11 `In progress`:

- **Ground truth ([M2][m2]).** Trace results are scanner results, so path
  shapes (shared prefix, divergence, reconvergence, equal-cost routes, silent
  hops) need comparison-corpus entries with independent expected paths.
- **Runtime evidence ([M3][m3]).** The M5 native work changed the
  submission boundary so immediate replies now correlate, but M11's one
  Linux run predates it and needed replies delayed past `send()`; the stage
  needs a fresh undelayed native run on the updated boundary before its
  runtime evidence counts. `scan --traceroute` has not run on macOS or
  Windows.

[m2]: m02-ground-truth-benchmarks.md
[m5]: m05-host-discovery.md
[m6]: m06-port-planning-inference.md
[m3]: m03-native-validation.md
[m7-fairness]: m07-adaptive-scheduling.md#m74-per-host-fairness-and-deadlines
[close-gates]: README.md#close-gates
[hosts-tests]: ../../crates/packetcraftr/src/traceroute/hosts/tests.rs
[hosts-contracts]: ../../crates/packetcraftr/tests/integration/traceroute_hosts_contracts.rs
[trace-contract]: ../../crates/packetcraftr/tests/integration/traceroute_contracts.rs
[cli-stage]: ../../crates/packetcraftr-cli/tests/integration/traceroute_stage_contracts.rs
[cli-aggregate]: ../../crates/packetcraftr-cli/tests/integration/aggregate_schema_conformance.rs
[cli-ndjson]: ../../crates/packetcraftr-cli/tests/integration/ndjson_conformance.rs
[netio-transmit]: ../../crates/packetcraftr-netio/src/transmit.rs
[compatibility-v11]: ../consumer-compatibility.md#output-family-v11
[evidence-trace]: ../scanner-evidence.md#traceroute-stage
[method-tests]: ../../crates/packetcraftr/src/scan/method/tests.rs
