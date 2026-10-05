# M11: Scan-informed traceroute

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M5][m5], [M6][m6] | Path inventory for scanned hosts |

PacketcraftR already has a bounded traceroute with UDP, TCP SYN, and ICMP
strategies. It is a separate workflow: the operator picks one target and one
strategy, and it traces one address. A scan that has just learned which probe
a host answers cannot hand that knowledge to a trace, and tracing twenty hosts
behind the same router probes the shared hops twenty times.

This milestone connects traceroute to host and scan results and lets one plan
trace several hosts. Standalone traceroute keeps its behavior.

## Outcome

- A trace can use a protocol and endpoint that the scan observed responding.
- Several authorized hosts are traced under one finite plan.
- Path reuse across hosts is evaluated, and where it is used every reused hop
  says where it came from and how fresh it is.

## Baseline

| | PacketcraftR at `22c7d182d577` | Nmap reference |
| --- | --- | --- |
| Strategies | UDP, TCP SYN, and ICMP, with hop bounds, payload shaping, and finite evidence ([request][trace-request]) | Traceroute is a scan-integrated capability ([host discovery][nmap-discovery]) |
| Targets per run | One [`target`][trace-request]; [execution][trace-engine] selects one destination address | Every scanned host ([host discovery][nmap-discovery]) |
| Hop order | [Planning][trace-plan] advances hops upward from the first hop | Starts at a high TTL and decrements ([host discovery][nmap-discovery]) |
| Use of scan results | None; traceroute is separate from scanning | Selects responsive protocols and endpoints ([host discovery][nmap-discovery]) |
| Path reuse | None | Reuses path information across hosts ([host discovery][nmap-discovery]) |

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

## Change map

| Change | Start here |
| --- | --- |
| Request shape, multiple targets | [`traceroute/request.rs`][trace-request] |
| Plans across hosts | [`traceroute/plan.rs`][trace-plan] |
| Execution and reuse | [`traceroute/engine.rs`][trace-engine] |
| Hop provenance | [`traceroute/report.rs`][trace-report] |
| Scan results as input | [`scan/report.rs`][scan-report] |
| Arguments and records | [`commands/traceroute.rs`][trace-command], [`output/traceroute.rs`][trace-output] |
| Existing contracts | [`traceroute_contracts.rs`][trace-contract] |

## Decisions to settle

1. What a trace does when the scan observed no responsive probe for a host
   (recommended: require an explicit strategy or report the host as not traced;
   do not guess).
2. Whether path reuse ships (recommended: only behind an explicit option, and
   only if the evaluation shows fewer probes with no wrong hop on the fixtures;
   otherwise record it as evaluated and declined).
3. The freshness bound for a reused hop (recommended: within one operation
   only, never across operations).
4. How the budget is divided across hosts (recommended: one operation budget
   with per-host ceilings, consistent with [M7][m7-fairness]).
5. Whether multi-host tracing is a stage of `scan`, an extension of
   `traceroute`, or both (recommended: one engine behind both entry points).

## Exit criteria

- [ ] Traceroute fixtures cover hop timeouts, destination and unreachable
      termination, protocol selection, multiple hosts, and reuse expiry.
- [ ] No fixture result contains an invented hop or treats an intermediate
      router as the destination.
- [ ] Reused hops carry source and freshness metadata and are distinguishable
      from fresh observations.
- [ ] Standalone traceroute passes its existing contracts unchanged.
- [ ] The workflow preserves authorized scope, final-wire checks, timestamps,
      cancellation, evidence ceilings, and platform capability failures.
- [ ] Linux, macOS, and Windows support and runtime evidence are recorded
      independently.

[m5]: m05-host-discovery.md
[m6]: m06-port-planning-inference.md
[m7-fairness]: m07-adaptive-scheduling.md#m74-per-host-fairness-and-deadlines
[trace-request]: ../../crates/packetcraftr/src/traceroute/request.rs
[trace-plan]: ../../crates/packetcraftr/src/traceroute/plan.rs
[trace-engine]: ../../crates/packetcraftr/src/traceroute/engine.rs
[trace-report]: ../../crates/packetcraftr/src/traceroute/report.rs
[scan-report]: ../../crates/packetcraftr/src/scan/report.rs
[trace-command]: ../../crates/packetcraftr-cli/src/commands/traceroute.rs
[trace-output]: ../../crates/packetcraftr-cli/src/output/traceroute.rs
[trace-contract]: ../../crates/packetcraftr/tests/integration/traceroute_contracts.rs
[nmap-discovery]: https://nmap.org/book/man-host-discovery.html
