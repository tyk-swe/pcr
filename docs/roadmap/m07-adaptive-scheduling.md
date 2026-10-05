# M7: Adaptive scheduling and bounded performance

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M2][m2], [M6][m6] | [M8][m8], [M10][m10] |

PacketcraftR schedules a scan from fixed inputs: a timeout, an attempt count, a
window, and an optional rate ceiling. It measures RTT and reports it, and does
nothing with the measurement. Every endpoint is planned for the same number of
attempts whether or not it answers, hosts are probed in address order, and
ordinary TCP scanning is capped at sixteen concurrent connections for the whole
process. That is predictable and bounded, and it does not adapt to the network.

This milestone makes scheduling respond to what the network does, inside the
same hard limits, and proves each change against the [M2][m2-benchmarks]
baseline before it is accepted.

## Outcome

- Timeouts follow a bounded RTT estimate instead of one fixed value.
- Retries are spent on the probes that need them, with backoff.
- Rate limiting by the target or path is detected and handled.
- Hosts make fair progress and each has its own deadline.
- Windows adapt within configured bounds.
- Ordinary TCP scanning is scheduled under explicit process-wide and
  operation-wide ceilings that have been redesigned and validated.

## Baseline

| | PacketcraftR at `22c7d182d577` | Nmap reference |
| --- | --- | --- |
| Timing inputs | Fixed `--timeout`, `--attempts` (default 1, at most 32), `--max-in-flight` (default 1, at most 1,024), and an optional `--rate` probe-start ceiling ([request][scan-request], [limits][scan-limits]) | Dynamic timeouts, parallelism, retry selection, and rate-limit handling ([performance][nmap-performance]) |
| Use of RTT | [Reports][scan-report] summarize RTT; [planning][scan-plan] computes a conservative fixed schedule | RTT-driven timeouts ([performance][nmap-performance]) |
| Ordering | [Raw planning][scan-plan] follows address, attempt, then port order under global limits | Host grouping, per-host timeouts and delays, port ordering ([performance][nmap-performance], [port specification][nmap-ports]) |
| Connect scan | [Connect execution][connect-engine] is capped by the TCP provider's [`MAX_PENDING_CONNECTIONS`][tcp-provider], the process-wide worker capacity of 16 | Parallel host and probe scheduling ([performance][nmap-performance]) |
| Bounds | Probe, duration, prepared-byte, and evidence ceilings; cancelled workers keep their permits until cleanup finishes ([limits][scan-limits], [pipeline contracts][pipeline-contract]) | Timing templates and explicit limits ([performance][nmap-performance]) |

## Invariants

- Adaptation may reduce work or delay it. It never bypasses an operation-wide
  limit.
- Cancellation does not release a native permit while its resource or provider
  work is still alive.
- A higher configured rate or window is not evidence of achieved throughput.
- The 16-connection cap is a resource contract to redesign and validate, not a
  constant to raise without review.
- Retained and prepared state stays bounded. An oversized plan fails closed.

## Scope

### M7.1 RTT estimation and adaptive timeouts

A bounded RTT estimate that sets probe timeouts between configured minimum and
maximum values.

### M7.2 Selective retry and backoff

Retries are scheduled for the probes whose outcome calls for one, up to the
configured attempt ceiling, with backoff between attempts. An endpoint that
answered is not probed again to fill a quota.

### M7.3 Response-rate-limit handling

Detect when responses are being rate limited and slow down rather than record
losses as silence. Detection is published as a condition with its evidence;
handling it may delay work and never extends the operation past its deadline.

### M7.4 Per-host fairness and deadlines

- Scheduling makes progress across hosts instead of exhausting one before
  starting the next.
- Each host has its own deadline inside the operation's. A host that reaches
  it is reported as incomplete, not as scanned.

### M7.5 Adaptive windows

Configurable adaptive windows: the in-flight window adjusts within configured
bounds in response to losses and replies.

### M7.6 Connect scheduling and plan retention

- Ordinary TCP scanning is scheduled under explicit process-wide and
  operation-wide resource ceilings.
- Plan retention improves under the same ceilings. A plan that exceeds its
  ceiling fails closed.

## Change map

| Change | Start here |
| --- | --- |
| Schedule, ordering, retries | [`scan/plan.rs`][scan-plan], [`scan/engine.rs`][scan-engine] |
| Windows, pacing, backpressure | [`scan/executor/pipeline.rs`][scan-pipeline], [`probe/runner.rs`][probe-runner] |
| Clock and deadlines | [`clock.rs`][clock], [`deadline.rs`][deadline] |
| Ceilings | [`scan.rs`][scan-limits], [`scan/request.rs`][scan-request] |
| Connect scheduling | [`scan/connect/engine.rs`][connect-engine], netio [`tcp.rs`][tcp-provider], [`resources.rs`][netio-resources] |
| Virtual-clock contracts | [`scan_pipeline_contracts.rs`][pipeline-contract], [`connect_clock_contracts.rs`][connect-clock-contract] |

## Decisions to settle

1. The RTT estimator and its bounds (recommended: a smoothed mean-and-variance
   estimator of the kind TCP retransmission timers use, clamped between
   configured limits, chosen only after comparison on the M2 fixtures).
2. The performance targets (recommended: set per scenario after the M2 baseline
   is recorded; take no target from another tool's documentation).
3. What replaces the 16-connection cap (recommended: keep a process-wide
   ceiling, add an operation-wide one, and choose both from measured resource
   use on each platform).
4. The signal that identifies rate limiting (recommended: define it against the
   M2 fixtures and publish it as an inferred condition with its evidence).
5. Whether adaptation is on by default (recommended: opt-in until benchmarks
   show accuracy is preserved on every fixture, with the fixed schedule kept
   available so runs stay reproducible).
6. The default probe order (recommended: a deterministic documented order that
   interleaves hosts).
7. Whether RTT is estimated per host or per operation (recommended: per host,
   falling back to the operation's estimate until a host has samples).

## Exit criteria

- [ ] Virtual-clock and fake-provider tests verify pacing, fair progress, retry
      ceilings, finite deadlines, backpressure, and cleanup.
- [ ] Cancellation does not release a native permit while its resource or
      provider work is still alive.
- [ ] No adaptive behavior exceeds an operation-wide limit.
- [ ] Baseline and candidate runs record accuracy, latency, work, and peak
      memory on the same fixtures and settings.
- [ ] Performance targets are agreed against that baseline before an
      optimization is accepted.
- [ ] No output or document presents a configured rate or window as achieved
      throughput.
- [ ] Every claimed optimization has Linux, macOS, and Windows runtime
      evidence.
- [ ] Retained and prepared state stays bounded, including fail-closed
      oversized-plan cases.

[m2]: m02-ground-truth-benchmarks.md
[m2-benchmarks]: m02-ground-truth-benchmarks.md#m23-workflow-benchmarks
[m6]: m06-port-planning-inference.md
[m8]: m08-service-identification.md
[m10]: m10-os-identification.md
[scan-limits]: ../../crates/packetcraftr/src/scan.rs
[scan-request]: ../../crates/packetcraftr/src/scan/request.rs
[scan-plan]: ../../crates/packetcraftr/src/scan/plan.rs
[scan-engine]: ../../crates/packetcraftr/src/scan/engine.rs
[scan-report]: ../../crates/packetcraftr/src/scan/report.rs
[scan-pipeline]: ../../crates/packetcraftr/src/scan/executor/pipeline.rs
[connect-engine]: ../../crates/packetcraftr/src/scan/connect/engine.rs
[probe-runner]: ../../crates/packetcraftr/src/probe/runner.rs
[clock]: ../../crates/packetcraftr/src/clock.rs
[deadline]: ../../crates/packetcraftr/src/deadline.rs
[tcp-provider]: ../../crates/packetcraftr-netio/src/tcp.rs
[netio-resources]: ../../crates/packetcraftr-netio/src/resources.rs
[pipeline-contract]: ../../crates/packetcraftr/tests/integration/scan_pipeline_contracts.rs
[connect-clock-contract]: ../../crates/packetcraftr/tests/integration/connect_clock_contracts.rs
[nmap-performance]: https://nmap.org/book/man-performance.html
[nmap-ports]: https://nmap.org/book/man-port-specification.html
