# M7: Adaptive scheduling and bounded performance

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M2][m2], [M6][m6] | [M8][m8], [M10][m10] |

Before M7, PacketcraftR scheduled every scan from fixed inputs: a timeout, an
attempt count, a window, and an optional rate ceiling. RTT was reported but did
not influence scheduling. Every endpoint received the same attempt count,
hosts were probed in address order, and ordinary TCP scanning had a
sixteen-connection process ceiling. The fixed schedule remains available;
opt-in adaptation now addresses those limitations within explicit bounds.

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

## Implementation status

The implementation gates are complete: `scan::Adaptive` and `Request.adaptive`
are public with `--adaptive` opt-in semantics (fixed remains the default), the
shared controller runs RTO estimation, selective retries with bounded backoff,
per-host absolute deadlines checked before preparation and at transmission,
AIMD windowing inside `min_window`..=`max_in_flight`, and inferred
`suspected_response_rate_limit` conditions; raw waves run through the real
pipeline with omission events and honest peak tracking; connect scans share a
`ConnectBudget` operation ceiling beneath the unchanged process pool of 16;
and output family v10 publishes the `scheduling` summary and host
`incomplete` state. Native Linux/macOS/Windows runtime evidence and the
accepted-optimization comparison against the [M2][m2-benchmarks] baseline are
still open, so no throughput or performance acceptance is claimed.

## Scheduling behavior

Adaptive scheduling is opt-in with `--adaptive`; the fixed schedule stays the
default and is unchanged, and the tuning options only apply when adaptive mode
is requested. Bounds and defaults: `--min-timeout-ms` 10 (so `--timeout-ms`
below 10 needs a smaller `--min-timeout-ms`), `--max-timeout-ms` defaults to
`--timeout-ms`, `--min-window` 1, `--initial-window` min(4, max-in-flight),
`--host-timeout-ms` defaults to `--max-duration-ms`, `--retry-backoff-ms` 100,
and `--max-backoff-ms` 1000, with `min ≤ initial ≤ max-in-flight` and
`min-timeout ≤ timeout ≤ max-timeout` validated at the boundary.

Each scoped host keeps a TCP-style RTT estimator: the first verified
first-attempt reply seeds SRTT=R and RTTVAR=R/2, later samples update with
α=1/8 and β=1/4, and the timeout is SRTT+max(1ms, 4·RTTVAR) clamped to
`--min-timeout-ms`..=`--max-timeout-ms`. Only verified first-attempt replies
sample; until a host has its own sample its timeout is the operation estimate
or the request timeout, whichever is more conservative. Retry attempts start `--retry-backoff-ms`·2^(n-2) after
silence, capped at `--max-backoff-ms`, and silent endpoints retry at most
`--attempts` times.

Ordering is deterministic: hosts take turns in selection order, endpoints
within a host in request order, and sequence numbers are reserved per attempt
so retries need no renumbering. Every host's deadline anchors at the moment
its first admitted probe was selected and ends `--host-timeout-ms` later
inside the operation deadline; authorization, admission, preparation, pacing,
and transmission all spend it, and an endpoint whose share is spent sends
nothing and publishes no probe evidence while the host reports
`scan=incomplete`. A connect admission whose worker never called
the provider also leaves the host incomplete; its `attempted: false` record is
not network loss and does not contribute to rate-limit inference.
The admission window starts at
`--initial-window`, grows additively after enough verified replies, halves once per
lossy wave, and stays within `--min-window`..=`--max-in-flight`.

Rate limiting is only ever inferred from observed replies: a host publishes
`suspected_response_rate_limit` after at least 8 completed probes with at
least 2 control errors from the same responder (ICMP port/destination
unreachable or TCP reset) beside at least 4 losses, with the cited sequences
on the condition. Silence alone never infers it, the inference names loss or
filtering as alternatives, and handling slows that host's sends to at least
min(`--max-backoff-ms`, max(`--retry-backoff-ms`, host RTO)) without ever
exceeding `--rate` or any deadline. Ordinary socket errors cannot reveal the
control issuer, so connect scans never infer the source-specific condition;
a connect endpoint still drives window growth, selective retry, and backoff
from its replies and silence.

Sequence numbers are preauthorized over the original target order, so a host
filtered by neighbor or discovery work leaves stable ordinal holes rather
than renumbering the survivors: every wire identity admission prepared —
source ports, IP identifications, DNS transaction ids — is the one that
executes. Admission itself walks attempts-then-endpoints-then-hosts to mirror
live round-robin waves, retains only per-probe and per-route maxima across
bounded wave-sized chunks so any live wave — filtered or shifted — is checked
conservatively against `max_prepared_bytes`, and unions capture interfaces
across chunks whenever a wave could span more than the 15-source bound, so
neither path can materialize an unadmitted wave mid-operation.

Connect scans share the same controller: `max_in_flight` is the operation
admission ceiling held by a `ConnectBudget`, the process pool of 16 workers is
unchanged, windows above it queue with backpressure that consumes no attempts,
and `retries_started` counts only additional starts the provider actually
made. Completed or failed provider results queue behind
`min(--max-in-flight, 16)` descriptors — the pool cannot hold more live
sockets — while the configured window and reported admission ceiling stay as
declared.

Reports publish `scheduling.mode` (`fixed` or `adaptive`), the effective
adaptive configuration, `observed_peak_window` (the largest pending count the
operation actually held, not a throughput rate), `retries_started` (additional
probe starts after the first), conditions with cited sequence evidence, and
`incomplete` host identities. Planned duration for adaptive work is a
conservative serial upper projection — `--max-timeout-ms` per probe plus
pacing, capped retry gaps, and worst inferred per-host spacing — which excludes
provider overrun and contended worker waits; the operation deadline remains
the hard bound.

For example, ordinary TCP scans need no raw-packet privileges:

```sh
packetcraftr scan --connect 127.0.0.1 --ports 8000-8003 \
  --adaptive --attempts 3 --max-in-flight 4 --initial-window 2 \
  --timeout-ms 100 --min-timeout-ms 10 --max-timeout-ms 100 \
  --host-timeout-ms 5000 --max-duration-ms 30000
```

The initial timeout must fit the configured timeout bounds. Adaptive duration
admission uses the conservative projection above, not an optimistic estimate
from a fast first reply; lower ceilings or a larger finite operation budget may
be needed for large plans.

## Validation evidence and remaining gates

The local Linux validation covers the workspace tests, portable library tests,
Clippy with warnings denied, schema conformance, and public IPv4/IPv6 fair-host,
deadline, retry, inferred-rate-spacing, and native-worker lease contracts.
The frozen pre-change binaries and baseline reports remain under
`target/validation/baseline-bin/` and `target/validation/m07-baseline*.json`.
Three repetitions of the adaptive M2 inventory produced 264 correct case-runs;
all 88 corresponding cells met the **proposed**, not agreed, latency, work, and
peak-RSS nonregression budgets. The final-binary reports are
`m07-candidate-final.json` and `m07-comparison-final.json` under
`target/validation/`.

The additional real-clock injected-provider scenarios use one current binary
in both fixed and adaptive modes. They are not a replacement for the frozen
baseline or native-platform runtime evidence:

| Scenario | Family | Fixed median operation ms | Adaptive median operation ms | Actual probe starts, fixed → adaptive |
| --- | --- | ---: | ---: | --- |
| 16 responsive ports, three-attempt ceiling | IPv4 | 41.243 | 25.613 | 48 → 16 |
| 16 responsive ports, three-attempt ceiling | IPv6 | 38.766 | 20.601 | 48 → 16 |
| One silent and one responsive port | IPv4 | 44.900 | 30.741 | 6 → 4 |
| One silent and one responsive port | IPv6 | 46.066 | 32.302 | 6 → 4 |

For 128 responsive ports with a 32-attempt ceiling and the same 128 KiB logical
preparation ceiling, fixed mode rejects before capture or transmission;
adaptive mode completes with 128 starts in both families. This is a bounded
admission result, not a like-for-like latency improvement over a successful
fixed run. All 36 controlled case-runs matched their independent outcome/work
oracles; the largest median candidate peak-RSS increase was 128 KiB. Peak RSS
covers the child process lifetime and is distinct from logical preparation
and retained-evidence byte charges.

Reproduce these comparisons with:

```sh
cargo build --locked -p packetcraftr-cli
cargo build --locked -p packetcraftr --example scanner_fixture --example scheduling_fixture
python3 scripts/benchmark-scanner.py --binary target/debug/packetcraftr \
  --fixture-binary target/debug/examples/scanner_fixture --adaptive \
  --repetitions 3 --report target/validation/m07-candidate-final.json
python3 scripts/compare-scheduling.py \
  --baseline target/validation/m07-baseline-current-corpus.json \
  --candidate target/validation/m07-candidate-final.json \
  --report target/validation/m07-comparison-final.json
python3 scripts/benchmark-adaptive-scenarios.py \
  --fixture-binary target/debug/examples/scheduling_fixture --repetitions 3 \
  --report target/validation/m07-controlled-scenarios-final.json
```

The final controlled report supersedes the earlier failed
`m07-controlled-scenarios.json`: that run checked the opaque outer error text
instead of the prepared-limit cause and used whole-file hashing that inflated
the parent's memory footprint before child launch. The corrected harness
retains failed observations and uses streaming hashes.
The final measurements include the unsampled-host bootstrap guard; older
candidate and verified reports remain preserved rather than overwritten.

Native isolated Linux validation could not start: `unshare` was denied when
writing `/proc/self/uid_map`. `m07-native-isolated.json` preserves the launcher
error and marks all eight scenarios `not_exercised`. No permission workaround
was applied. A privileged isolated Linux lane, macOS and Windows runtime
evidence, and agreement on the proposed performance targets are still required
before closing M7 or accepting an optimization. No native-throughput,
cross-platform speedup, or increased process-capacity claim is made.

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

- [x] Virtual-clock and fake-provider tests verify pacing, fair progress, retry
      ceilings, finite deadlines, backpressure, and cleanup.
- [x] Cancellation does not release a native permit while its resource or
      provider work is still alive.
- [x] No adaptive behavior exceeds an operation-wide limit.
- [x] Baseline and candidate runs record accuracy, latency, work, and peak
      memory on the same fixtures and settings.
- [ ] Performance targets are agreed against that baseline before an
      optimization is accepted.
- [x] No output or document presents a configured rate or window as achieved
      throughput.
- [ ] Every claimed optimization has Linux, macOS, and Windows runtime
      evidence.
- [x] Retained and prepared state stays bounded, including fail-closed
      oversized-plan cases.

[m2]: m02-ground-truth-benchmarks.md
[m2-benchmarks]: m02-ground-truth-benchmarks.md#m23-workflow-benchmarks
[m6]: m06-port-planning-inference.md
[m8]: m08-service-identification.md
[m10]: m10-os-identification.md
