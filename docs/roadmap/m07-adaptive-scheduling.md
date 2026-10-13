# M7: Adaptive scheduling and bounded performance

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M2](m02-ground-truth-benchmarks.md), [M6](m06-port-planning-inference.md) | [M8](m08-service-identification.md), [M10](m10-os-identification.md) |

Bounded adaptive scheduling is implemented; agreed performance targets and
applicable native runtime acceptance remain open. Fixed scheduling is default.

## Decisions made

`scan::Adaptive` / `Request::adaptive` / `--adaptive` enables one shared raw/connect
controller. Output/v10 introduced configuration, observed peak, retries,
conditions, and incomplete hosts; [current v15](../consumer-compatibility.md#output-family-v10)
retains them. No configured window is a throughput claim.

| Setting | Default |
| --- | --- |
| Minimum timeout | 10 ms |
| Maximum timeout | Request timeout |
| Minimum / initial window | 1 / min(4, max_in_flight) |
| Host timeout | Operation maximum duration |
| Retry / maximum backoff | 100 / 1,000 ms |

Validate min≤initial≤maximum timeout/window before I/O. A host's first verified
first-attempt sample initializes SRTT=R and RTTVAR=R/2; updates use α=1/8, β=1/4.
RTO=SRTT+max(1 ms,4·RTTVAR), clamped. Retries never sample RTT; unsampled hosts
use the conservative operation/request estimate. Retry n waits
backoff·2^(n−2), capped, under the attempt ceiling.

## Admission and fairness

- Hosts take turns in selection order, endpoints in request order; stable wire
  identities and sequence holes survive filtering/discovery. Bounded waves
  conservatively respect preparation bytes and the 15-source interface union.
- Host deadlines begin with the first admitted selected probe; authorization,
  preparation, pacing, output callbacks, and transmission spend them. Expired
  unsent entries create incomplete hosts, not network evidence.
- Windows grow additively after verified replies and halve once per lossy wave,
  within ceilings. Rate-limit suspicion requires≥8 completions, ≥2 same-responder
  ICMP errors/TCP resets, and ≥4 losses with cited sequences. Loss/filtering remain
  alternatives. Silence alone and connect errors never identify a rate limiter.
- Qualified slowing uses at least min(max_backoff,max(retry_backoff,hostRTO)),
  without overriding rate/deadline. Conservative projected duration includes
  timeouts, pacing, gaps, and slowing, not provider overrun or contention.
- ConnectBudget admission sits beneath the shared native pool of 16 workers.
  Larger windows backpressure without spending attempts; completion descriptors
  stay≤min(max_in_flight,16). Leases survive cleanup after timeout/cancellation.
  `attempted=false` is neither loss nor a retry start.

```sh
packetcraftr scan --connect 127.0.0.1 --ports 8000-8003 --adaptive \
  --attempts 3 --max-in-flight 4 --initial-window 2 --timeout-ms 100 \
  --min-timeout-ms 10 --max-timeout-ms 100 --host-timeout-ms 5000 \
  --max-duration-ms 30000
```

Run live examples only in an authorized disposable lab.

## Recorded measurements

Local reports under ignored `target/validation/` are frozen revision-bound history,
not retained cross-platform acceptance. Three repetitions of 88 scanner cells
produced 264 correct runs and met proposed, not agreed, nonregression targets.
Controlled injected-provider scenarios used real time and the same binary:

| Scenario | IPv4 fixed → adaptive median | IPv6 fixed → adaptive median | Starts |
| --- | --- | --- | --- |
| 16 responsive ports, three attempts | 41.243 → 25.613 ms | 38.766 → 20.601 ms | 48 → 16 |
| Silent and responsive endpoint | 44.900 → 30.741 ms | 46.066 → 32.302 ms | 6 → 4 |

Thirty-six controlled runs were correct; largest median peak-RSS increase was
128 KiB. For 128 responsive ports/32 attempts/128 KiB preparation, fixed mode
refused before I/O and adaptive completed 128 starts: not a like-for-like latency
comparison. No native throughput, broad speedup, or capacity increase is accepted.

The corrected `m07-scheduling-comparison-final.json` supersedes an earlier harness
that matched the outer error instead of its cause and inflated memory by whole-file
hashing. Streaming hashes and unsampled-host guards were reviewed; earlier failures
remain history. Linux isolation failed at `unshare` `/proc/self/uid_map`; all eight
scenarios were not_exercised, without bypassing the boundary.

## Reproduction and remaining gates

Build the CLI and `scanner_fixture`/`scheduling_fixture` examples. Run
`scripts/benchmark-scanner.py --adaptive --repetitions 3`,
`scripts/compare-scheduling.py` against the fixed current-corpus baseline, and
`scripts/benchmark-adaptive-scenarios.py`; retain commands, binaries, digests,
configuration, independent expectations, and process measurements.

Local workspace/portable/Clippy/schema regressions cover fairness, deadlines,
retries, and retained leases. M7 stays **In progress** until agreed performance
criteria and fresh privileged Linux/macOS/Windows runtime evidence are retained.
