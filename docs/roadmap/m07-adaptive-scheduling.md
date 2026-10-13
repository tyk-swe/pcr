# M7: Adaptive scheduling and bounded performance

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M2](m02-ground-truth-benchmarks.md), [M6](m06-port-planning-inference.md) | [M8](m08-service-identification.md), [M10](m10-os-identification.md) |

Bounded adaptive scheduling is implemented; agreed performance targets and
native runtime acceptance remain open. Fixed scheduling is default.

## Decisions made

`scan::Adaptive` / `Request::adaptive` / `--adaptive` enables the shared
raw/connect controller (output/v10, retained in [v15](../consumer-compatibility.md#output-family-v10)).

| Setting | Default |
| --- | --- |
| Minimum / maximum timeout | 10 ms / request timeout |
| Minimum / initial window | 1 / `min(4, max_in_flight)` |
| Host timeout | Operation maximum duration |
| Retry / maximum backoff | 100 / 1,000 ms |

- First verified first-attempt sample sets `SRTT = R`, `RTTVAR = R/2`; updates
  use `α = 1/8`, `β = 1/4`, `RTO = SRTT + max(1 ms, 4·RTTVAR)` clamped to `[min, max]`.
  Retries wait `backoff · 2^(n−2)` up to `max_backoff`.
- Hosts take turns in selection order within bounded preparation waves (`≤ 15`
  interfaces). Per-host deadlines include authorization, preparation, pacing,
  callbacks, and sends; expired unsent work marks the host `incomplete`.
- Windows grow additively on verified replies and halve once per lossy wave.
  `suspected_response_rate_limit` requires `≥ 8` completions, `≥ 2` same-responder
  ICMP errors/resets, and `≥ 4` losses, pacing at `≥ min(max_backoff, max(retry_backoff, RTO))`.
- `ConnectBudget` sits beneath the 16-worker native pool; unstarted work
  (`attempted=false`) counts as neither loss nor retry.

```sh
packetcraftr scan --connect 127.0.0.1 --ports 8000-8003 --adaptive \
  --attempts 3 --max-in-flight 4 --initial-window 2 --timeout-ms 100 \
  --min-timeout-ms 10 --max-timeout-ms 100 --host-timeout-ms 5000 \
  --max-duration-ms 30000
```

## Recorded measurements and remaining gates

| Scenario | IPv4 fixed → adaptive median | IPv6 fixed → adaptive median | Starts |
| --- | --- | --- | --- |
| 16 responsive ports, three attempts | 41.243 → 25.613 ms | 38.766 → 20.601 ms | 48 → 16 |
| Silent and responsive endpoint | 44.900 → 30.741 ms | 46.066 → 32.302 ms | 6 → 4 |

Three repetitions of the 88-cell corpus (264 runs) and 36 controlled runs
(`scripts/benchmark-scanner.py --adaptive`, `scripts/compare-scheduling.py`,
`scripts/benchmark-adaptive-scenarios.py`) passed with at most 128 KiB median
peak-RSS delta. M7 stays **In progress** until agreed performance criteria and
privileged Linux/macOS/Windows runtime evidence are retained.
