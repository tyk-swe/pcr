# M12: TCP diagnostic scans

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M6](m06-port-planning-inference.md) | ACK/window and flag-dependent diagnostics |

Software implementation, dataset 1.7.0 diagnostic scenarios, and the native
acceptance runner are present. Cross-platform recordings and broader OS stack
truth remain open. Usage and rule tables live in
[TCP diagnostics](../tcp-diagnostics.md) and
[scanner evidence](../scanner-evidence.md#port-inference).

## Implemented decisions

- Modes: `syn` (default), `ack`, `window`, `fin`, `null`, `xmas`, `maimon`, and
  observation-only `custom` (`0..=0x1ff`). Non-SYN modes apply only to raw
  scan-stage TCP endpoints and never fall back to connect.
- ACK-bearing probes carry per-sequence acknowledgment `sequence + 0x50435201`
  so bare resets bind to a single attempt; ACK-less probes carry `0`. Final wire
  checks enforce exact flags, acknowledgment, empty options, and empty payload.
- Attempt classification never claims `open` for a diagnostic probe (FIN-family
  reset is `closed`; other TCP replies are `unknown`; port-unreachable is
  `unreachable`). Correlated direct TCP replies retain `tcp_window`.
- Output/v15 adds `tcp_scan` (`{mode, flags}`), `tcp_window`, `unfiltered`, and
  `tcp_<mode>.*` rules ([v15 contract](../consumer-compatibility.md#output-family-v15)).

## Evidence and native route

- Unit and integration suites (`scan/tcp.rs`, `scan/inference/tests.rs`,
  [`tcp_diagnostic_contracts.rs`](../../crates/packetcraftr/tests/integration/tcp_diagnostic_contracts.rs),
  and [CLI contracts](../../crates/packetcraftr-cli/tests/integration/tcp_diagnostic_contracts.rs))
  cover serial, pipelined, and adaptive execution, noise/reordering/duplicates,
  and v15 schema conformance.
- Dataset **1.7.0** adds eight dual-stack `tcp_diagnostic_scenarios` across all
  seven modes.
- [`test-tcp-diagnostics-native.py`](../../scripts/test-tcp-diagnostics-native.py)
  (`packetcraftr.tcp-diagnostic-native-evidence/v1`, workflow `scenario=tcp_diagnostics`)
  provisions an independent Linux reply peer + kernel peer in fresh namespaces
  and host-local macOS/Windows loopback sockets across five profiles. See
  [native validation](../native-validation.md#m12-tcp-diagnostic-acceptance).

## Remaining acceptance gates

- Exact-revision native acceptance on supported Linux, macOS, and Windows profiles
  under [M2](m02-ground-truth-benchmarks.md)/[M3](m03-native-validation.md).
- Independent ground truth for stack-dependent window and FIN-family behavior
  across operating systems.
