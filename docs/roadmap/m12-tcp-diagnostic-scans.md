# M12: TCP diagnostic scans

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M6](m06-port-planning-inference.md) | ACK/window and flag-dependent diagnostics |

Software implementation is present; native cross-platform acceptance and
independent ground truth remain open, so M12 stays **In progress**. No native
parity or completed close gate is claimed. Usage and limits are in
[TCP diagnostics](../tcp-diagnostics.md).

## Implemented decisions

- Modes: `syn` (default), `ack`, `window`, `fin`, `null`, `xmas`, `maimon`, and
  `custom`. Flags are `SYN=0x002`, `ACK`/`window`=`0x010`, `FIN=0x001`, `NULL=0`,
  `Xmas=0x029` (FIN, PSH, URG), `Maimon=0x011` (FIN, ACK); custom accepts
  `0..=0x1ff` with no reserved bits.
- The request mode applies to scan-stage TCP endpoints only. Discovery TCP stays
  SYN; UDP and ICMP are unaffected; connect, traceroute, and identification
  probes build their own segments. A non-SYN mode needs the raw method and one
  scan TCP endpoint; it fails before resolution or I/O otherwise, and an explicit
  or automatic method never falls back to connect.
- Probe sequence stays the operation sequence. A probe with ACK carries the
  nonzero per-sequence acknowledgment `sequence + 0x50435201`, so a bare reset
  (sequence equal to the request acknowledgment) binds to one probe and retries
  never share reset identities. ACK-less probes carry acknowledgment zero. The
  final wire check requires the exact flags, acknowledgment, endpoint, address,
  sequence, empty options, and no payload.
- Correlation reuses the shared matcher. SYN correlation is unchanged; a SYN/ACK
  answering a probe without SYN is an uninterpreted reply, not evidence of open.
  Corrupt, unrelated, or mis-identified replies stay rejected.
- Attempt classification never claims open for a diagnostic segment: ACK, window,
  and custom resets, and SYN/ACK or other TCP segments, are `unknown`; FIN-family
  resets are `closed`. ICMP port-unreachable is `unreachable` for diagnostic modes.
  Silence stays `timeout`. The correlated reply window is retained as observed.
- Inference tables (rule IDs `tcp_<mode>.<reason>`):
  ACK: reset→`unfiltered`; unreachable→`filtered`; time exceeded and other→`unknown`;
  silence→`filtered`. Window: reset window >0→`open`, 0→`closed`, missing→`unknown`;
  unreachable→`filtered`; time exceeded and other→`unknown`; silence→`filtered`.
  FIN/NULL/Xmas/Maimon: reset→`closed`; unreachable→`filtered`; time exceeded and
  other→`unknown`; silence→`open_or_filtered`. Custom: any reply or silence→`unknown`.
  `unfiltered` never means open; operational failures never imply a state.
- Output family v15 adds the effective `tcp_scan` (mode and flags), per-response
  `tcp_window`, `unfiltered`, and the diagnostic rule vocabulary; v6–v14 stay frozen.

## Software evidence

Injected-responder and serialization tests, not native runtime evidence:

- Owner tests: `scan/tcp.rs` (exact flags, acknowledgment identities, final-wire
  mutation rejection), `scan/inference/tests.rs` (every rule/state row, windows,
  ordering, partitions), and `scan/method/tests.rs` (no connect fallback).
- [`tcp_diagnostic_contracts.rs`](../../crates/packetcraftr/tests/integration/tcp_diagnostic_contracts.rs)
  drives an independent IPv4/IPv6 responder through the serial, pipelined, and
  adaptive engines: exact wire per mode, reset/silent/prohibited/unexpected
  behaviors, unrelated, corrupt, late, and reordered frames, a reset beside ICMP
  prohibition in both delivery orders, custom SYN-bearing sequence space, retries,
  discovery staying SYN, validation, policy, ceilings, and mid-flight failure.
- [CLI `tcp_diagnostic_contracts.rs`](../../crates/packetcraftr-cli/tests/integration/tcp_diagnostic_contracts.rs)
  covers parsing, method conflicts, list output, and aggregate/stream schema
  conformance with frozen v14.

## Remaining acceptance gates

- Exact-revision native acceptance on supported Linux, macOS, and Windows profiles
  under [M2](m02-ground-truth-benchmarks.md)/[M3](m03-native-validation.md);
  injected-responder tests are software evidence, not runtime evidence.
- Independent ground truth for stack-dependent window and FIN-family behavior
  across operating systems; the heuristics are documented as unreliable until then.
- Data review as the corpus grows. Idle/bounce/evasion remain outside scope.
