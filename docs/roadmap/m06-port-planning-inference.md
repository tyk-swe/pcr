# M6: Port planning and state inference

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M1](m01-claims-evidence.md) | [M7](m07-adaptive-scheduling.md), [M11](m11-scan-informed-traceroute.md), [M12](m12-tcp-diagnostic-scans.md), [M13](m13-sctp-ip-protocol.md) |

Catalog selection, mixed plans, and inference are implemented; independent
comparison-corpus and native-platform close gates remain open.

## Behavior and decisions

- Project-authored `port-catalog` 1.0.0 has 73 RFC-cited TCP/UDP names and six
  topical presets. Select names, `@preset`, or `tcp:`/`udp:` terms. No frequency
  ranking or default set exists; `@all` is explicit. Provenance accompanies data.
- `--exclude-ports` applies after expansion and before maximum-port, policy,
  preparation, and list-mode admission. M5 discovery uses the same exclusions.
- `--curated-udp-payloads` selects seven original RFC-cited `udp-payloads` 1.0.0
  profiles: DNS, mDNS, RPC bind, NTP, SNMPv3, STUN, CoAP. Operator profiles win;
  each overridden port and dataset identity is published.
- `Request::endpoints` contains typed TCP/UDP selections under one operation
  budget. Address, transport, port, and interface distinguish endpoints through
  correlation, collection, and output. ICMP echo stays portless.
- Port hints and configured application checks are not identification.
  Attempt outcomes stay unchanged beside inference. Every sequence belongs to
  supporting, conflicting, unanswered, or failed evidence; late/duplicate/
  ambiguous frames remain unattributed.
- Inferred states are `open`, `closed`, `filtered`, `open_or_filtered`, `unknown`.
  UDP silence remains timeout evidence and can infer `open_or_filtered`.
  Socket capacity/deadline/local failures infer no port state. `unfiltered`
  awaits M12; idle-specific `closed|filtered` is outside scope.
- `--method raw|tcp-connect|auto` defaults raw; `--connect` aliases connect.
  Explicit methods never fall back. Automatic choice reads build capability and
  publishes its reason, not runtime privilege. Kernel socket evidence is not wire.
- Output/v8 introduced plans, hints, inference, unattributed frames, endpoint
  events, and list ports. Current v13 retains them under
  [compatibility](../consumer-compatibility.md#output-family-v8).

[Port inference](../scanner-evidence.md#port-inference) owns the rule tables.
[Data policy](../scanner-data-policy.md) owns import/review limits.

## Evidence

Owner-local and public contracts cover each inference rule, silence, ICMP errors,
contradictions/order, malformed/lost/duplicate/late replies, mixed tcp/53+udp/53,
exclusion wire checks, method refusal, capacity backpressure, provenance, and
frozen-schema conformance. See
[workflow pipeline contracts](../../crates/packetcraftr/tests/integration/scan_pipeline_contracts.rs),
[selection matrix](../../crates/packetcraftr/tests/integration/port_selection_matrix.rs),
and [CLI planning contracts](../../crates/packetcraftr-cli/tests/integration/port_planning_contracts.rs).

One historical Linux veth run disabled checksum offload, selected mixed
`tcp:18080-18082` and three UDP ports, excluded tcp/18081, and retained udp/18081
separately. UDP echo inferred open; silent bound/closed UDP inferred
open_or_filtered. This is not exact-revision cross-platform acceptance.

## Known limits

Frequency-ranked top ports need a reviewed source; Nmap data is rejected and
IANA registry terms remain under review. A capture-capable build without privileges
still chooses raw in automatic mode and fails at execution.
M5 fixed the earlier fast-reply completion-marker race using submission-start
eligibility, without claiming wire departure or identity.

## Remaining gates

- Add independently expected mixed-plan, silent-UDP, and contradictory-attempt
  scenarios to [M2's corpus](m02-ground-truth-benchmarks.md); the injected scanner
  matrix measures attempt classifications, not every new inference.
- Retain M6-specific exact-revision native inference acceptance across supported
  platforms under [M3](m03-native-validation.md). M5 discovery evidence cannot
  substitute for it.

All implementation criteria have fixture evidence; these close gates keep M6
**In progress**.
