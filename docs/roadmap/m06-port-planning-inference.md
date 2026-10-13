# M6: Port planning and state inference

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M1](m01-claims-evidence.md) | [M7](m07-adaptive-scheduling.md), [M11](m11-scan-informed-traceroute.md), [M12](m12-tcp-diagnostic-scans.md), [M13](m13-sctp-ip-protocol.md) |

Catalog selection, mixed plans, and inference are implemented with checked-in
corpus scenarios; native-platform and Nmap comparison gates remain open.

## Behavior and decisions

- `port-catalog` 1.0.0 provides 73 RFC-cited TCP/UDP names and six presets (`@web`,
  `@mail`, `@name-services`, `@infrastructure`, `@legacy-services`, `@all`),
  with optional `tcp:`/`udp:` prefixes and `--exclude-ports` applied before budgets.
- `--curated-udp-payloads` selects seven `udp-payloads` 1.0.0 profiles (DNS,
  mDNS, RPC bind, NTP, SNMPv3, STUN, CoAP); operator `--udp-profiles` override per port.
- `Request::endpoints` keeps typed TCP/UDP endpoints distinct by address,
  transport, port, and scope under shared budgets; ICMP echo is portless.
- [Port inference](../scanner-evidence.md#port-inference) publishes `state`,
  `rule`, and supporting/conflicting/unanswered/failed sequence partitions
  beside attempt outcomes; late/duplicate/ambiguous frames stay unattributed.
- `--method raw|tcp-connect|auto` defaults to `raw` (`--connect` aliases
  `tcp-connect`); explicit methods never fall back, and `auto` selects from
  build capabilities.
- Introduced in output/v8 and retained in v15; see
  [compatibility](../consumer-compatibility.md#output-family-v8) and
  [data policy](../scanner-data-policy.md).

## Evidence and remaining gates

- [Workflow pipeline](../../crates/packetcraftr/tests/integration/scan_pipeline_contracts.rs),
  [selection matrix](../../crates/packetcraftr/tests/integration/port_selection_matrix.rs),
  [CLI planning](../../crates/packetcraftr-cli/tests/integration/port_planning_contracts.rs),
  and dataset 1.6.0 `inference_scenarios` verify mixed `tcp/53`+`udp/53`,
  silent-UDP, and contradictory-attempt rules in both IP families.
- Frequency-ranked top ports remain unbundled (Nmap data is rejected; IANA terms
  require per-registry review).
- M6 stays **In progress** pending exact-revision cross-platform native
  inference acceptance ([M3](m03-native-validation.md)) and Nmap differential
  comparison ([M2](m02-ground-truth-benchmarks.md)).
