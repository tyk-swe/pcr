# M13: SCTP and IP-protocol inventory

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M5](m05-host-discovery.md), [M6](m06-port-planning-inference.md) | SCTP diagnostics, IP-protocol inventory, and extra discovery families |

Software implementation, dataset 1.8.0 SCTP and IP-protocol scenarios, and the
native acceptance runner are present. Cross-platform recordings and broader OS
stack truth remain open.

## Implemented decisions

- SCTP raw scan modes: `init` (default, chunk type `1`) and `cookie-echo`
  (chunk type `10`) via `scan::SctpScan` / `--transport sctp` and
  `--sctp-scan init|cookie-echo`, with non-zero per-sequence correlation tags,
  `sctp:` port prefixes, and mixed `tcp,udp,sctp` port selections. SCTP port `0`
  is rejected.
- Standalone IP-protocol inventory: `scan::IpProtocolSelection` /
  `select_ip_protocols` (`0..=255` and inclusive ranges with exclusions applied
  before `max_ports`) via `--transport ip`, `--ip-protocols`, and
  `--exclude-ip-protocols`. Empty-payload IPv4/IPv6 headers with explicit
  protocol/next-header discriminators encode in strict mode without inventing
  transport headers or ports.
- Extra opt-in host-discovery probe families: `tcp-ack`, `icmp-timestamp`,
  `icmp-netmask`, `sctp` (`INIT`), and `ip` (`--discovery-ip-protocols`),
  sharing exclusions and finite operation budgets. IPv4-only ICMP timestamp and
  netmask probes fail typed when IPv6 targets are selected.
- Output/v16 adds `sctp_scan` (`{mode, chunk_type}`), `ip_protocol` (`0..=255`),
  `ip_protocols` list-mode selection, `icmp_request` (`timestamp` / `netmask`),
  `sctp_*` / `ip_protocol_*` / `icmp_timestamp_reply` / `icmp_netmask_reply` /
  `icmp_protocol_unreachable` host reasons, and `sctp_init.*`,
  `sctp_cookie_echo.*`, and `ip_protocol.*` inference rules
  ([v16 contract](../consumer-compatibility.md#output-family-v16)).

## Evidence and native route

- Unit and integration suites (`scan/sctp.rs`, `scan/ip_protocol.rs`,
  `scan/inference/tests.rs`,
  [`sctp_ip_protocol_contracts.rs`](../../crates/packetcraftr/tests/integration/sctp_ip_protocol_contracts.rs),
  and [CLI contracts](../../crates/packetcraftr-cli/tests/integration/sctp_ip_protocol_contracts.rs))
  cover serial, pipelined, and adaptive execution, ICMP error disambiguation,
  and v16 schema conformance.
- Dataset **1.8.0** adds dual-stack `sctp_ip_protocol_scenarios` covering
  `sctp-init`, `sctp-cookie-echo`, and `ip-protocol`.
- [`test-sctp-ip-protocol-native.py`](../../scripts/test-sctp-ip-protocol-native.py)
  (`packetcraftr.sctp-ip-protocol-native-evidence/v1`, workflow
  `scenario=sctp_ip_protocol`) tracks five-profile native validation.

## Remaining acceptance gates

- Exact-revision native acceptance on supported Linux, macOS, and Windows
  profiles under [M2](m02-ground-truth-benchmarks.md)/[M3](m03-native-validation.md).
- Independent ground truth for SCTP `COOKIE-ECHO` and IP-protocol stack behavior
  across operating systems.
