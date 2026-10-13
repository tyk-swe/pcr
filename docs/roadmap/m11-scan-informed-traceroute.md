# M11: Scan-informed traceroute

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M5](m05-host-discovery.md), [M6](m06-port-planning-inference.md) | Bounded multi-host path diagnostics |

The workflow is implemented; fresh undelayed native acceptance and ECMP/reconvergent
ground-truth coverage remain open. Standalone single-target traceroute keeps its
existing contract.

## Behavior and decisions

- `Client::trace_hosts` and raw-only `scan --traceroute` run after scan and
  before PTR lookup under remaining budgets (connect/list reject upfront).
- Responsive probe selection prefers target SYN/ACK, then reset, then echo
  (lowest sequence tie); UDP or unanswered hosts require explicit
  `--traceroute-strategy`/`--traceroute-port` fallback, otherwise `not_traced`
  (scoped targets also report `not_traced`).
- Optional within-operation hop reuse (`--traceroute-reuse-max-age-ms`) is
  bounded by family, transport, scope, and age, publishing `reused_hops` with
  source host/probe provenance separately from fresh `hops`.
- Introduced in output/v11 and retained in v15; see
  [compatibility](../consumer-compatibility.md#output-family-v11).

## Recorded fixtures and remaining gates

| Condition | Without → with reuse |
| --- | --- |
| Four hosts sharing four routers | 20 → 11 probes |
| Divergent paths | 15 → 14 |
| Expired one-second cache | 20 → 20 |

- Dataset 1.5.0 `trace_path_scenarios` covers shared, divergent, and silent-hop
  paths through `Client::trace_hosts` (`traceroute_hosts_contracts.rs`).
- Historical Linux namespace evidence used a 5 ms reply delay before M5's
  submission-start freshness fix.
- M11 stays **In progress** pending reconvergent/ECMP corpus scenarios
  ([M2](m02-ground-truth-benchmarks.md)) and undelayed Linux/macOS/Windows
  native runs ([M3](m03-native-validation.md)).
