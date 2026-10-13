# M4: Target planning

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Complete | [M1](m01-claims-evidence.md) | [M5](m05-host-discovery.md) |

## Outcome and decisions

- Bounded line-oriented target/exclusion manifests share argument admission
  (combined 1 MiB, 4,096 lines, 512 bytes/declaration, one stdin consumer).
- `scan --list` publishes selected targets and declaration provenance without
  target/neighbor packets; authorized hostname resolution is reported.
- Exclusions are numeric. Zone-qualified unicast `fe80::/10` targets carry
  declared zone and resolved interface as part of route, socket, endpoint, and
  correlation identity (introduced in output/v7, retained in
  [v15](../consumer-compatibility.md#output-family-v7)).

## Completion evidence and limits

Reviewed revision `8e010a0b9eac118aa13384f0b854111a73d47d76` closed M4 on
2026-10-07 ([acceptance records](evidence/m04/README.md)):

- 264 matching case-runs across 88 cells (dataset 1.1.0, three repetitions) with
  separate work, latency, retention, and RSS metrics.
- 20 scoped native profile executions on Linux, macOS ARM/Intel, and Windows
  ([run 37549075757](https://github.com/tyk-swe/pcr/actions/runs/37549075757)),
  plus all eight Linux isolated scenarios.
- Portable builds without interface enumeration refuse scoped selection; macOS
  complete-header raw IPv6 remains unsupported ([native validation](../native-validation.md)).
