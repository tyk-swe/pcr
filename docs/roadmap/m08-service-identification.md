# M8: Service and version identification

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Complete | [M7](m07-adaptive-scheduling.md) | [M9](m09-tls-services-corpus.md) |

## Outcome and decisions

- `identify` / `Client::identify` runs explicitly over numeric endpoints
  (`Endpoint::from_scan` selects reported TCP-open and UDP-open/open-or-filtered
  endpoints) under four-scope budgets and final-endpoint reauthorization.
- Read-only SSH banner, HTTP HEAD, and nonrecursive DNS probes use anchored
  ASCII literals over parsed fields under the [data policy](../scanner-data-policy.md).
  Sensitive-service exclusions apply before planning (`--ignore-exclusions`
  overrides data only). See [service identification](../service-identification.md).
- Introduced in output/v12 and retained in v15
  ([compatibility](../consumer-compatibility.md#output-family-v12)), separating
  exact bytes and untrusted claims from matched candidates and ordinal confidence.

## Completion evidence

Corrected revision `99a9cf23216eb490892c0b6659e303d1a0b02c3d` (2026-10-10)
passed 1,440 cases across 20 profile executions on Linux, macOS ARM/Intel, and
Windows using IPv4/IPv6 and JSON/NDJSON ([evidence](evidence/m08/README.md),
dataset 1.4.0). M9 subsequently closed TLS and held-out corpus evaluation.
