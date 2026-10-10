# M8: Service and version identification

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Complete | [M7](m07-adaptive-scheduling.md) | [M9](m09-tls-services-corpus.md) |

## Outcome and decisions

`identify` / `Client::identify` is an explicit operation over numeric endpoints;
ordinary scans never start it. `Endpoint::from_scan` selects reported TCP-open
and UDP-open/open-or-filtered endpoints. Each invocation declares its own policy
and operation/host/connection/probe budgets; final endpoints and requests are
reauthorized before I/O.

Probes are limited to read-only SSH banners, HTTP HEAD, and reviewed nonrecursive
DNS questions on TCP/UDP, including nonstandard ports. No hidden resolution,
redirect following, authentication, arbitrary request bytes, or regex engine is
introduced. TLS-wrapped services remain M9 work. See the
[user guide](../service-identification.md) for controls and limits.

### M8.3 Probe and match documents

Core owns bounded, independently versioned probe/match and sensitive-service
exclusion documents under the [data policy](../scanner-data-policy.md). Matching
uses anchored ASCII literals over parsed fields and bounded version tokens.
Each probe carries a read-only review and maintenance/provenance record.
Exclusions apply before planning; `--ignore-exclusions` overrides only that data,
not policy or resource checks. UDP-profile `confirmed` still means configured
checks matched, not that a product was identified.

### Claims and output

Output/v12 separates exact observations from matched candidates and provenance.
Ordinal confidence is `claim` or `protocol`, not a probability. Banners are
unauthenticated; unknown or ambiguous evidence never manufactures an exact
version. Malformed/truncated replies retain their qualifications, and no result
is a vulnerability finding. See the
[v12 contract](../consumer-compatibility.md#output-family-v12).

## Completion evidence

The [evidence index](evidence/m08/README.md) links core, netio, workflow, and CLI
contracts to the independent inventory (dataset 1.4.0), covering nonstandard ports,
misleading/unknown/ambiguous replies, malformed/truncated data, deterministic
matching, exclusions, budgets, and final-endpoint authorization.

Corrected runtime records at `99a9cf23216eb490892c0b6659e303d1a0b02c3d`
on 2026-10-10 supersede the earlier `928ad8d555fe8b34abd144083612b54ace0fef1f`
reports: all 1,440 cases passed in 20 profile executions across Linux, macOS
ARM/Intel, and Windows, using IPv4/IPv6 and JSON/NDJSON. The index preserves
checkout/tree identities and a separate later local-validation record; these are
not new measurements of the current checkout.

M8 closes its applicable ground-truth and ordinary-socket gates. Broader M2/M3/M5/M7
native/performance acceptance and M9 held-out coverage/calibration remain open.
No new retained-state or peak-RSS benchmark baseline is claimed.
