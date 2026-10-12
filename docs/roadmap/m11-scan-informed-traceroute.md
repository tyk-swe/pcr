# M11: Scan-informed traceroute

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M5](m05-host-discovery.md), [M6](m06-port-planning-inference.md) | Bounded multi-host path diagnostics |

The workflow is implemented; fresh undelayed native acceptance and independent
path-ground-truth coverage remain open. Standalone single-target traceroute
keeps its existing contract and shapes.

## Behavior and decisions

- `Client::trace_hosts` reuses bounded standalone probes/classification/evidence
  for multiple authorized hosts. Responsive selection prefers SYN/ACK, then reset,
  then echo, breaking ties by lowest sequence. Router errors never select a target.
  UDP requires an explicit strategy because destination ports change.
- Missing observations without fallback and scoped targets become `not_traced`.
  Every trace reauthorizes final wire/scope and keeps partial failures.
- Raw-only `scan --traceroute` runs before PTR lookup under remaining budgets.
  Connect/list reject it upfront. Host-order sequence numbers, pacing, retained
  evidence, packet/byte ceilings, and operation deadline are shared.
- Optional within-operation reuse is bounded by family, transport, scope, and
  freshness. Reused hops carry source/probe sequences, observed time, and age;
  they are claims, never new observations. Cache lifetime cannot exceed operation
  or maximum age. Default is no reuse.
- Output/v11 introduced scan trace summaries/records; current v14 retains them
  under [compatibility](../consumer-compatibility.md#output-family-v11).

## Recorded fixtures

Injected paths compare actual fixture topology and send counts:

| Condition | Without → with reuse |
| --- | --- |
| Four hosts sharing four routers | 20 → 11 probes |
| Divergent paths | 15 → 14 |
| Expired one-second cache | 20 → 20 |

A four-second age reuses only eligible hops and re-probes others. These controlled
providers prove workflow behavior, not native parity or production efficiency.

The checked-in corpus adds `trace_path_scenarios` (dataset 1.5.0) for a shared
path, divergent paths, and a shared path with a silent hop. Each states its
expected hop addresses, probe counts with and without reuse, and the hops the
later hosts must reuse; `traceroute_hosts_contracts.rs` reproduces them through
`Client::trace_hosts` on the path fixture. ECMP and reconvergent paths stay out
until the fixture can choose a path per probe.

One historical Linux namespace run on documentation addresses used disabled
checksum offload and replies delayed 5 ms to avoid the then-completion-marker
race. Two hosts shared two routers at three hops; a third used one router at two.
TCP/22 SYN/ACK/reset selected probes; echo discovery followed the same paths.
Counts were 8→7 with 30-second reuse and 8 with 1 ms age, before added neighbor
accounting. They were not rerun and are not updated undelayed acceptance.
Initially offloaded-checksum SYN/ACK was correctly integrity-rejected.
The run also checked streamed stage order and a two-probe postscan refusal.

## Known limits

- Matching anchor routers do not prove a shared prefix under reconvergence/ECMP;
  reused claims may be wrong. Descending anchor probes can add work.
- Hosts trace sequentially; a slow host delays later ones. No cross-host native
  throughput or speedup is accepted.
- Remaining evidence/time/probe limits can refuse trace after a successful scan
  but before trace I/O. No traceable host needs no trace allowance.
- Trace TCP/UDP source port defaults to 49151, apart from generated scan UDP
  ports 49152–65535. Automatic/Layer 2 timeouts must outlast a pacing interval
  for neighbor requests. No response/fallback means no trace.

## Remaining gates

Provision independently expected reconvergent and ECMP paths in
[M2](m02-ground-truth-benchmarks.md); shared, divergent, and silent-hop paths are
now `trace_path_scenarios` there. Repeat native Linux with immediate
replies after M5's submission-start fix, then retain applicable macOS/Windows
runs under [M3](m03-native-validation.md). Preserve standalone contracts, exact
bytes/timestamps, scope, cancellation, and failed evidence. M11 stays **In progress**.
