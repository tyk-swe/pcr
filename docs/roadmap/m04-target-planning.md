# M4: Target planning

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Complete | [M1](m01-claims-evidence.md) | [M5](m05-host-discovery.md) |

## Outcome and decisions

- Bounded line-oriented target/exclusion manifests share argument admission.
  Blank lines and `#` comments are ignored; limits are combined across files
  (1 MiB, 4,096 physical lines, 512 bytes per declaration), tightened only downward.
  One `-` stdin consumer is allowed across manifests, payload, and profile inputs.
- `scan --list` publishes the same selected targets and declaration provenance
  without target/neighbor packets. Hostname resolution remains explicitly
  authorized and reported; it is not advertised as network-free.
- Exclusions remain numeric. Zone-qualified unicast `fe80::/10` targets carry
  both declared zone and resolved interface. Name/index aliases coalesce only
  when they identify the same interface; ambiguity fails before active work.
- Scope remains part of raw route, socket, endpoint, and correlation identity.
  Output first gained scope/list records in v7; current v12 retains them under
  the [consumer policy](../consumer-compatibility.md#output-family-v7).
- Octet ranges, hostname/CIDR shorthand, and random/unbounded generation remain
  outside this milestone. M6 owns the later list-mode port selection.

## Completion evidence

Reviewed implementation and fixtures
`8e010a0b9eac118aa13384f0b854111a73d47d76` closed M4 on 2026-10-07.
The [acceptance records](evidence/m04/README.md) retain commands, corpus/executable
identity, output, scope markers, and separate work/latency/retention/RSS measurements.

- Recording-provider and CLI contracts verify numeric zero-I/O listing,
  authorized DNS, source equivalence, exclusions, malformed/oversized inputs,
  duplicate diagnostics, family selection, and scope refusal/propagation.
- Independent dataset 1.1.0 produced 264 matching case-runs across 88 cells,
  repeated three times. Raw/traceroute benchmarks use injected providers;
  connect benchmarks use native sockets. No Nmap comparison was run.
- Twenty scoped native profile executions passed on Linux, macOS ARM/Intel,
  and Windows; [reviewed run 37549075757](https://github.com/tyk-swe/pcr/actions/runs/37549075757)
  records the host-local lanes. Linux also passed the eight isolated scenarios.
- The [gap matrix](nmap-gap-matrix.md) marks manifests, listing, and scoped
  targets present with constraints. M4 has no remaining gate.

## Limits

Portable builds without interface enumeration refuse scoped selection.
macOS complete-header raw IPv6 remains unsupported. Focused host-local reports
leave the seven unrelated M3 scenarios unselected; their global incompleteness
does not erase M4 evidence or close broader M2/M3 gates. See
[native validation](../native-validation.md) for current validation routes.
