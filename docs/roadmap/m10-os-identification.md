# M10: OS identification

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M5](m05-host-discovery.md), [M7](m07-adaptive-scheduling.md) | Qualified remote stack observations |

No OS probe set, fingerprint representation, matching corpus, or result exists.
Packet codecs and passive JA3/JA4 client fingerprints do not identify a remote OS.

## Intended behavior

- Define independent, finite IPv4/IPv6 probe sets before corpus/matcher design.
  Record suitability, prerequisites such as responsive open/closed endpoints,
  missing responses, and intermediary effects; unsuitable targets are inconclusive.
- Bound probes, retries, bytes, response windows, retained evidence, and matching.
  Reauthorize final endpoint/bytes; packet construction alone is not OS scanning.
- Match a reviewed original/redistributable corpus with independent version,
  provenance, maintenance, and coverage. No Nmap database import is presumed legal.
- Publish observed fingerprint fields separately from ranked qualified candidates.
  Missing/contradictory evidence remains visible, with supported granularity only.
  NATs, firewalls, proxies, and stack customization may change observations.
  No authenticated identity or probability follows from ordinal confidence.

## Decisions before implementation

Set the smallest explicit probe set and bounded representation for each family;
choose suitability/refusal rules, supported output granularity, scoring/confidence,
and corpus ownership/refresh. Set training/held-out partitions before rule tuning.
A new machine family is required if existing meanings/shapes would change.

## Acceptance gates

Independent fixtures must cover known, unknown, unsuitable, partial, conflicting,
and intermediary-modified stacks in IPv4/IPv6. Report held-out coverage,
uncertainty, and stated accuracy separately from observed-field fidelity and
runtime/performance. Record exact-revision native runs on supported platforms
under [M2](m02-ground-truth-benchmarks.md)/[M3](m03-native-validation.md).

Keep [evidence semantics](../scanner-evidence.md),
[data review](../scanner-data-policy.md), and
[consumer compatibility](../consumer-compatibility.md) synchronized. M10 remains
**Planned**; no implementation or acceptance is claimed.
