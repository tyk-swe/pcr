# M1: Claims and evidence model

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Complete | None | [M2](m02-ground-truth-benchmarks.md), [M4](m04-target-planning.md), [M6](m06-port-planning-inference.md) |

## Outcome and decisions

M1 established the written model and data policy; it introduced no scanner
capability or unused public types. Types belong beside their first producer.
New inference meanings require a new contract family rather than reinterpreting
attempt classifications in already-published output.

### M1.1 Evidence vocabulary

[Scanner evidence](../scanner-evidence.md) separates attempt observations,
scan-dependent port inference, host observations, and operational failures.
Timeout/unreachable/unknown evidence remains visible. A backend failure is not a
network observation; an aggregate attempt classification is not port inference.

### M1.2 Scanner data policy

The [data policy](../scanner-data-policy.md) and
[provenance template](../scanner-data-provenance-template.md) require source,
license review, independent version, maintenance ownership, and fixture-based
coverage claims. Nmap's NPSL is not assumed compatible with AGPL redistribution.
Sources and packaging are reviewed per dataset at first import.

## Completion evidence

- [Vocabulary and field assignments](../scanner-evidence.md#attempt-observations)
  preserve the original evidence meanings while allowing separate inference.
- [Source review](../scanner-data-policy.md#source-review) gates every import;
  enforcement is procedural, not a claim that every later dataset is reviewed.
- The [consumer policy](../consumer-compatibility.md) governs contract evolution.

Later feature and platform acceptance belongs to its own milestone, not M1.
