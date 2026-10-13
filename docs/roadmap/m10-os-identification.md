# M10: OS identification

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M5](m05-host-discovery.md), [M7](m07-adaptive-scheduling.md) | Qualified remote stack observations |

Standalone `identify-os` / `Client::identify_os` and output/v14 (retained in
v15) are implemented. See [OS identification](../os-identification.md).

## Implemented decisions

- One numeric unicast target with explicit distinct open/closed TCP ports;
  open SYN/ACK and closed RST/ACK prerequisites are verified before remaining
  `packetcraftr.os-probes/v1` probes, with bounded RST/ACK cleanup.
- Observations and qualified OS-family candidates (`Linux`, `Windows`, `macOS`)
  stay separate; missing, contradictory, or intermediary-modified evidence
  produces `unknown` or `inconclusive` with ordinal `qualified` confidence.
- Original `project-os-fingerprints` 1.0.0 corpus with provenance and a
  pre-tuning training/hold-out split.

## Evidence and remaining acceptance

[Preserved evidence](evidence/m10/README.md) pairs Linux 7.0.0-38 training
captures with a frozen independent 7.0.0-34 KVM guest hold-out (4 suitable
case-runs qualified as Linux; 8 missing-prerequisite cases `inconclusive`).

M10 remains **In progress** pending independently labeled Windows/macOS stacks,
broader configurations/intermediaries, scoped native coverage, cross-family
held-out evaluation, and reviewed-revision execution across Linux/macOS/Windows
profiles ([M2](m02-ground-truth-benchmarks.md)/[M3](m03-native-validation.md)).
