# M2: Ground truth and benchmarks

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M1](m01-claims-evidence.md) | [M7](m07-adaptive-scheduling.md), scanner-result [close gates](README.md#close-gates) |

The corpus and evaluator exist. M2 adds measurement, not scanner capability;
Nmap agreement is never fixture truth.

## Implemented method

- The reviewed [inventory](../scanner-corpus.v1.json) uses the independent
  [scanner-corpus/v1 schema](../../schemas/packetcraftr.scanner-corpus.v1.schema.json).
  Scenarios declare expected outcomes before execution and cover responsive,
  closed, blocked, silent, malformed, and unrelated replies in IPv4/IPv6.
- `scanner_fixture` runs real `Client` scan/traceroute paths with deterministic
  injected providers, never native I/O. Native loopback connect uses the CLI.
- `scripts/benchmark-scanner.py` repeats 88 cells: 72 raw scan, 12 traceroute,
  four native connect. It records accuracy, work, elapsed time, exact
  `retained_evidence_bytes`, and child-process peak RSS using POSIX `wait4`.
  Logical retention is not RSS; Windows peak under that method is unavailable.
- Optional comparison uses an official Nmap 7.991 build, never vendored.
  Retain acquisition URL/hash, configure flags, version, arguments, fixture truth,
  acquisition conditions, and explained divergences with each run.
- Benchmarks run on demand; record a fixed-behavior baseline before optimizing.
  Native platform behavior requires the separate [M3](m03-native-validation.md) gate.

## Recorded results and limits

Early `target/validation/scanner-baseline*.json` snapshots are local history,
not checked-in acceptance. `scanner-baseline-final.json` was incomplete: its
injected cells matched expectations, but six IPv6 connect case-runs could not
bind `::1`. IPv4 connect agreed with Nmap; no raw-versus-Nmap comparison was run.
A closed-port-unreachable echo fixture remains `unreachable` because it has no
port; do not alter expectations to match the classifier.

Later [M4 evidence](evidence/m04/README.md) at
`8e010a0b9eac118aa13384f0b854111a73d47d76` records 264 passing case-runs
(dataset 1.1.0, three repetitions), including IPv6 connect in an isolated
namespace. This supersedes that environment gap for M4, not every M2 workflow.
[M8](evidence/m08/README.md) and [M9](evidence/m09/README.md) close their declared
identification inventories. [M7](m07-adaptive-scheduling.md) retains separate
fixed/adaptive measurements. None establishes an Internet-wide accuracy claim.

## Remaining gates

- Extend the independent inventory to mixed-port inference/contradictions and
  shared/divergent/reconvergent/ECMP/silent paths for M6/M11.
- Retain exact-version Nmap differential runs for supported native workflows,
  explaining differences without treating one tool as ground truth.
- Review workflow baselines and variance/performance targets across applicable
  platforms; report unavailable methods explicitly.

M2 remains **In progress**. Local snapshots, compilation, and repeated fixture
instances cannot substitute for these gates.
