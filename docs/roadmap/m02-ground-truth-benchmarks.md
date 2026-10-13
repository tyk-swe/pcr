# M2: Ground truth and benchmarks

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M1](m01-claims-evidence.md) | [M7](m07-adaptive-scheduling.md), scanner-result [close gates](README.md#close-gates) |

The corpus and evaluator exist. M2 adds measurement, not scanner capability;
Nmap agreement is never fixture truth.

## Implemented method

- The reviewed [inventory](../scanner-corpus.v1.json) uses
  [scanner-corpus/v1](../../schemas/packetcraftr.scanner-corpus.v1.schema.json)
  with pre-declared responsive, closed, blocked, silent, malformed, and unrelated
  IPv4/IPv6 scenarios, `inference_scenarios` (mixed same-port, silent UDP,
  contradictory attempts), `trace_path_scenarios` (shared, divergent, silent-hop
  paths), and dataset 1.7.0 `tcp_diagnostic_scenarios` (eight conditions × seven modes).
- `scanner_fixture` exercises `Client` scan/traceroute paths with injected providers;
  native loopback connect uses the CLI.
- `scripts/benchmark-scanner.py` repeats 88 cells (72 raw scan, 12 traceroute,
  4 native connect), recording accuracy, work, elapsed time, `retained_evidence_bytes`,
  and POSIX `wait4` peak RSS.
- Optional comparison uses an official Nmap 7.991 build (never vendored),
  retaining build/version metadata, fixture truth, and explained divergences.

## Recorded results and limits

- Early `target/validation/scanner-baseline*.json` snapshots are local history;
  six IPv6 connect case-runs could not bind `::1`, while IPv4 connect agreed with Nmap.
- [M4 evidence](evidence/m04/README.md) (`8e010a0b9eac118aa13384f0b854111a73d47d76`)
  records 264 passing case-runs (dataset 1.1.0, three repetitions), including
  isolated-namespace IPv6 connect.
- [M8](evidence/m08/README.md) and [M9](evidence/m09/README.md) close their
  identification inventories; [M7](m07-adaptive-scheduling.md) retains fixed/adaptive
  measurements.

## Remaining gates

- Add reconvergent/ECMP path fixtures for [M11](m11-scan-informed-traceroute.md).
- Retain exact-version Nmap differential runs for supported native workflows.
- Review workflow baselines and variance/performance targets across applicable
  platforms.
