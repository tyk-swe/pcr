# M2: Ground truth and benchmarks

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M1][m1] | [M7][m7], and the ground-truth [close gate][close-gates] of every milestone that publishes scanner results |

Nothing in the repository today says what a scanner result *should* be for a
given network condition, and nothing measures a live workflow end to end.
Existing contracts exercise loopback socket outcomes and controlled-provider
pipelines; the only benchmarks are core microbenchmarks. Without independent
expected outcomes, agreement with Nmap would be the only available oracle, and
an Nmap result is one tool's inference under its own defaults, not ground truth.

This milestone establishes the comparison corpus and the benchmark method that
later milestones are judged against. It adds no scanner capability.

## Outcome

- A versioned corpus of scenarios, each with a provisioned condition and an
  independently stated expected outcome, in both IP families.
- Comparison runs against a pinned Nmap build, with settings recorded and
  expected differences explained.
- Repeatable workflow benchmarks that report elapsed time, work sent, result
  accuracy, retained-state charges, and peak process memory.

## Baseline

| | PacketcraftR at `22c7d182d577` | Nmap reference |
| --- | --- | --- |
| Expected outcomes | [Connect contracts][connect-contract] over loopback and [scan pipeline contracts][pipeline-contract] over controlled providers; no scenario inventory with provisioned network conditions | Not applicable; Nmap is a comparison subject, not an oracle |
| Comparison runs | None recorded | The [reference guide][nmap-guide] moves with development; the [download page][nmap-download] names the stable release |
| Benchmarks | [Core microbenchmarks][core-bench] for decode, documents, capture files, reassembly, checksums, and TLS parsing; no live-workflow benchmark | Timing and performance options ([performance][nmap-performance]); the guide's throughput claims are not acceptance targets |

## Scope

### M2.1 Comparison corpus

A versioned inventory of scenarios. Each scenario provisions a known condition
and states its expected outcome in the [M1][m1-vocabulary] vocabularies,
independently of any tool's output.

- Conditions cover responsive, closed, blocked, silent, malformed, and
  unrelated responses.
- Every condition exists for IPv4 and IPv6.
- Scenarios use loopback, documentation addresses, or isolated fixtures. None
  targets an uncontrolled reachable host.
- The inventory is the place later milestones add their own scenarios; a
  milestone's fixtures are not accepted until they are listed here.

### M2.2 Nmap comparison runs

A procedure for running a pinned Nmap build against corpus scenarios.

- Each run records the Nmap version, build features, arguments, and acquisition
  conditions.
- Each scenario records where PacketcraftR is expected to differ from Nmap and
  why. A difference without an explanation is a finding, not a failure of
  either tool.
- Matching Nmap alone never satisfies an exit criterion.

### M2.3 Workflow benchmarks

A repeatable benchmark for each live workflow, run against corpus scenarios.

- Each run records elapsed time, probes or connections sent, result accuracy
  against the expected outcome, retained-state charges, and peak process
  memory.
- Logical byte ceilings and peak process memory are reported separately; a
  charged-bytes figure is not a claim about resident memory.
- A baseline run at the current behavior is recorded before any optimization
  in [M7][m7] is evaluated.

## Change map

| Change | Start here |
| --- | --- |
| Scenario provisioning | [`scripts/test-native-isolated.py`][isolated-launcher], [native validation][native-validation] |
| Expected-outcome contracts | [`scan_pipeline_contracts.rs`][pipeline-contract], [`connect_scan_contracts.rs`][connect-contract] |
| Evidence recording | [`scripts/validation_evidence.py`][validation-evidence] |
| Benchmark harness | [`benches/benchmarks.rs`][core-bench] as the existing precedent; workflow benchmarks belong to the `packetcraftr` crate |

## Decisions to settle

1. Where the corpus inventory lives and in what format (recommended: a
   versioned document in the repository, validated by a schema, so adding a
   scenario is a reviewed change).
2. How scenarios are provisioned on each platform (recommended: the isolated
   namespace launcher on Linux, with [M3][m3] deciding the macOS and Windows
   equivalents).
3. How the Nmap build is pinned and obtained for comparison runs (recommended:
   record the exact version and build features per run; do not vendor Nmap).
4. Whether benchmarks run in CI or on demand (recommended: on demand with
   recorded results, until run-to-run variance on hosted runners is measured).

## Exit criteria

- [ ] The fixture inventory specifies, for every scenario, an independent
      expected outcome, the comparison versions and settings, and known
      divergences.
- [ ] The inventory covers responsive, closed, blocked, silent, malformed, and
      unrelated responses in IPv4 and IPv6.
- [ ] No scenario uses agreement with Nmap as its expected outcome.
- [ ] A baseline benchmark run for the current scan workflows records elapsed
      time, work sent, accuracy, retained-state charges, and peak process
      memory.
- [ ] The benchmark methodology is reviewed before any dependent feature is
      claimed complete.

[m1]: m01-claims-evidence.md
[m1-vocabulary]: m01-claims-evidence.md#m11-evidence-vocabulary
[m3]: m03-native-validation.md
[m7]: m07-adaptive-scheduling.md
[close-gates]: README.md#close-gates
[native-validation]: ../native-validation.md
[isolated-launcher]: ../../scripts/test-native-isolated.py
[validation-evidence]: ../../scripts/validation_evidence.py
[core-bench]: ../../crates/packetcraftr-core/benches/benchmarks.rs
[connect-contract]: ../../crates/packetcraftr-cli/tests/integration/connect_scan_contracts.rs
[pipeline-contract]: ../../crates/packetcraftr/tests/integration/scan_pipeline_contracts.rs
[nmap-guide]: https://nmap.org/book/man.html
[nmap-download]: https://nmap.org/download.html
[nmap-performance]: https://nmap.org/book/man-performance.html
