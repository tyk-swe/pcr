# Core scanner roadmap

Authorized inventory and diagnostics roadmap, not a clone of the Nmap suite.
Status separates implemented behavior from completed acceptance; open milestones
are not release commitments. The [gap matrix][matrix] owns capability comparisons,
and each milestone owns its decisions and remaining gates.

## Comparison baseline

The initial review used `22c7d182d577` (2026-10-05) and the official
[Nmap reference guide][nmap-guide] (7.991). Current `main` emits output/v16;
beta.3 emits v2. See [migration guidance][project-readme] for producer contracts.
Comparison runs must record actual Nmap versions/build features; database size
and advertised throughput are not targets.

## Scope and non-goals

Priorities are target planning, discovery, mainstream scans, qualified service/OS
identification, bounded scheduling, and cross-platform validation, followed by
diagnostic scan families. Parity means documented outcomes on declared fixtures
and platforms, not identical syntax, algorithms, defaults, or databases.

Scripting/NSE, resume/checkpointing, and Nmap XML are deferred. Exact CLI syntax,
legacy output, companion-tool clones, evasion/decoys, idle/bounce, exploit/brute-force,
unbounded scans, and random public targets are non-goals; see [deferred items][matrix-deferred].

## Milestones

The dependency column constrains implementation order; independent workstreams
need not wait for one another.

| ID | Milestone | Outcome | Depends on | Status |
| --- | --- | --- | --- | --- |
| M1 | [Claims and evidence model][m1] | Separate vocabularies for host observations, inferred port states, attempt outcomes, and operational failures; reviewed scanner data policy. | None | Complete |
| M2 | [Ground truth and benchmarks][m2] | Versioned comparison corpus with expected outcomes, pinned Nmap comparison runs, and repeatable workflow benchmarks. | M1 | In progress |
| M3 | [Native validation on three platforms][m3] | Controlled privileged runtime routes for macOS and Windows beside Linux, reporting exercised, failed, and unavailable scenarios. | None | In progress |
| M4 | [Target planning][m4] | Bounded target/exclusion manifests, packet-free list mode, scoped IPv6 identity, and source-aware diagnostics across five profiles. | M1 | Complete |
| M5 | [Host discovery][m5] | Composed discovery over ARP/NDP and ICMP/TCP/UDP probes, with host records, reasons, and optional enrichment. | M4 | In progress |
| M6 | [Port planning and state inference][m6] | Catalog/named port selections, exclusions, curated UDP payloads, mixed TCP/UDP plans, inferred states, and method planning. | M1 | In progress |
| M7 | [Adaptive scheduling and bounded performance][m7] | RTT-driven timeouts, selective retries, rate-limit handling, per-host fairness, adaptive windows, and bounded connect admission. | M2, M6 | In progress |
| M8 | [Service and version identification][m8] | Read-only identification with banner/protocol-aware probes, match documents, and separate claim/candidate/confidence records. | M7 | Complete |
| M9 | [TLS services and identification corpus][m9] | TLS-wrapped interrogation over a bounded transport, expanded reviewed corpus, and held-out evaluation. | M8 | Complete |
| M10 | [OS identification][m10] | Finite IPv4/IPv6 stack-fingerprint collection, corpus matching, and qualified or inconclusive results. | M5, M7 | In progress |
| M11 | [Scan-informed traceroute][m11] | Traceroute selecting an observed responsive probe, tracing multiple authorized hosts under one plan with sourced path reuse. | M5, M6 | In progress |
| M12 | [TCP diagnostic scans][m12] | ACK/window and FIN/NULL/Xmas/Maimon/custom scan families keeping probe flags separate from inference rules. | M6 | In progress |
| M13 | [SCTP and IP-protocol inventory][m13] | SCTP INIT/COOKIE-ECHO scanning, typed IP-protocol inventory, and remaining discovery probe families. | M5, M6 | In progress |

### Close gates

- **Ground truth ([M2][m2]):** scanner-result milestones require independently
  expected comparison-corpus scenarios. Agreement with Nmap alone is insufficient.
- **Runtime evidence ([M3][m3]):** native behavior requires recorded Linux,
  macOS, and Windows execution for every supported profile. Compilation, skipped
  checks, and typed unsupported results do not establish feature parity.

A milestone can close its applicable gates without closing broader M2/M3 work.

## Gap gate and scorecard

Scope is met when each matrix row is `Present with constraints`, `Deferred`, or
`Non-goal`. Coverage divides present rows by all non-deferred/non-non-goal rows.
Accuracy, work/latency, retained-state charges, peak process memory, platform
coverage, and held-out identification quality stay separate.

| Recorded review | Gap coverage | Evidence and limits |
| --- | --- | --- |
| Initial, 2026-10-05 (`22c7d182d577`) | 9/36 (25%); 13 partial, 14 missing | No benchmark or runtime baseline claimed |
| M4, 2026-10-07 (`8e010a0b9eac118aa13384f0b854111a73d47d76`) | 12/36 (33.3%); 12 partial, 12 missing | [264 matching corpus runs and 20 scoped native profile executions](evidence/m04/README.md); work, latency, retained bytes, and peak memory recorded separately |
| M8 baseline, 2026-10-09 (`928ad8d555fe8b34abd144083612b54ace0fef1f`) | 16/36 (44.4%); 12 partial, 8 missing | [Corrected acceptance](evidence/m08/README.md) at `99a9cf23216eb490892c0b6659e303d1a0b02c3d` on 2026-10-10: 1,440 passing cases, 20 profiles across Linux/macOS ARM+Intel/Windows |
| M9, 2026-10-11 (`5e5a41470c0c63404ca3e581067fded136eda1ce`) | 17/34 (50%); 11 partial, 6 missing | [4,000 passing case-runs](evidence/m09/README.md), 20 profiles across Linux/macOS ARM+Intel/Windows; fixed 21-instance holdout, 18 eligible: 66.67% matched, 22.22% unknown, 11.11% ambiguous |

Earlier reviews used 44 rows (including 3 deferred and 5 non-goals); M9 recounts
42 distinct capabilities (denominator 34), so percentages are not directly
comparable. [M5 Linux acceptance](evidence/m05/README.md) at
`e7f3e2efa7b47ba2ffa7e2818dbcc4d53eaef9e3` records 44 exercised cases, 36 typed
refusals, and 168 bounded CLI invocations (dataset 1.3.0); macOS/Windows remain open.

## Definition of done

Every milestone follows [code and test boundaries][repository-guide] and ships:

1. Authorization before active discovery, final endpoint/byte checks, and finite
   budgets for every retry, loop, and collection.
2. Faithful bytes, scope, timestamps, and partial evidence with separate
   [host, attempt, inference, and failure vocabularies](../scanner-evidence.md).
3. Synchronized schemas, examples, tests, migration notes, and release assets
   under the [consumer policy][compatibility]; data provenance under the
   [scanner data policy](../scanner-data-policy.md).
4. Owner-local tests and validation results per [Contributing][contributing],
   independent ground truth, and [native evidence][native-validation].
5. Updated user guidance, `[Unreleased]`, and matrix rows tied to the reviewed
   revision, with known limits beside every completion claim.

[matrix]: nmap-gap-matrix.md
[matrix-deferred]: nmap-gap-matrix.md#deferred-capabilities-and-deliberate-differences
[m1]: m01-claims-evidence.md
[m2]: m02-ground-truth-benchmarks.md
[m3]: m03-native-validation.md
[m4]: m04-target-planning.md
[m5]: m05-host-discovery.md
[m6]: m06-port-planning-inference.md
[m7]: m07-adaptive-scheduling.md
[m8]: m08-service-identification.md
[m9]: m09-tls-services-corpus.md
[m10]: m10-os-identification.md
[m11]: m11-scan-informed-traceroute.md
[m12]: m12-tcp-diagnostic-scans.md
[m13]: m13-sctp-ip-protocol.md
[project-readme]: ../../README.md
[repository-guide]: ../../CONTRIBUTING.md#code-and-tests
[contributing]: ../../CONTRIBUTING.md
[compatibility]: ../consumer-compatibility.md
[native-validation]: ../native-validation.md
[nmap-guide]: https://nmap.org/book/man.html
