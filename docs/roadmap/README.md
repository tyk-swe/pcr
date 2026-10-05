# Core scanner roadmap

This roadmap addresses PacketcraftR's core scanner gaps relative to Nmap for
**authorized network inventory and diagnostics**. It complements PacketcraftR's
packet-development and offline-analysis role; it does not propose cloning the
entire Nmap tool suite.

The phases below are **planned work, not shipped capabilities or release
commitments**. The [Nmap gap matrix](nmap-gap-matrix.md) distinguishes existing
functionality, partial coverage, missing capabilities, and explicit deferrals.

## Comparison baseline

The implementation baseline is `main` at `22c7d182d577`, reviewed on
2026-10-05, rather than only the published `0.5.0-beta.3` release. In particular,
`main` publishes [output v6][output-contract]; the beta release has different
contracts. Review the [release and migration guidance][project-readme] before
assuming a roadmap baseline applies to a released binary.

The comparison uses the [official Nmap reference guide][nmap-guide] consulted on
2026-10-05. The [download page][nmap-download] identifies `7.991` as stable at
that date, while the online options summary can describe a development version.
Future comparison runs must record the actual Nmap version and build features,
not infer them from the moving online guide. Database-size and throughput claims
from the guide are not acceptance targets.

PacketcraftR already has bounded IPv4/IPv6 target selection, TCP SYN and ordinary
TCP connect scanning, UDP and ICMP echo probes, per-port UDP response checks,
UDP/TCP/ICMP traceroute, and versioned JSON/NDJSON evidence. The main gaps are
composed host discovery, scanner-oriented port selection and inference,
adaptive scheduling, active service/version and OS identification, and broader
diagnostic scan modes. Existing packet codecs or passive TLS fingerprints do
not by themselves fill those workflow gaps.

## Scope and non-goals

Committed roadmap priorities are:

1. Target planning, host discovery, and trustworthy mainstream scanning.
2. Service/version and OS identification with explicit evidence and confidence.
3. Bounded performance improvements and equal Linux, macOS, and Windows
   acceptance requirements throughout.
4. Later diagnostic coverage for additional TCP scan families, SCTP, and
   IP-protocol inventory.

Scripting/NSE, scan resume/checkpointing, and Nmap-compatible XML are deferred.
Exact Nmap CLI syntax, legacy output formats, and Zenmap/Ncat/Nping/Ndiff clones
are not parity goals. Evasion/decoy, idle/bounce, exploit/brute-force, unbounded
scanning, and random public-target workflows are outside this roadmap. These
are scope decisions, not claims that their Nmap equivalents do not exist.

Capability parity means comparable, documented outcomes on the declared fixture
and platform matrix, not identical algorithms, defaults, flags, or database
coverage. No milestone should be marked complete merely because a new option
exists or one Linux fixture agrees with Nmap.

## Invariants and ownership

All phases retain the [repository guide][repository-guide] boundaries:

- Authorize declared targets, resolution, and the operation before active
  discovery; check final numeric endpoints and materialized bytes before
  transmission. Discovery, identification, retries, and traceroute all spend
  explicit finite budgets.
- Preserve captured bytes, scope, timestamps, per-attempt outcomes, and partial
  execution evidence. Silence is an observation, not proof that a host is absent
  or a UDP port is closed. A gateway's neighbor reply is not a remote host reply.
- Keep host reachability, inferred port state, application observations, and
  execution/capability failures distinct. Do not turn a missing backend into a
  network timeout or an untrusted banner into authenticated identity.
- Follow the [consumer compatibility policy][compatibility]. New enum meanings
  or incompatible inference semantics require a new contract family; schemas,
  examples, CLI conformance tests, migration notes, and release assets move
  together when future implementation changes contracts. This roadmap itself
  changes none of them.

| Owner | Responsibility in this roadmap |
| --- | --- |
| `packetcraftr-core` | Portable packet models/codecs, bounded fingerprint documents and parsers, pure matching, and offline fixture analysis; no native I/O or live policy. |
| `packetcraftr-netio` | Socket/capture/transmit providers, native resources, cancellation and cleanup accounting, and platform capability boundaries. |
| `packetcraftr` | Discovery/scanning/identification/traceroute workflows, authorization, preparation, scheduling, budgets, and domain evidence. |
| `packetcraftr-cli` | Target/port arguments, provider composition, rendering, and versioned machine representations. |

Only netio's `platform/` owns unsafe code. Native selection remains in its
`build.rs` and dispatch boundary; code elsewhere uses emitted capability cfgs.
Expose capabilities without introducing equivalent public assembly paths.

## Phases and dependencies

| Phase | Priority outcome | Prerequisites |
| --- | --- | --- |
| [P0: Evidence and platform foundations](#p0-evidence-and-platform-foundations) | Define what can be claimed and establish comparison, data, and runtime evidence. | Required gates for every later phase. |
| [P1: Target planning and host discovery](#p1-target-planning-and-host-discovery) | Select and discover authorized hosts before deeper investigation. | P0 semantics and validation fixtures. |
| [P2: Reliable scanning and bounded performance](#p2-reliable-scanning-and-bounded-performance) | Complete mainstream scanner behavior and adapt work within hard limits. | P0/P1 planning and evidence foundations. |
| [P3: Service and version identification](#p3-service-and-version-identification) | Identify applications rather than only reachable ports. | P0 data gates and P2 endpoint evidence/bounded I/O. |
| [P4: OS identification and path inventory](#p4-os-identification-and-path-inventory) | Add qualified OS results and scan-informed multi-host traceroute. | P0/P2 fingerprint and scheduling foundations; P1 host inventory. |
| [P5: Broader diagnostic scan coverage](#p5-broader-diagnostic-scan-coverage) | Extend diagnostic transports and scan-dependent inference. | P0/P2 contracts, correlation, and platform validation. |

This is priority ordering, not a requirement that all work be serial. OS
identification need not wait for service identification. Later diagnostic modes
share the reliable scanning foundations and are not technically blocked on
completion of every identification feature. Each phase remains open until its
required outcomes and runtime evidence are met on Linux, macOS, and Windows.
Unsupported profiles remain explicit limitations, not a way to call a missing
platform feature complete.

## P0: Evidence and platform foundations

**Owners:** all four crates within their domains; no scanner semantics in CI
assembly or CLI-only types.

**Deliverables**

- Define host observations, scan-dependent port inference, per-attempt probe or
  socket outcomes, and operational failures separately. Retain the current
  timeout/unreachable/unknown evidence rather than simply renaming it to match
  Nmap's port vocabulary.
- Establish a versioned comparison corpus with provisioned ground truth for
  responsive, closed, blocked, silent, malformed, and unrelated responses in
  both IP families. Record Nmap settings and explain expected differences.
- Establish repeatable workflow benchmarks recording elapsed time, work sent,
  result accuracy, retained-state charges, and peak process memory. Logical byte
  ceilings are not claims about process RSS.
- Define provenance, license review, versioning, maintenance ownership, and
  coverage policy for port, service, OS, and vendor data. Do not copy or bundle
  Nmap code/data on the assumption that its [NPSL][nmap-license] is compatible
  with PacketcraftR's AGPL license.
- Establish controlled native runtime validation routes for Linux, macOS, and
  Windows. The [current validation matrix][native-validation] has privileged
  isolated Linux coverage but no equivalent configured macOS/Windows lane.
  Preserve reviewed-native and administrator-owned permission controls.

**Exit criteria**

- The fixture inventory specifies independent expected outcomes, comparison
  versions/settings, and known divergences; matching Nmap alone is not an oracle.
- Required platform/profile checks distinguish exercised, failed, and
  unavailable scenarios. Compilation and fake-provider results are never
  relabeled as privileged native evidence.
- Data sources and benchmark methodology are reviewed before dependent features
  are claimed complete. Missing runtime evidence remains an open platform gap.

## P1: Target planning and host discovery

**Owners:** workflow `target`, `neighbor`, and probe/discovery behavior; core
wire models; netio interface/capture providers; CLI selection and host output.

**Deliverables**

- Add bounded target/exclusion file and stdin ingestion with deterministic
  deduplication and provenance. Keep numeric/CIDR and hostname authorization,
  exclusions, and family selection consistent across input forms.
- Add a bulk scan list/plan mode distinct from today's passive packet-route
  `plan`, and preserve interface/zone identity for scoped IPv6 targets.
- Add a host-discovery workflow with discovery-only and explicit skip-discovery
  behavior. Compose local ARP/NDP and configurable ICMP/TCP/UDP probes, including
  an ordinary-socket path when raw I/O is unavailable and explicitly selected.
- Publish host-level response reasons and optional, policy-aware reverse-DNS and
  local-link MAC/vendor observations. Distinguish cached next-hop information,
  proxy replies, and direct host evidence; do not infer target identity from a
  routed gateway's MAC address.

**Exit criteria**

- Numeric list/plan operations send no target or neighbor packets. Hostname
  resolution remains explicit; it is not disguised as a network-free operation.
- Denials, exclusions, malformed/oversized input, duplicate targets, scope
  ambiguity, and family mismatches fail or narrow selection before active work.
- Closed-but-responsive TCP endpoints can demonstrate host responsiveness;
  silent or blocked hosts retain uncertainty. Discovery omission and skipping
  are visible rather than represented as measured reachability.
- The declared discovery matrix passes controlled IPv4/IPv6 behavior and native
  runtime checks on all three platforms where the capability is supported.

## P2: Reliable scanning and bounded performance

**Owners:** workflow scan/probe planning and inference; netio bounded socket and
capture resources; core port-data documents; CLI scan arguments and output.

**Deliverables**

- Add versioned common-port/named-port selections, explicit port exclusions,
  bounded curated UDP payload coverage, and mixed TCP/UDP plans. Port-name hints
  remain hints, not service identification. Combined endpoint identity includes
  the transport, so TCP and UDP on one address/port cannot merge.
- Define scan-dependent inferred states and reasons, including UDP ambiguity,
  separately from the recorded outcome of each attempt. Retain conflicting and
  late/unattributed evidence rather than erasing it to force a single answer.
- Add capability-aware method planning without silently changing an explicitly
  requested raw method into an ordinary connection or fabricating wire evidence
  for socket observations.
- Add bounded RTT estimation, selective retry/backoff, response-rate-limit
  handling, per-host fairness/deadlines, and configurable adaptive windows.
  Adaptation may reduce work or delay it but never bypass operation-wide limits.
- Improve connect scheduling and plan retention under explicit process-wide and
  operation-wide resource ceilings. The current 16-connection cap is a resource
  contract to redesign and validate, not a constant to increase without review.

**Exit criteria**

- Mainstream state/reason matrices cover replies, silence, ICMP errors,
  duplicates, contradictory attempts, malformed packets, loss, and reordering.
  Socket deadline/capacity failures are not mistaken for target port states.
- Virtual-clock/fake-provider tests verify pacing, fair progress, retry ceilings,
  finite deadlines, backpressure, and cleanup. Cancellation does not release a
  native permit while its resource or provider work is still alive.
- Baseline and candidate runs record accuracy, latency, work, and peak memory on
  the same fixtures/settings. Performance targets are agreed against that
  baseline before an optimization is accepted; higher configured rate/window
  values are not evidence of achieved throughput.
- Every claimed optimization has Linux/macOS/Windows runtime evidence and keeps
  retained/prepared state bounded, including fail-closed oversized-plan cases.

## P3: Service and version identification

**Owners:** core bounded response parsing and matching; workflow identification
and policy; netio stream resources; CLI identification records.

**Deliverables**

- Add read-only banner and protocol-aware TCP/UDP identification with explicit
  per-host/connection/probe byte, time, and attempt limits. Start with HTTP(S),
  SSH banners, and DNS fixtures, then expand the reviewed corpus.
- Add TLS-wrapped service interrogation through bounded, reviewed transport
  support. Passive TLS decoding/JA3/JA4 observations are not this capability;
  new runtime dependencies need the normal dependency and license review.
- Add a versioned curated probe/match corpus with safe intensity controls,
  sensitive-service exclusions, and maintenance/provenance metadata. Reuse UDP
  profile building blocks without interpreting `confirmed` as product identity.
- Report observed protocol/banner claims, matched product/version candidates,
  confidence, and evidence provenance separately. Add hostname/device/CPE
  metadata only when supported by the observations and matching data.

**Exit criteria**

- Known services on nonstandard ports, encrypted services, unknown services,
  ambiguous matches, misleading banners, truncation, and malformed replies have
  explicit fixture outcomes. Unknown/ambiguous cases do not become exact versions.
- Reauthorization covers final numeric endpoints; hidden resolution, redirects,
  authentication attempts, or extra probing cannot bypass the declared policy
  and budget. Active identification remains an explicit operation.
- Corpus versions reproduce matching results; claimed coverage and confidence
  are evaluated against held-out fixtures, not only examples used to write rules.
  An identified version is not an assertion that the service is vulnerable.
- Applicable portable and native behavior passes on Linux, macOS, and Windows,
  and any future machine-contract changes follow the compatibility policy.

## P4: OS identification and path inventory

**Owners:** core bounded fingerprint representation/matching; workflow OS and
traceroute engines; netio packet resources; CLI qualified inventory output.

**Deliverables**

- Add explicit, finite IPv4/IPv6 stack-fingerprint collection and a reviewed
  matching corpus. Define the probe and evidence requirements for each family
  rather than assuming an IPv4 method transfers unchanged to IPv6.
- Add suitability checks, ranked candidates with evaluated confidence, and
  explicit unsupported/inconclusive results for missing evidence. Service
  banners and passive TLS client fingerprints are not remote OS proof.
- Integrate traceroute with host/scan results: select an observed responsive
  protocol/endpoint, trace multiple authorized hosts under one finite plan, and
  evaluate bounded path reuse with explicit source and freshness metadata.
  Cached hops must not masquerade as fresh observations for another target.

**Exit criteria**

- Known and held-out OS fixtures cover exact/near/unknown matches, unavailable
  open/closed ports, filtered paths, NAT/intermediaries, and malformed evidence.
  Missing suitability conditions or ambiguous matches do not produce exact labels.
- Traceroute fixtures cover hop timeouts, destination/unreachable termination,
  protocol selection, multiple hosts, and reuse expiry without inventing hops or
  treating an intermediate router as the destination.
- Both workflows preserve authorized scope, final-wire checks, timestamps,
  cancellation, evidence ceilings, and platform capability failures. Linux,
  macOS, and Windows support and runtime evidence are recorded independently.

## P5: Broader diagnostic scan coverage

**Owners:** core transport/chunk models and matchers; workflow mode-specific
planning/correlation/inference; netio native resources; CLI mode/result contracts.

**Deliverables**

- Add explicit TCP ACK/window and flag-based diagnostic families, including
  FIN/NULL/Xmas/Maimon behavior where useful for controlled firewall/stack tests.
  Separate configured probe flags from the chosen inference rules.
- Add SCTP INIT/COOKIE-ECHO diagnostic scanning, reusing existing core SCTP
  header/checksum and matcher building blocks while adding missing bounded
  chunk models and workflow evidence.
- Add bounded IP-protocol inventory and relevant additional discovery probes.
  Protocol numbers are not transport ports; keep their selection/results typed.

**Exit criteria**

- Each mode has an observable correlation/state matrix, including unrelated
  replies, valid negative replies, malformed chunks, ICMP quotations, and silence.
  ACK responsiveness does not imply an open port, and window/flag-dependent
  heuristics explicitly retain their stack-compatibility limits.
- Ambiguous states remain ambiguous; idle-scan-only semantics are not added merely
  to reproduce every Nmap label. Known implementation-dependent counterexamples
  belong in the acceptance fixtures.
- Applicable IPv4/IPv6 and Linux/macOS/Windows native checks pass before a mode is
  marked complete. Unsupported execution paths publish capability failures,
  not false port/protocol or host classifications.

## Validation and roadmap maintenance

Future implementation follows [Contributing][contributing] and the
[native validation guidance][native-validation], using owner-local unit tests,
public `*_contracts.rs` regressions, `*_matrix.rs` combinations, and
`*_conformance.rs` wire/schema checks. Keep public integration modules in the
owning crate's single integration binary; process-isolated native suites retain
their dedicated launcher. Use loopback, documentation addresses, or isolated
fixtures rather than uncontrolled reachable targets.

The existing comprehensive Linux check is:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

It requires libpcap development support and is not a substitute for macOS or
Windows runtime validation. Exercise relevant portable/default/Layer 2/pcap-free/
full-native profiles and record actual capability limitations. A correct
unsupported error validates failure behavior, not successful feature parity.

When advancing a phase, update the matrix against the exact reviewed revision,
link the behavior and native evidence, report known limits, and synchronize any
changed contracts and release documentation. Keep deferrals explicit. Do not
mark a phase complete based on compilation, a skipped scenario, or a claim that
has no supporting fixture/runtime evidence.

This document addition changes no scanner behavior, schema, dependency, CI
configuration, or permission policy. It does not claim a new comparison run or
successful native validation.

[project-readme]: ../../README.md
[repository-guide]: ../../AGENTS.md
[contributing]: ../../CONTRIBUTING.md
[compatibility]: ../consumer-compatibility.md
[native-validation]: ../native-validation.md
[output-contract]: ../../crates/packetcraftr-cli/src/output/contract.rs
[nmap-guide]: https://nmap.org/book/man.html
[nmap-download]: https://nmap.org/download.html
[nmap-license]: https://nmap.org/npsl/
