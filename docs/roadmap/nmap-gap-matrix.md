# Nmap core-scanner gap matrix

This is the comparison companion to the [core scanner roadmap](README.md), not
an exhaustive Nmap option checklist. It records PacketcraftR `main` at
`22c7d182d577` as reviewed on 2026-10-05. Nmap references are the official guide
consulted on that date; actual differential tests must pin their binary version,
build features, arguments, fixture truth, and acquisition conditions.

No live comparison or newly passed native test is claimed by this document.
Relative source links describe the reviewed implementation; future changes need
an updated baseline and supporting behavior evidence.

## Status legend

| Status | Meaning |
| --- | --- |
| Present with constraints | The capability exists; the listed profile, method, resource, and evidence limits still apply. This is not complete equivalence to every Nmap default or option. |
| Partial | Related behavior/building blocks exist, but the compared workflow or coverage is incomplete. |
| Missing | No corresponding scanner capability is exposed in the reviewed workflow/CLI surface. |
| Deferred | A recorded gap outside the committed milestones of this roadmap. |
| Non-goal | A deliberate product/scope difference; no parity commitment. |

A milestone reference is a **future destination**, not a completion status. It
names a workstream, such as `M4.1` for the first workstream of [M4][m4].
Existing packet construction, generic exchange, or passive decoding is not
counted as a fully implemented scanner feature. Supported platforms and
successful runtime validation are also separate claims.

## Targets, discovery, and host inventory

| Capability | Nmap behavior/reference | PacketcraftR baseline and concrete gap | Status | Roadmap |
| --- | --- | --- | --- | --- |
| Explicit targets, CIDRs, exclusions, and families | Hostnames, numeric addresses/CIDRs, exclusions, and family controls; see [targets][nmap-targets]. | [Target selections][target-selection] and [admission][target-admission] already bound expansion, deduplicate, apply numeric exclusions, and filter families. Hostname resolution is opt-in and all selected authorized answers are considered; do not assume Nmap's default first-answer behavior. | Present with constraints | Preserve in [M4][m4]. |
| Target/exclusion files and stdin | `-iL`/`--excludefile` read declarations; see [targets][nmap-targets]. | [Scan arguments][scan-args] accept positional targets and numeric exclusions, not target/exclusion files or scanner stdin lists. Add bounded ingestion and consistent authorization/provenance. | Missing | [M4.1][m4] |
| Nmap-specific target grammar | IPv4 octet ranges and hostname/CIDR expressions; see [targets][nmap-targets]. | [Specifications][target-selection] accept numeric CIDRs or individual IP/hostname targets. Nmap's exact shorthand grammar is not implemented or promised; bounded explicit manifests can express the required authorized inventory. | Non-goal | Native selection interfaces in [M4][m4]; no syntax-clone commitment. |
| Scoped IPv6 targets | Zone/interface-qualified non-global addresses; see [targets][nmap-targets]. | [Target values][target-model] use `IpAddr` and validated hostnames. Packet-route interface overrides exist, but declarations do not retain a zone and [connect planning][connect-engine] creates numeric socket endpoints without scope information. | Partial | [M4.3][m4] |
| Bulk list/scan planning | `-sL` lists targets; DNS is independently controllable; see [discovery][nmap-discovery]. | Existing [`plan`][route-plan] performs passive route planning for a packet, not a bounded scan target/port manifest. Add an explicit bulk mode without target/neighbor transmission and with visible resolution opt-ins. | Missing | [M4.2][m4] |
| Scanner DNS enrichment and controls | Reverse DNS, custom resolver selection, and parallel resolution controls; see [targets][nmap-targets]. | [Resolution][target-model] is synchronous system resolution with bounded answers and provider-owned I/O timeout. A [separate DNS workflow][project-readme] supports reverse questions, but scan output has no integrated reverse-name enrichment or configurable scanner resolver workflow. | Partial | [M5.5][m5]; bounded scheduling in [M7][m7]. |
| Dedicated/composed host discovery | Discovery-only/skip-discovery controls and combined ICMP/TCP/UDP probes; see [discovery][nmap-discovery]. | [Scan transports][scan-args] include portless ICMP echo, SYN, UDP, and explicit connect probing, but [scan planning][scan-engine] has no separate discovery stage or host-level composition/selection result. | Partial | [M5.1][m5], [M5.3][m5] |
| Local ARP/NDP discovery | Local-link discovery is distinct from IP probing; see [discovery][nmap-discovery]. | [Neighbor resolution][neighbor-resolver] supplies bounded ARP/NDP route-preparation building blocks, not a host-inventory workflow. Next-hop/cache success must not be interpreted as remote host responsiveness. | Partial | [M5.2][m5] |
| Additional discovery probe families | ACK, ICMP timestamp/netmask, SCTP, and IP-protocol probes; see [discovery][nmap-discovery]. | The [probe transports][scan-args] expose SYN/UDP/echo rather than these discovery families. Extend explicit discovery strategies alongside mode-specific correlation, without adding hidden probes. | Missing | Compose mainstream discovery in [M5.3][m5]; additional families in [M13.4][m13]. |
| Host identity/context metadata | Host state/reasons, reverse names, and local MAC/vendor context; see [guide][nmap-guide] and [discovery][nmap-discovery]. | [Scan reports][scan-report] expose resolved addresses and endpoint/probe evidence, not a composed host record. Add qualified host metadata without converting router MACs, proxy replies, or names into authenticated identity. | Partial | [M5.4][m5], [M5.5][m5] |

## Mainstream scanning and port-state evidence

| Capability | Nmap behavior/reference | PacketcraftR baseline and concrete gap | Status | Roadmap |
| --- | --- | --- | --- | --- |
| TCP SYN scanning | Raw SYN scanning with method-dependent state inference; see [scan techniques][nmap-techniques]. | [Raw probe construction][scan-packets] and [classification][scan-evidence] already implement SYN probing. Responses require a capture-capable profile; pcap-free raw transmission alone is not a capture-backed scan. This is not an absent scan mode. | Present with constraints | [M6][m6] and [M7][m7] improve planning, inference, and performance. |
| Ordinary TCP connect scanning | Kernel connection results; see [scan techniques][nmap-techniques]. | [Connect engine][connect-engine] and its [public CLI regression][connect-contract] already work without raw capture privileges. Concurrency is capped at 16 and packet-route overrides are rejected; socket outcomes remain distinct from wire receipts. | Present with constraints | [M7.6][m7] |
| UDP scanning | Datagram/ICMP observations and ambiguous silent ports; see [scan techniques][nmap-techniques]. | [UDP probes][scan-packets] accept empty or explicit payloads; [profiles][udp-profiles] supply per-port DNS/byte checks. Silence is retained as timeout evidence, not Nmap's inferred `open\|filtered` state. | Present with constraints | [M6.3][m6], [M6.5][m6]; identification in [M8][m8]. |
| Numeric port lists and ranges | Explicit protocol-port selections; see [port selection][nmap-ports]. | [Port selection][scan-request] already expands inclusive numeric ranges with first-seen deduplication and `max_ports` bounds. TCP/UDP require explicit ports; there is no Nmap-style default common-port catalog. | Present with constraints | [M6.1][m6] adds catalog-based selections. |
| Common/named-port presets and exclusions | Named/frequency-ranked ports, fast/top-port selections, and exclusions; see [port selection][nmap-ports]. | [CLI port parsing][scan-args] and [requests][scan-request] are numeric-only without catalog-based presets or port exclusions. Add reviewed, versioned data and ensure discovery cannot silently use excluded ports. | Missing | [M1.2][m1] data gate; [M6.1][m6], [M6.2][m6] behavior. |
| Mixed-protocol scan plans | TCP/UDP/SCTP selections can coexist; see [scan techniques][nmap-techniques] and [port selection][nmap-ports]. | Each [request][scan-request] has one transport. A combined plan needs typed protocol selections, one operation budget, and protocol-aware endpoint identity rather than merging equal TCP/UDP port numbers. | Missing | [M6.4][m6]; SCTP extension in [M13.1][m13]. |
| Capability-aware method choice | Nmap can select connect when raw SYN scanning is unavailable; see [scan techniques][nmap-techniques]. | [`--connect` dispatch][scan-command] is explicit; no automatic scanner method-selection policy exists. Future convenience must expose the selected method and retain explicit raw-method intent and accurate socket/wire evidence. | Partial | [M6.6][m6] |
| Scan-dependent ambiguous states | `open`, `closed`, `filtered`, `unfiltered`, `open\|filtered`, and idle-specific `closed\|filtered`; see [state meanings][nmap-states]. | [Classification][scan-report] uses open/closed/filtered/unreachable/unknown/timeout, with [raw observations][scan-evidence] and ranked endpoint aggregation. Add a separate inference contract; retain timeout, contradictions, and operational failures. Idle-specific labels are not required by this scope. | Partial | Semantics in [M1.1][m1]; mainstream inference in [M6.5][m6]; additional modes in [M12][m12] and [M13][m13]. |
| Reasons, timing, and raw evidence | State reasons and tracing; see [output][nmap-output]. | [Output records][scan-output] already include per-probe reasons, timestamps, RTT, and captured responses. Rolling raw scans also emit `probe_sent` records and partial-failure evidence. They are not identical to Nmap's interactive packet tracing or a packet transcript for kernel connects. | Present with constraints | Preserve in [M1.1][m1] and [M6.5][m6]. |

## Identification, data, and traceroute

| Capability | Nmap behavior/reference | PacketcraftR baseline and concrete gap | Status | Roadmap |
| --- | --- | --- | --- | --- |
| Application protocol/product/version identification | Active TCP/UDP response matching, including nonstandard ports; see [version detection][nmap-version]. | [UDP profile status][udp-profiles] means configured checks matched, not product/version identity. The [workflow surface][workflow-surface] exposes no general service-identification engine, corpus, or result record. | Missing | [M8][m8] |
| TLS-wrapped service identification | Interrogate applications behind TLS when the build supports it; see [version detection][nmap-version]. | [Passive TLS analysis][project-readme] parses captures and fingerprints hellos. The [TCP provider][tcp-provider] supplies ordinary streams, not an active TLS identification workflow. Passive fingerprints are not encrypted application identification. | Missing | [M9.1][m9], [M9.2][m9] |
| Identification intensity and sensitive-service exclusions | Configurable probe intensity and excluded sensitive ports; see [version detection][nmap-version]. | [UDP profiles][udp-profiles] are explicit bounded configurations, not an identification probe-selection/intensity policy. Add finite identification budgets and reviewed read-only probes; avoid assuming every open endpoint is safe to interrogate identically. | Missing | [M8.5][m8] |
| Service metadata and qualified inventory | Product/version, hostname/device context, and supported CPE metadata; see [version detection][nmap-version]. | [Published scan records][scan-output] contain endpoint/probe and configured-profile evidence, without an identification/candidate/confidence model. Preserve observed claims separately from inferred metadata and unsupported fields. | Missing | [M8.4][m8], [M9.5][m9]; OS results in [M10.4][m10] |
| Active OS fingerprinting and matching | Stack fingerprints, suitability checks, candidates, and confidence; see [OS detection][nmap-os]. | The [workflow surface][workflow-surface] and [scan reports][scan-report] contain no OS-fingerprint collection/matching workflow. Packet codecs and JA3/JA4 do not identify the remote operating system. | Missing | [M10][m10] |
| Scanner data provenance and maintenance | Port, probe/match, OS, and vendor data drive coverage; see [port selection][nmap-ports], [version detection][nmap-version], [OS detection][nmap-os], and [licensing][nmap-license]. | Bounded [UDP profile documents][udp-document] exist, but no general scanner fingerprint-data lifecycle exists. Define independent provenance, allowed redistribution, corpus versions, coverage evaluation, and maintenance before importing or shipping data. | Missing | [M1.2][m1], then [M6.1][m6], [M8.3][m8], and [M10.3][m10]. |
| Standalone traceroute strategies | Nmap's traceroute is a scan-integrated capability; see [discovery/traceroute][nmap-discovery]. | [Traceroute requests][trace-request] already expose UDP, TCP SYN, and ICMP, hop bounds, payload shaping, and finite evidence. [Execution][trace-engine] selects one destination and [planning][trace-plan] advances hops upward. Basic tracing is not missing. | Present with constraints | Preserve and integrate in [M11][m11]. |
| Scan-informed multi-host traceroute | Select responsive protocols/endpoints and reuse path information across hosts; see [discovery/traceroute][nmap-discovery]. | [Traceroute execution][trace-engine] is separate from scanning, traces one selected address, and has no cross-host path reuse. Add an authorized multi-host plan with explicit observed versus cached hop provenance. Identical reverse-TTL algorithms are not required. | Missing | [M11][m11] |

## Timing, resources, platforms, and machine output

| Capability | Nmap behavior/reference | PacketcraftR baseline and concrete gap | Status | Roadmap |
| --- | --- | --- | --- | --- |
| Adaptive RTT and retries | Dynamic timeouts, parallelism, retry selection, and rate-limit handling; see [performance][nmap-performance]. | [Requests][scan-request] set fixed timeout/attempt/window values, [planning][scan-plan] computes a conservative schedule, and [reports][scan-report] summarize RTT. Reporting RTT does not imply feedback-driven scheduling; add bounded adaptation. | Partial | [M7.1][m7], [M7.2][m7], [M7.3][m7] |
| Per-host fairness, deadlines, and ordering | Host grouping, timeout/delay controls, and port ordering; see [performance][nmap-performance] and [port selection][nmap-ports]. | [Raw planning][scan-plan] follows address/attempt/port order under global limits. Existing rate and operation-duration ceilings do not implement host-level adaptive fairness, selective retries, or per-host deadlines. | Partial | [M7.4][m7] |
| Scalable bounded work admission | Parallel host/probe scheduling; see [performance][nmap-performance]. | [Raw execution][scan-engine] has bounded rolling windows and prepared descriptions; [connect execution][connect-engine] is capped at 16 process-wide native operations. Add scalable scheduling/retention without removing the [scan ceilings][scan-limits] or cleanup accounting. | Partial | [M7.5][m7], [M7.6][m7] |
| Existing resource and failure evidence | Nmap exposes timing/reason controls; see [performance][nmap-performance] and [output][nmap-output]. | [Limits][scan-request], [pipeline contracts][pipeline-contract], and [published failure records][scan-output] already cover bounded preparation/evidence and confirmed pending transmissions. Preserve these strengths; logical byte charges and complete acquisition are not the same claim. | Present with constraints | [M1.1][m1] and [M7][m7] |
| IPv4/IPv6 and native platform coverage | IPv6 and platform/build-dependent capabilities; see [options][nmap-options] and [downloads][nmap-download]. | [Feature profiles][project-readme], [capability selection][native-build], and [dispatch][native-dispatch] cover Linux/macOS/Windows, not every Nmap platform. macOS complete-header raw IPv6 transmission and Windows raw-source restrictions remain explicit limits; capture-backed work needs Layer 2 support. | Partial | Platform gate in [M3][m3], tracked in every milestone. |
| Privileged native runtime evidence | Platform/build-dependent raw and socket capabilities; see [scan techniques][nmap-techniques] and [downloads][nmap-download]. A guide entry is not runtime evidence. | The [validation matrix][native-validation] and [CI routes][ci] distinguish Linux isolated runtime checks from macOS/Windows compilation, passive, and deterministic contracts. Equivalent configured privileged macOS/Windows evidence is missing. | Partial | [M3][m3], required for each native milestone. |
| Versioned machine output | Nmap offers normal/XML and other output formats; see [output][nmap-output]. | [Scan command formats][scan-command] already support text, JSON, and NDJSON under [output v6][output-contract], with streaming terminal semantics and a [compatibility policy][compatibility]. Machine output is not a missing capability; it is a different contract. | Present with constraints | Preserve/version in every milestone; no schema change in this roadmap addition. |

## Broader diagnostic scan coverage

| Capability | Nmap behavior/reference | PacketcraftR baseline and concrete gap | Status | Roadmap |
| --- | --- | --- | --- | --- |
| TCP ACK/window and flag-based diagnostics | ACK, window, FIN/NULL/Xmas/Maimon, and configurable flag/base-method semantics; see [scan techniques][nmap-techniques]. | [Probe construction][scan-packets] requires SYN for the TCP scan workflow; custom packets built elsewhere are not a diagnostic scan engine. Add mode-specific correlation and inference, including documented stack-dependent limitations. | Missing | [M12][m12] |
| SCTP INIT/COOKIE-ECHO diagnostics | SCTP-specific probing and ambiguous response handling; see [scan techniques][nmap-techniques]. | Core has an [SCTP codec][sctp-codec] and [matcher building blocks][sctp-matcher], but [scan transports][scan-args] contain no SCTP mode. Add bounded chunk models, workflow correlation, and typed outcomes rather than equating codec presence with scanner support. | Partial | [M13.1][m13], [M13.2][m13] |
| IP-protocol inventory | Protocol-number discovery rather than transport-port scanning; see [scan techniques][nmap-techniques]. | [Requests][scan-request] target TCP/UDP ports or ICMP echo, not a selected protocol-number set. Add typed bounded protocol selection and correlated positive/negative/ambiguous evidence. | Missing | [M13.3][m13] |

## Deferred capabilities and deliberate differences

These entries prevent recorded gaps from becoming accidental commitments.

| Area | Nmap comparison/reference | Roadmap decision | Status |
| --- | --- | --- | --- |
| Scripting/NSE | [Scripting engine][nmap-nse] and script ecosystems. | Deferred by scope choice; no Lua/NSE compatibility or general extension runtime is planned in M1-M13. Built-in protocol identification is not a scripting engine. | Deferred |
| Scan resume/checkpointing | Resume interrupted scans from saved output; see [output][nmap-output]. | Record the gap, but do not add persistent/resumable execution before the core scanner/evidence foundations. Current streamed partial evidence is not a checkpoint. | Deferred |
| Nmap XML interoperability | XML output and downstream consumers; see [output][nmap-output]. | Retain PacketcraftR's JSON/NDJSON contracts. A reviewed exporter may be a later integration project, not a prerequisite for core capability parity. | Deferred |
| Exact CLI grammar and legacy output formats | Nmap-specific flags, shorthand selection syntax, and legacy formats; see [options][nmap-options] and [output][nmap-output]. | Preserve native, explicit PacketcraftR interfaces rather than promise a drop-in Nmap executable or byte-identical output. | Non-goal |
| Evasion/decoys, idle/bounce, exploit/brute-force workflows | The [options][nmap-options] and [scan techniques][nmap-techniques] document additional techniques outside the selected inventory/diagnostic scope. | No parity commitment for these workflows. Existing packet-development controls do not change this roadmap's scope. | Non-goal |
| Random public targets or unbounded scans | Random/unbounded target options appear in [target specification][nmap-targets]. | Keep explicit authorized targets and finite resource budgets. | Non-goal |
| Nmap companion application suite | The [download page][nmap-download] also distributes companion applications. | No Zenmap/Ncat/Nping/Ndiff clone commitment; PacketcraftR's construction/capture/offline-analysis capabilities remain their own product strengths. | Non-goal |

## Evidence and acceptance

Source links establish what the reviewed implementation exposes; they do not
prove that every platform passed runtime tests. Existing
[connect contracts][connect-contract] exercise loopback socket outcomes and
[scan pipeline contracts][pipeline-contract] cover preparation/pacing/evidence
limits with controlled providers. Neither replaces a real native capture/send
check on another operating system.

Future gap closure follows the roadmap's
[definition of done][definition-of-done] and [close gates][close-gates]. Record
fixture ground truth and expected divergences before using Nmap as a comparison
tool. Update source links, milestone status, known limits, and the comparison
revision together. Never make packet silence, a skipped native test, or a
matched configured profile stand in for evidence it does not provide.

[m1]: m01-claims-evidence.md
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
[definition-of-done]: README.md#definition-of-done
[close-gates]: README.md#close-gates
[project-readme]: ../../README.md
[compatibility]: ../consumer-compatibility.md
[native-validation]: ../native-validation.md
[ci]: ../../.github/workflows/ci.yml
[target-model]: ../../crates/packetcraftr/src/target/model.rs
[target-selection]: ../../crates/packetcraftr/src/target/selection.rs
[target-admission]: ../../crates/packetcraftr/src/target/admission.rs
[route-plan]: ../../crates/packetcraftr-cli/src/commands/plan.rs
[neighbor-resolver]: ../../crates/packetcraftr/src/neighbor/resolver.rs
[scan-args]: ../../crates/packetcraftr-cli/src/commands/scan/arguments.rs
[scan-command]: ../../crates/packetcraftr-cli/src/commands/scan.rs
[scan-limits]: ../../crates/packetcraftr/src/scan.rs
[scan-request]: ../../crates/packetcraftr/src/scan/request.rs
[scan-plan]: ../../crates/packetcraftr/src/scan/plan.rs
[scan-engine]: ../../crates/packetcraftr/src/scan/engine.rs
[scan-packets]: ../../crates/packetcraftr/src/scan/plan/packet.rs
[scan-evidence]: ../../crates/packetcraftr/src/scan/evidence.rs
[scan-report]: ../../crates/packetcraftr/src/scan/report.rs
[scan-output]: ../../crates/packetcraftr-cli/src/output/scan.rs
[connect-engine]: ../../crates/packetcraftr/src/scan/connect/engine.rs
[connect-contract]: ../../crates/packetcraftr-cli/tests/integration/connect_scan_contracts.rs
[pipeline-contract]: ../../crates/packetcraftr/tests/integration/scan_pipeline_contracts.rs
[udp-profiles]: ../../crates/packetcraftr/src/scan/profile.rs
[udp-document]: ../../crates/packetcraftr-core/src/document/udp_profiles.rs
[workflow-surface]: ../../crates/packetcraftr/src/lib.rs
[tcp-provider]: ../../crates/packetcraftr-netio/src/tcp.rs
[trace-request]: ../../crates/packetcraftr/src/traceroute/request.rs
[trace-engine]: ../../crates/packetcraftr/src/traceroute/engine.rs
[trace-plan]: ../../crates/packetcraftr/src/traceroute/plan.rs
[sctp-codec]: ../../crates/packetcraftr-core/src/protocol/transport/sctp.rs
[sctp-matcher]: ../../crates/packetcraftr-core/src/protocol/matcher/sctp.rs
[native-build]: ../../crates/packetcraftr-netio/build.rs
[native-dispatch]: ../../crates/packetcraftr-netio/src/platform/dispatch.rs
[output-contract]: ../../crates/packetcraftr-cli/src/output/contract.rs
[nmap-guide]: https://nmap.org/book/man.html
[nmap-targets]: https://nmap.org/book/man-target-specification.html
[nmap-discovery]: https://nmap.org/book/man-host-discovery.html
[nmap-techniques]: https://nmap.org/book/man-port-scanning-techniques.html
[nmap-ports]: https://nmap.org/book/man-port-specification.html
[nmap-states]: https://nmap.org/book/man-port-scanning-basics.html
[nmap-version]: https://nmap.org/book/man-version-detection.html
[nmap-os]: https://nmap.org/book/man-os-detection.html
[nmap-performance]: https://nmap.org/book/man-performance.html
[nmap-output]: https://nmap.org/book/man-output.html
[nmap-options]: https://nmap.org/book/man-briefoptions.html
[nmap-nse]: https://nmap.org/book/man-nse.html
[nmap-download]: https://nmap.org/download.html
[nmap-license]: https://nmap.org/npsl/
