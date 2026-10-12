# Nmap core-scanner gap matrix

Comparison of authorized scanner capabilities, not the full Nmap suite.
The initial review used `22c7d182d577` on 2026-10-05 and the official Nmap guide
(download listing 7.991). Rows now describe current implementation; open
acceptance remains explicit. This documentation refresh establishes no new run
or revision-wide coverage score.

Revision-bound acceptance: [M4](evidence/m04/README.md) targets/scopes at
`8e010a0b9eac118aa13384f0b854111a73d47d76`; [M5](evidence/m05/README.md)
Linux discovery at `e7f3e2efa7b47ba2ffa7e2818dbcc4d53eaef9e3`;
[M8](evidence/m08/README.md) identification at
`99a9cf23216eb490892c0b6659e303d1a0b02c3d`;
[M9](evidence/m09/README.md) TLS/held-out quality at
`5e5a41470c0c63404ca3e581067fded136eda1ce`.
The [roadmap scorecard](README.md#gap-gate-and-scorecard) preserves historical
counts rather than measuring this checkout. No new live Nmap comparison is claimed;
differential runs must pin version/build/settings, independent truth, and acquisition.

## Status legend

| Status | Meaning |
| --- | --- |
| Present with constraints | The capability exists; the listed profile, method, resource, and evidence limits still apply. This is not complete equivalence to every Nmap default or option. |
| Partial | Related behavior/building blocks exist, but the compared workflow or coverage is incomplete. |
| Missing | No corresponding scanner capability is exposed in the reviewed workflow/CLI surface. |
| Deferred | A recorded gap outside the committed milestones of this roadmap. |
| Non-goal | A deliberate product/scope difference; no parity commitment. |

Milestone links identify ownership, not completion. Partial includes implemented
behavior with open independent/native acceptance. Codecs and generic packet
building are not scanner workflows.

## Targets, discovery, and host inventory

| Capability | Nmap behavior/reference | Current behavior and remaining gate | Status | Roadmap |
| --- | --- | --- | --- | --- |
| Explicit targets, CIDRs, exclusions, and families | [targets][nmap-targets] | [Admission][target-admission] bounds expansion/deduplication/numeric exclusions/families for arguments and manifests. Hostnames require opt-in; all authorized selected answers count, not Nmap first-answer defaults. | Present with constraints | [M4][m4] |
| Target/exclusion files and stdin | [targets][nmap-targets] | Line-oriented --targets-file/--exclude-file share 1 MiB/4,096 physical lines/512 bytes per declaration and one stdin consumer. Source/line provenance survives admission; malformed input fails before providers. | Present with constraints | [M4][m4] |
| Nmap-specific target grammar | [targets][nmap-targets] | Numeric CIDRs/individual IPs/hostnames and bounded manifests; no octet-range or hostname/CIDR shorthand clone. | Non-goal | [M4][m4] |
| Scoped IPv6 targets | [targets][nmap-targets] | Unicast fe80::/10 zones resolve to one interface; address/interface identity merges aliases. [M4 records](evidence/m04/README.md) cover list/connect/raw or typed refusals across five profiles. Missing enumeration refuses; trace/packet-route/DNS TCP reject scope. | Present with constraints | [M4][m4], [M4][m4], [M3][m3] |
| Bulk list/scan planning | [discovery][nmap-discovery] | scan --list uses [plan_targets][target-plan], preserving scope/origins/ports without target/neighbor packets. Numeric unscoped selections use no providers; scoped ones enumerate passively. Authorized DNS is reported, not network-free. | Present with constraints | [M4][m4] |
| Scanner DNS enrichment and controls | [targets][nmap-targets] | Bounded synchronous target resolution and explicit authorized-server PTR follow-up under remaining duration. Names are observations; broader native acceptance stays M5/M7 work. | Partial | [M5][m5], [M7][m7] |
| Dedicated/composed host discovery | [discovery][nmap-discovery] | Opt-in before/only/skip over echo/SYN/UDP/explicit TCP sockets; responders-only or scan-all follow-up. Independent dual-stack/Linux results recorded; broader native acceptance open. | Partial | [M5][m5], [M5][m5] |
| Local ARP/NDP discovery | [discovery][nmap-discovery] | Bounded explicit neighbors with direct/cache/possible-proxy/silent/routed evidence. Gateway link is not target identity. Linux recorded; broader native acceptance open. | Partial | [M5][m5] |
| Additional discovery probe families | [discovery][nmap-discovery] | No ACK/timestamp/netmask/SCTP/IP-protocol discovery; requires explicit mode-specific construction/correlation, never hidden extra probes. | Missing | [M5][m5], [M13][m13] |
| Host identity/context metadata | [guide][nmap-guide], [discovery][nmap-discovery] | Ordered host reasons, timestamps, explicit PTR, and local link observations with wire/socket/cache provenance. No vendor database or authenticated identity; broader acceptance open. | Partial | [M5][m5], [M5][m5] |

## Mainstream scanning and port-state evidence

| Capability | Nmap behavior/reference | Current behavior and remaining gate | Status | Roadmap |
| --- | --- | --- | --- | --- |
| TCP SYN scanning | [scan techniques][nmap-techniques] | SYN probes/correlation exist. Responses need Layer 2 capture; pcap-free transmission alone is not a capture-backed scan. | Present with constraints | [M6][m6], [M7][m7] |
| Ordinary TCP connect scanning | [scan techniques][nmap-techniques] | Kernel results work without raw privileges. Shared native pool caps starts at 16; route overrides fail. Adaptive admission may backpressure larger operation windows. No wire transcript. | Present with constraints | [M7][m7] |
| UDP scanning | [scan techniques][nmap-techniques] | Empty/explicit/curated/operator payloads, configured checks, captured replies/errors. Silent attempts stay timeout; separate inference can be open_or_filtered. Confirmation is not identification. | Present with constraints | [M6][m6], [M6][m6], [M8][m8] |
| Numeric port lists and ranges | [port selection][nmap-ports] | Inclusive ranges, first-seen deduplication, transport identity, and finite selection. TCP/UDP require explicit ports; no default set. | Present with constraints | [M6][m6] |
| Common/named-port presets and exclusions | [port selection][nmap-ports] | Original catalog 1.0.0: 73 RFC-cited names/six topical presets; exclusions precede budgets and bind discovery. No frequency-ranked top ports. Implemented; M6 close gates open. | Partial | [M1][m1], [M6][m6], [M6][m6] |
| Mixed-protocol scan plans | [scan techniques][nmap-techniques], [port selection][nmap-ports] | Typed TCP/UDP endpoints share policy/work/evidence/duration budgets without merging equal ports. Implemented; M6 independent/native gates open. SCTP remains M13. | Partial | [M6][m6], [M13][m13] |
| Capability-aware method choice | [scan techniques][nmap-techniques] | --method auto selects raw with build capture/transmit support, otherwise all-TCP connect, publishing reason. Default raw and explicit methods never fall back. Runtime privilege is not predicted; M6 acceptance open. | Partial | [M6][m6] |
| Scan-dependent ambiguous states | [state meanings][nmap-states] | Separate [inference][evidence-inference] partitions supporting/conflicting/unanswered/failed sequences beside unchanged attempts. Silent UDP→open_or_filtered; local failures→no state. M6 close gates open; extra modes remain M12/M13. | Partial | [M1][m1], [M6][m6], [M12][m12], [M13][m13] |
| Reasons, timing, and raw evidence | [output][nmap-output] | Per-probe reasons, submission/ingress timing, RTT, capture/source evidence, rolling probe_sent, and partial errors. Kernel connects are not packet tracing. | Present with constraints | [M1][m1], [M6][m6] |

## Identification, data, and traceroute

| Capability | Nmap behavior/reference | Current behavior and remaining gate | Status | Roadmap |
| --- | --- | --- | --- | --- |
| Application protocol/product/version identification | [version detection][nmap-version] | Explicit bounded SSH/HTTP/DNS/SMTP/FTP numeric-endpoint probes with reviewed corpus, separate untrusted claims/candidates/ordinal confidence/provenance. UDP checks retain their old meaning. | Present with constraints | [M8][m8] |
| TLS-wrapped service identification | [version detection][nmap-version] | Explicit TLS 1.2/1.3 TCP wrapping with encrypted/step/time/certificate limits and declared SNI; unauthenticated DER evidence. M9 five-profile/four-platform acceptance. No STARTTLS/automatic fallback. | Present with constraints | [M9][m9], [M9][m9] |
| Identification intensity and sensitive-service exclusions | [version detection][nmap-version] | Intensity 1–9 under operation/host/connection/probe ceilings; independent exclusions before planning, explicit override that never bypasses policy. | Present with constraints | [M8][m8] |
| Service metadata and qualified inventory | [version detection][nmap-version] | Observed fields and supported hostname/static CPE values carry sources. Unknown/ambiguous evidence asserts no exact version; no bundled device types. Held-out token fidelity is not software identity accuracy. | Present with constraints | [M8][m8], [M9][m9], [M10][m10] |
| Active OS fingerprinting and matching | [OS detection][nmap-os] | Standalone bounded dual-stack probes, verified prerequisites, preserved observations, qualified family matching, and original Linux Ethernet corpus. Broader corpus and native acceptance remain open. | Present with constraints | [M10][m10] |
| Scanner data provenance and maintenance | [port selection][nmap-ports], [version detection][nmap-version], [OS detection][nmap-os], [licensing][nmap-license] | Independent original catalog/UDP/probes/exclusions with reviewed sources, owner/refresh/fixture coverage. Original narrowly validated Linux OS signatures; vendor datasets remain unimplemented; no copied Nmap data. | Present with constraints | [M1][m1], [M6][m6], [M8][m8], [M10][m10] |
| Standalone traceroute strategies | [discovery/traceroute][nmap-discovery] | Bounded UDP/TCP SYN/ICMP, hops, shaping, and evidence. Single-target standalone shapes preserved; scan trace is separate. | Present with constraints | [M11][m11] |
| Scan-informed multi-host traceroute | [discovery/traceroute][nmap-discovery] | Select target SYN/ACK/reset/echo or explicit fallback; no evidence→not_traced. Optional source/age-qualified reuse is a claim. Sequential hosts; reconvergence/ECMP risk. Historical delayed Linux run only; M11 close gate open. | Present with constraints | [M3][m3], [M2][m2], [M7][m7], [M11][m11] |

## Timing, resources, platforms, and machine output

| Capability | Nmap behavior/reference | Current behavior and remaining gate | Status | Roadmap |
| --- | --- | --- | --- | --- |
| Adaptive RTT and retries | [performance][nmap-performance] | Opt-in bounded first-attempt RTT estimator, selective capped retries/backoff, AIMD windows, qualified rate-limit suspicion. Fixed default. Implemented; agreed/native performance acceptance open. | Partial | [M7][m7], [M7][m7], [M7][m7] |
| Per-host fairness, deadlines, and ordering | [performance][nmap-performance], [port selection][nmap-ports] | Adaptive deterministic host turns and absolute per-host deadlines include preparation/pacing/callback delays. Never-sent work has no outcome and marks host incomplete. M7 acceptance open. | Partial | [M7][m7] |
| Scalable bounded work admission | [performance][nmap-performance] | Bounded adaptive preparation waves/retention and connect admission beneath shared pool 16. Cleanup leases survive cancellation. No accepted native throughput/capacity increase. | Partial | [M7][m7], [M7][m7] |
| Existing resource and failure evidence | [performance][nmap-performance], [output][nmap-output] | Finite preparation/evidence, pending confirmed transmissions, capture-source validity, omissions, and typed partial failures. Logical charges differ from RSS and acquisition completeness. | Present with constraints | [M1][m1], [M7][m7] |
| IPv4/IPv6 and native platform coverage | [options][nmap-options], [downloads][nmap-download] | Five profiles on Linux/macOS/Windows; macOS complete-header IPv6 and Windows raw-source limits explicit. Capture-backed work needs Layer 2. Broad native parity remains open. | Partial | [M3][m3] |
| Privileged native runtime evidence | [scan techniques][nmap-techniques], [downloads][nmap-download] | Isolated Linux and reviewed host-local routes; M4 scoped and M8/M9 ordinary-socket recordings retained. Broader native inventory/isolation/admin protections remain M3 gates. | Partial | [M3][m3] |
| Versioned machine output | [output][nmap-output] | Text/JSON/NDJSON output/v14 with terminal/error semantics. v6–v13 remain frozen; [compatibility][compatibility] distinguishes shapes and meanings. Not an XML/syntax clone. | Present with constraints | [M4][m4] |

## Broader diagnostic scan coverage

| Capability | Nmap behavior/reference | Current behavior and remaining gate | Status | Roadmap |
| --- | --- | --- | --- | --- |
| TCP ACK/window and flag-based diagnostics | [scan techniques][nmap-techniques] | No scanner mode beyond SYN; generic custom packets are not a diagnostic engine. Need separate flag/rule selection, correlation, and qualified inference. | Missing | [M12][m12] |
| SCTP INIT/COOKIE-ECHO diagnostics | [scan techniques][nmap-techniques] | SCTP codec/tag helpers only, no scanner transport. Need bounded chunks, workflow correlation, and ambiguity-preserving results. | Partial | [M13][m13], [M13][m13] |
| IP-protocol inventory | [scan techniques][nmap-techniques] | No selected protocol-number scan plan. Must be typed separately from transport ports with correlated positive/negative/ambiguous evidence. | Missing | [M13][m13] |

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

Source/contract tests establish exposed behavior, not another OS's raw runtime.
[M2 ground truth][m2] and [M3 native evidence][m3] gate applicable milestones;
Nmap agreement alone is insufficient. Preserve exact revisions, failures,
unavailable paths, source links, and known limits when updating rows. Silence,
configured-check matches, and skipped checks must never imply unsupported claims.

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
[compatibility]: ../consumer-compatibility.md
[target-plan]: ../../crates/packetcraftr/src/target/plan.rs
[target-admission]: ../../crates/packetcraftr/src/target/admission.rs
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
[evidence-inference]: ../scanner-evidence.md#port-inference
