# Nmap core-scanner gap matrix

Comparison of authorized scanner capabilities, not the full Nmap suite.
Initial review: `22c7d182d577` (2026-10-05) against the Nmap 7.991 guide.
Rows describe current implementation; open acceptance stays explicit.

Revision-bound acceptance: [M4](evidence/m04/README.md) (`8e010a0b`),
[M5](evidence/m05/README.md) Linux discovery (`e7f3e2ef`),
[M8](evidence/m08/README.md) identification (`99a9cf23`), and
[M9](evidence/m09/README.md) TLS/held-out quality (`5e5a4147`).
See the [roadmap scorecard](README.md#gap-gate-and-scorecard).

## Status legend

| Status | Meaning |
| --- | --- |
| Present with constraints | Capability exists under listed profile, method, resource, and evidence limits; not equivalence to every Nmap default/option. |
| Partial | Building blocks or implementation exist, with open independent or native acceptance. |
| Missing | No corresponding scanner capability in the workflow/CLI surface. |
| Deferred | Recorded gap outside M1–M13. |
| Non-goal | Deliberate product/scope difference. |

## Targets, discovery, and host inventory

| Capability | Nmap reference | Current behavior and remaining gate | Status | Roadmap |
| --- | --- | --- | --- | --- |
| Explicit targets, CIDRs, exclusions, and families | [targets][nmap-targets] | [Admission][target-admission] bounds expansion, deduplication, numeric exclusions, and families; hostnames require opt-in and retain all selected answers. | Present with constraints | [M4][m4] |
| Target/exclusion files and stdin | [targets][nmap-targets] | `--targets-file`/`--exclude-file` share 1 MiB, 4,096 lines, 512 bytes/line, and one stdin consumer with source/line provenance. | Present with constraints | [M4][m4] |
| Nmap-specific target grammar | [targets][nmap-targets] | Numeric CIDRs, IPs, hostnames, and manifests only; no octet-range shorthand. | Non-goal | [M4][m4] |
| Scoped IPv6 targets | [targets][nmap-targets] | Unicast `fe80::/10` zones resolve to one interface and merge aliases ([M4 records](evidence/m04/README.md)); trace/packet-route/DNS TCP reject scope. | Present with constraints | [M3][m3], [M4][m4] |
| Bulk list/scan planning | [discovery][nmap-discovery] | `scan --list` uses [plan_targets][target-plan] without target/neighbor packets; authorized DNS is reported. | Present with constraints | [M4][m4] |
| Scanner DNS enrichment and controls | [targets][nmap-targets] | Bounded target resolution and explicit PTR follow-up under remaining duration; broader native acceptance open. | Partial | [M5][m5], [M7][m7] |
| Dedicated/composed host discovery | [discovery][nmap-discovery] | Opt-in `before`/`only`/`skip` over echo/SYN/UDP/TCP connect; Linux recorded, macOS/Windows native acceptance open. | Partial | [M5][m5] |
| Local ARP/NDP discovery | [discovery][nmap-discovery] | Bounded neighbors with direct/cache/possible-proxy/silent/routed evidence; Linux recorded, macOS/Windows open. | Partial | [M5][m5] |
| Additional discovery probe families | [discovery][nmap-discovery] | Opt-in `tcp-ack`, `icmp-timestamp`, `icmp-netmask`, `sctp`, and `ip` discovery probes with exclusions and finite budgets; native acceptance open. | Partial | [M5][m5], [M13][m13] |
| Host identity/context metadata | [guide][nmap-guide], [discovery][nmap-discovery] | Ordered host reasons, timestamps, PTR, and link observations with provenance; no vendor DB; broader acceptance open. | Partial | [M5][m5] |

## Mainstream scanning and port-state evidence

| Capability | Nmap reference | Current behavior and remaining gate | Status | Roadmap |
| --- | --- | --- | --- | --- |
| TCP SYN scanning | [scan techniques][nmap-techniques] | SYN probes/correlation; responses require Layer 2 capture. | Present with constraints | [M6][m6], [M7][m7] |
| Ordinary TCP connect scanning | [scan techniques][nmap-techniques] | Kernel sockets without raw privileges; shared 16-worker pool caps concurrent starts, queueing larger windows. | Present with constraints | [M7][m7] |
| UDP scanning | [scan techniques][nmap-techniques] | Empty/explicit/curated/operator payloads and response checks; silent attempts infer `open_or_filtered`. | Present with constraints | [M6][m6], [M8][m8] |
| Numeric port lists and ranges | [port selection][nmap-ports] | Inclusive ranges, first-seen deduplication, transport identity, explicit selection required. | Present with constraints | [M6][m6] |
| Common/named-port presets and exclusions | [port selection][nmap-ports] | Catalog 1.0.0 (73 RFC-cited names, six presets); exclusions precede budgets; M6 close gates open. | Partial | [M1][m1], [M6][m6] |
| Mixed-protocol scan plans | [scan techniques][nmap-techniques], [port selection][nmap-ports] | Typed TCP/UDP/SCTP endpoints share budgets without merging equal ports; M6/M13 native/comparison gates open. | Partial | [M6][m6], [M13][m13] |
| Capability-aware method choice | [scan techniques][nmap-techniques] | `--method auto` selects raw when build supports capture+transmit, else TCP connect; M6 acceptance open. | Partial | [M6][m6] |
| Scan-dependent ambiguous states | [state meanings][nmap-states] | [Inference][evidence-inference] partitions supporting/conflicting/unanswered/failed attempts across TCP, UDP, SCTP, and IP-protocol scans; M6/M12/M13 close gates open. | Partial | [M1][m1], [M6][m6], [M12][m12], [M13][m13] |
| Reasons, timing, and raw evidence | [output][nmap-output] | Per-probe reasons, submission/ingress timing, RTT, capture/source evidence, `probe_sent`, and partial errors. | Present with constraints | [M1][m1], [M6][m6] |

## Identification, data, and traceroute

| Capability | Nmap reference | Current behavior and remaining gate | Status | Roadmap |
| --- | --- | --- | --- | --- |
| Application protocol/product/version identification | [version detection][nmap-version] | Explicit bounded SSH/HTTP/DNS/SMTP/FTP probes over numeric endpoints with separate claims, candidates, and provenance. | Present with constraints | [M8][m8] |
| TLS-wrapped service identification | [version detection][nmap-version] | Explicit TLS 1.2/1.3 wrapping with byte/step/time/cert limits and declared SNI ([M9 acceptance](evidence/m09/README.md)); no STARTTLS. | Present with constraints | [M9][m9] |
| Identification intensity and exclusions | [version detection][nmap-version] | Intensity 1–9 under four-scope budgets; sensitive-service exclusions before planning (`--ignore-exclusions` overrides data only). | Present with constraints | [M8][m8] |
| Service metadata and qualified inventory | [version detection][nmap-version] | Sourced hostnames and static wildcard-version CPEs; unknown/ambiguous results assert no exact version. | Present with constraints | [M8][m8], [M9][m9], [M10][m10] |
| Active OS fingerprinting and matching | [OS detection][nmap-os] | Standalone `identify-os` with dual-stack probes, prerequisite checks, and Linux Ethernet signatures; broader corpus/native gates open. | Present with constraints | [M10][m10] |
| Scanner data provenance and maintenance | [licensing][nmap-license] | Original catalog, UDP profiles, service probes/exclusions, and Linux OS signatures with provenance manifests; no Nmap data. | Present with constraints | [M1][m1], [M6][m6], [M8][m8], [M10][m10] |
| Standalone traceroute strategies | [discovery/traceroute][nmap-discovery] | Bounded UDP/TCP SYN/ICMP hops, shaping, and evidence. | Present with constraints | [M11][m11] |
| Scan-informed multi-host traceroute | [discovery/traceroute][nmap-discovery] | Responsive SYN/ACK, reset, or echo selection with optional sourced hop reuse; M11 close gates open. | Present with constraints | [M2][m2], [M3][m3], [M7][m7], [M11][m11] |

## Timing, resources, platforms, and machine output

| Capability | Nmap reference | Current behavior and remaining gate | Status | Roadmap |
| --- | --- | --- | --- | --- |
| Adaptive RTT and retries | [performance][nmap-performance] | Opt-in first-attempt RTT estimator, capped backoff retries, AIMD windows, and rate-limit suspicion; M7 acceptance open. | Partial | [M7][m7] |
| Per-host fairness, deadlines, and ordering | [performance][nmap-performance], [port selection][nmap-ports] | Deterministic host turns and per-host deadlines marking uncompleted hosts `incomplete`; M7 acceptance open. | Partial | [M7][m7] |
| Scalable bounded work admission | [performance][nmap-performance] | Bounded preparation waves and connect admission beneath the 16-worker pool; M7 acceptance open. | Partial | [M7][m7] |
| Existing resource and failure evidence | [performance][nmap-performance], [output][nmap-output] | Finite preparation/evidence, pending confirmed sends, capture-source validity, omissions, and typed partial errors. | Present with constraints | [M1][m1], [M7][m7] |
| IPv4/IPv6 and native platform coverage | [options][nmap-options], [downloads][nmap-download] | Five profiles on Linux/macOS/Windows with explicit platform capability limits; broad native parity open. | Partial | [M3][m3] |
| Privileged native runtime evidence | [scan techniques][nmap-techniques], [downloads][nmap-download] | Isolated Linux and reviewed host-local routes; broader macOS/Windows inventory and admin gates remain in M3. | Partial | [M3][m3] |
| Versioned machine output | [output][nmap-output] | Text/JSON/NDJSON output/v16 with terminal/error semantics; v6–v15 remain frozen ([compatibility][compatibility]). | Present with constraints | [M4][m4] |

## Broader diagnostic scan coverage

| Capability | Nmap reference | Current behavior and remaining gate | Status | Roadmap |
| --- | --- | --- | --- | --- |
| TCP ACK/window and flag-based diagnostics | [scan techniques][nmap-techniques] | ACK, window, FIN, NULL, Xmas, Maimon, and custom modes with dataset 1.7.0 and `tcp_diagnostics` native runner; cross-platform recordings and OS truth open ([TCP diagnostics](../tcp-diagnostics.md)). | Partial | [M12][m12] |
| SCTP INIT/COOKIE-ECHO diagnostics | [scan techniques][nmap-techniques] | Raw `init` and `cookie-echo` modes with per-sequence tags, `sctp_init.*`/`sctp_cookie_echo.*` rules, and dataset 1.8.0; cross-platform recordings open. | Partial | [M13][m13] |
| IP-protocol inventory | [scan techniques][nmap-techniques] | Standalone `--transport ip` (`0..=255`) with exclusions, `ip_protocol.*` rules, and dataset 1.8.0; cross-platform recordings open. | Partial | [M13][m13] |

## Deferred capabilities and deliberate differences

| Area | Nmap reference | Roadmap decision | Status |
| --- | --- | --- | --- |
| Scripting/NSE | [Scripting engine][nmap-nse] | Deferred outside M1–M13; built-in identification is not a scripting runtime. | Deferred |
| Scan resume/checkpointing | [output][nmap-output] | Deferred; streamed partial evidence is not a resumable checkpoint. | Deferred |
| Nmap XML interoperability | [output][nmap-output] | Deferred; PacketcraftR uses versioned JSON/NDJSON contracts. | Deferred |
| Exact CLI grammar and legacy output | [options][nmap-options], [output][nmap-output] | Preserve explicit PacketcraftR CLI/output rather than drop-in Nmap syntax. | Non-goal |
| Evasion/decoys, idle/bounce, exploit/brute-force | [options][nmap-options], [scan techniques][nmap-techniques] | Outside authorized inventory/diagnostic scope. | Non-goal |
| Random public targets or unbounded scans | [target specification][nmap-targets] | Require explicit authorized targets and finite budgets. | Non-goal |
| Nmap companion application suite | [downloads][nmap-download] | No Zenmap/Ncat/Nping/Ndiff clone commitment. | Non-goal |

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
