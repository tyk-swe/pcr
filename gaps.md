# PacketcraftR feature gaps

## Scope and baseline

Assessed **2026-09-12**, at commit `e5e2bf0b8849b79ebf72c3ef50848f0bd406f79d`
on `main`. The working tree was clean and there was no previous `gaps.md`.
The manifest identifies `0.5.0-beta.3`; this assessment includes the implemented
`[Unreleased]` changes, rather than treating the last release as the whole product.

PacketcraftR is a Rust library and CLI for protocol development, interoperability
testing, and authorized network diagnostics. Its distinguishing capabilities are
exact packet bytes, reflective construction, bounded parsing and analysis, and
policy-gated live operations. It is pre-1.0, with independently versioned packet
documents and machine output. Sources: [README](README.md),
[workspace manifest](Cargo.toml), [repository guidance](AGENTS.md),
[changelog](CHANGELOG.md), and [migration notes](docs/migration-unreleased.md).

This inventory assesses packet construction, common IP application inspection,
capture handling, replay, scans, and CLI data extraction across all four crates.
It covers public interfaces, relevant implementation paths, fixtures, examples,
and regression tests. It is not an exhaustive protocol catalog comparison,
performance benchmark, security audit, or certification of native backends.
At assessment time, cited tests were inspected, not executed, and no live traffic
was generated. Subsequent implementation validation is recorded below.

The public [issue list](https://github.com/tyk-swe/pcr/issues) returned no open
issues on the assessment date. The only open PR was
[PR #167](https://github.com/tyk-swe/pcr/pull/167), concerning isolated native CI
identity mapping. No separate roadmap was found in the checkout. Thus every gap
below was a candidate at assessment time. The approved implementation now closes
all 20 candidates, as recorded below.

## Implementation status

**All 20 gaps are closed** on `tyk/close-feature-gaps`. The capability map and
inventory below preserve the original assessment, including its historical
missing/partial descriptions. This table records the resulting behavior and
regression evidence against those closure criteria.

| Closed gaps | Implementation and regression evidence |
| --- | --- |
| GAP-001, GAP-002 | Named DNS/TLS fixture construction, exact retained wire, nested fields; `dns_construction_contracts`, `tls_construction_contracts`, and CLI `construction_workflows` pass. |
| GAP-011, GAP-012 | Shared-queue multi-interface capture, one policy budget/readiness barrier, per-source loss/cleanup, strict frame-boundary byte/time rotation, stop/ring retention, and partial file evidence; native/workflow/CLI and schema regressions pass. |
| GAP-007 | DHCPv4/DHCPv6 codecs, named options, overloaded areas, relays, DUIDs, IA_NA/IA_PD, unknown bytes and bounded construction; core, codec-matrix, document/fuzz, and CLI regressions pass. |
| GAP-013 | Header rewriting, ordered bounded rules, checked TCP/UDP/ICMPv6 checksums, VLAN replacement, and atomic PCAPNG output; core, CLI, metadata, and schema regressions pass. |
| GAP-008 | `export` plans whole streams, derived-field matches, and complete/incomplete datagram source groups before atomic source-record copying; dependency, limits, compression, and CLI/schema regressions pass. |
| GAP-006 | Registered HTTP/1 headers and sourced stream messages, pipelining/HEAD, chunks/trailers, clean close and upgrade boundaries; core and CLI framing regressions and output contract checks pass. |
| GAP-004, GAP-005 | Offline `dns-read` frames TCP messages and correlates scoped UDP/TCP transactions with physical sources, retries, duplicates, and signed latency evidence; core and CLI regressions and machine-contract checks pass. |
| GAP-003 | Bounded IPv4/IPv6 fragment transforms and CLI; reverse-order reassembly and resource/DF regressions pass. |
| GAP-009, GAP-010 | Ordered merge with interface provenance and gzip/Zstd adapters; merge, compression, corruption, capacity, and CLI regressions pass. |
| GAP-014, GAP-015 | Per-frame interface selection and finite repetition share replay budgets; mapped/repeated replay regressions pass. |
| GAP-016, GAP-017 | Portable TCP connect scanning and bounded host/CIDR selections; loopback, resource cleanup, deduplication, exclusion, and preflight regressions pass. |
| GAP-020 | Field projection with JSON/NDJSON/CSV/TSV, missing/repeated values, stream indexes, and output limits; CLI regressions pass. |
| GAP-018 | Rolling raw scan windows share ready capture sources, pacing, policy, preparation/evidence budgets, deadlines, and cleanup; [pipeline contracts](crates/packetcraftr/tests/scan_pipeline_contracts.rs) cover overlap/refill, pacing, preflight, pending-wire failures, ingress checks, and bounded timeout waves. |
| GAP-019 | Validated per-port DNS/byte profiles retain arbitrary payload fallback and report application checks separately from reachability; [workflow contracts](crates/packetcraftr/tests/udp_profile_contracts.rs) and [CLI regressions](crates/packetcraftr-cli/tests/udp_profiles.rs) cover nonce/question checks, masks, explicit bindings, reverse-flow matching, and preflight. |

Packet recipes use `packetcraftr.packet/v2` and machine output uses
`packetcraftr.output/v5`; schemas, examples, release assets, and
[migration notes](docs/migration-unreleased.md) migrate together. Rewrite and UDP
profile documents have independent v1 schemas. The agreed exclusions remain:
no live TLS engine, HTTP/2 or HTTP/3 engine, DHCP server, service fingerprint
database, unbounded live work, or throughput parity claim. Merge requires
chronological inputs; fragment-dependent header rewrites fail explicitly.

### Validation

Validated this working tree on Linux with pinned Rust **1.98.1**.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` and `git diff --check` | Passed. |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed. |
| `cargo test --locked --workspace --all-features` | 1,170 passed, 0 failed; the 5 deliberately ignored native cases passed in the isolated suite below. |
| `cargo test --locked --workspace --no-default-features` | 1,118 passed, 0 failed. |
| `cargo test --locked -p packetcraftr-cli -p packetcraftr-netio --no-default-features --features packetcraftr-cli/native-layer3,packetcraftr-netio/native-layer3` | 353 passed, 0 failed. |
| `RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps` with portable, pcap-free, and all features | All three profiles passed. |
| `cargo deny --locked check` and `cargo deny --locked --manifest-path fuzz/Cargo.toml check advisories` | Passed. Zstd's exact-version BSD notices are bundled in release assets. |
| `cargo check --locked --manifest-path fuzz/Cargo.toml --all-targets` | Passed. |
| `python3 scripts/check-architecture.py` and `python3 scripts/test-validation-evidence.py` | Dependency direction passed; 18 validation-evidence tests passed. |
| `scripts/test-verify-archive.py` with real all-features and pcap-free binaries | 7 tests passed for each variant, including extracted-archive smoke. Pcap-free `ldd` has no libpcap dependency. |
| `scripts/test-native-isolated.py` with the full-native binary and prebuilt native test executable | All 6 scenarios passed in a fresh user/network namespace: loopback exchange, readiness/cleanup, cancellation/deadlines, queue loss, filter errors, and interface disappearance. |
| `scripts/check-decode-oracle.py --full` with TShark 4.6.4 | All 14 captures passed with zero field mismatches; TLS JA3 matched. |

Native runtime evidence covers Linux. Privileged macOS/Windows runtime lanes
were not exercised locally. Regression coverage and the decoder comparison do
not imply performance parity or support outside the documented protocol bounds.

## Original capability map

| Domain and owner | Implemented baseline and evidence | Remaining findings |
| --- | --- | --- |
| Packet mechanics — core | Reflective typed layers, mutable packet stacks, strict/permissive construction, exact/derived wire values, runtime codec/binding extensions, JSON/YAML recipes, Cartesian field axes. See [protocol catalog](crates/packetcraftr-core/src/protocol/catalog.rs), [Packet](crates/packetcraftr-core/src/packet/mod.rs), [Template](crates/packetcraftr-core/src/template.rs), [runtime registry contracts](crates/packetcraftr-core/tests/runtime_registry_contracts.rs), and [packet-set CLI tests](crates/packetcraftr-cli/tests/packet_sets.rs). | GAP-001–003 |
| Decode and application analysis — core | Ethernet/VLAN and cooked/loopback roots; IPv4/IPv6, extension headers, ICMP, TCP/UDP/SCTP and several tunnels. DNS records/EDNS retain unknown RDATA. TLS hellos, alerts, SNI, ALPN and JA3/JA3S/JA4 have bounded TCP session assembly. [DNS regression](crates/packetcraftr-core/tests/dns_record_contracts.rs), [TLS collector](crates/packetcraftr-core/src/analysis/tls/mod.rs). | GAP-004–007 |
| Capture files and offline analysis — core/CLI | Streaming PCAP/PCAPNG, source-record preservation, filtered export, normalized PCAPNG, redirected stdin, scoped conversations, IP/TCP reassembly, follow, expert findings, endpoint/port/protocol/I/O statistics. Filters already support sets, CIDRs, slices, repeated layers and stream indices in analysis commands. [Analysis API](crates/packetcraftr-core/src/analysis/mod.rs), [filters](crates/packetcraftr-core/src/filter/mod.rs), [normalization tests](crates/packetcraftr-cli/tests/normalized_capture_contracts.rs). | GAP-008–010, 020 |
| Native resources and capture — netio/CLI | Provider injection; Linux/macOS/Windows dispatch; passive routes/interfaces; ARP/NDP resolution; raw L3 and pcap/Npcap L2; capture readiness, native BPF, bounded queues, loss reporting and cancellation. [Capture contracts](crates/packetcraftr-netio/src/capture.rs), [platform dispatch](crates/packetcraftr-netio/src/platform/dispatch.rs), [isolated native tests](crates/packetcraftr-netio/tests/native_isolated.rs). | GAP-011–012 |
| Live workflows — workflow crate/CLI | Policy admission and final-wire validation, finite budgets, send/exchange, replay with original/scaled/immediate/pps/bps timing, TCP SYN/UDP/ICMP scanning, traceroute, UDP/TCP DNS with retries and truncation fallback. Scan supports an explicit UDP payload. [Workflow API](crates/packetcraftr/src/lib.rs), [replay tests](crates/packetcraftr/src/replay/tests.rs), [scan tests](crates/packetcraftr/src/scan/tests.rs), [DNS TCP tests](crates/packetcraftr/tests/dns_tcp_contracts.rs). | GAP-013–019 |
| Fuzzing and automation — core/workflow/CLI | Deterministic boundary/random/bit-flip/malformed mutations, field targeting, per-case reproduction, shrink candidates, offline and live outcomes. Versioned output/v4 JSON/NDJSON with event/terminal contracts and release assets. [Fuzz arguments](crates/packetcraftr-cli/src/commands/fuzz/arguments.rs), [case model](crates/packetcraftr-core/src/fuzz/report.rs), [NDJSON contracts](crates/packetcraftr-cli/tests/ndjson_conformance.rs), [published examples](examples/documents). | GAP-020; larger scenario engines remain a scope question |

## Peer comparison

All external sources were accessed on **2026-09-12**. These are documented,
available capabilities, not proposals. Rolling manuals are identified as such;
no claim depends on an unreleased peer branch.

| Peer and baseline | Why this comparison matters | Capabilities used in the comparison |
| --- | --- | --- |
| **Scapy 2.7.0**, stable Python library documentation | Direct overlap in packet construction and protocol experimentation; language differences do not imply PacketcraftR needs a Python shell. | [DNS packet constructors and TCP decoding](https://scapy.readthedocs.io/en/stable/api/scapy.layers.dns.html), [TLS handshake constructors](https://scapy.readthedocs.io/en/stable/api/scapy.layers.tls.handshake.html), [IP fragmentation](https://scapy.readthedocs.io/en/stable/api/scapy.layers.inet.html#scapy.layers.inet.fragment), and [HTTP/1 session decoding](https://scapy.readthedocs.io/en/stable/layers/http.html). |
| **PcapPlusPlus**, current release [v26.07](https://github.com/seladb/PcapPlusPlus/releases/tag/v26.07); versioned **v25.05** documentation used for the specific comparisons | Direct systems-library overlap in parsing, editing and capture I/O. The older versioned page gives a reproducible released baseline for the selected features. | [Feature overview](https://pcapplusplus.github.io/docs/v25.05/features): HTTP headers, DHCP/DHCPv6, editing, reassembly, and optional Zstd PCAPNG I/O. Zstd requires the corresponding build option; backend availability varies by platform. |
| **Wireshark/TShark, dumpcap, mergecap**, current official manuals; DNS field reference through **4.6.8** | Direct overlap with offline analysis and CLI capture processing. GUI features are used only where they reveal an equivalent export workflow. | [TShark](https://www.wireshark.org/docs/man-pages/tshark.html): selected fields and compressed captures; [dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html): rotation and multiple interfaces; [mergecap](https://www.wireshark.org/docs/man-pages/mergecap.html): ordered capture merging; [DNS fields](https://www.wireshark.org/docs/dfref/d/dns.html): transaction evidence. |
| **Tcpreplay suite v4.6.1** [release](https://github.com/appneta/tcpreplay/releases/tag/v4.6.1), rolling official manuals | Specialized direct peer for replaying saved traffic through a lab device. No line-rate performance parity is assumed. | [Header rewriting](https://tcpreplay.appneta.com/guides/rewriting-headers/) and [replay options](https://tcpreplay.appneta.com/reference/man/tcpreplay/): two interfaces and repetition, alongside timing controls PacketcraftR already has. |
| **Nmap**, rolling official Nmap Network Scanning manual | Specialized peer for authorized endpoint diagnostics; its larger security-testing platform is adjacent, not the target scope. | [Connect scans](https://nmap.org/book/man-port-scanning-techniques.html), [target sets](https://nmap.org/book/man-target-specification.html), [bounded parallelism controls](https://nmap.org/book/man-performance.html), and [service probe definitions](https://nmap.org/book/vscan-fileformat.html). |

## Original gap inventory

**20 supported gaps, now closed above.** Confidence describes the assessed capability boundary, not
estimated demand. **P1** means a strong fit that closes a significant existing
workflow; **P2** means a useful extension with narrower reach or dependencies;
**P3** means convenience or a more specialized extension. Priorities are analysis
judgments, not delivery promises. Closure outcomes preserve resource bounds,
capture provenance, original bytes where promised, and authorization before live
effects. Domain ownership follows AGENTS.md.

### Packet construction

#### GAP-001 — Author and edit structured DNS messages

**Partial capability · High confidence · P1 · Owner: core, exposed through CLI.**
Protocol authors can inspect DNS records and issue normal live queries, but cannot
use packet recipes to construct responses, arbitrary question/record sets, or
field-based DNS fuzz cases. The catalog marks DNS non-constructible;
`DnsCodec::make_layer` refuses construction and `validate_wire_consistency`
rejects edits that disagree with retained bytes. The live `encode_query` path is
a narrower workaround, as is supplying externally encoded raw bytes.

Evidence: [DNS codec](crates/packetcraftr-core/src/protocol/application/dns.rs),
[query encoder](crates/packetcraftr/src/dns/wire/encode.rs), and
[DNS record tests](crates/packetcraftr-core/tests/dns_record_contracts.rs), including
exact round trips and rejection of changed names. Scapy exposes structured
[DNS/DNSQR/DNSRR constructors](https://scapy.readthedocs.io/en/stable/api/scapy.layers.dns.html).
**Closes when:** bounded recipes and Rust APIs can author and modify DNS questions
and records, derive wire lengths/counts, and retain explicit malformed/unknown
data semantics. This directly extends an existing supported protocol.

#### GAP-002 — Construct TLS hello fixtures from fields

**Partial capability · High confidence · P2 · Owner: core, exposed through CLI.**
Users testing hello parsers and fingerprints must hand-encode TLS wire fixtures;
the typed hello models serve inspection rather than recipe construction.
`TlsCodec::make_layer` rejects construction, and the catalog marks TLS
non-constructible. Existing wire can still be decoded and re-encoded exactly.

Evidence: [TLS codec](crates/packetcraftr-core/src/protocol/application/tls/codec.rs),
[hello models](crates/packetcraftr-core/src/protocol/application/tls/model.rs),
[fixture builders](crates/packetcraftr-core/tests/common/tls_vectors.rs), and
[Scapy TLS hello constructors](https://scapy.readthedocs.io/en/stable/api/scapy.layers.tls.handshake.html).
**Closes when:** users can build bounded ClientHello/ServerHello records and vary
their supported fields through the normal construction/template/fuzz interfaces.
Priority reflects the strong fit with existing TLS analysis but a narrower user
task than DNS authoring. A live TLS stack or cryptographic handshake engine is not
required for this outcome.

#### GAP-003 — Explicitly fragment a complete IP packet

**Partial capability · High confidence · P1 · Owner: core; live validation in workflows.**
Fragment headers and offline reassembly exist, but users must manually split
payloads and calculate fragment offsets to create an MTU-sized packet sequence.
`validate_mtu` rejects oversized packets; `PacketExceedsMtu` even suggests an
explicit fragmentation transform, but no such public transform is exposed in
the packet/build/template APIs. Test helpers manually author fragments.

Evidence: [MTU validation](crates/packetcraftr/src/mtu.rs),
[MTU error](crates/packetcraftr/src/error.rs),
[core public modules](crates/packetcraftr-core/src/lib.rs),
[fragment fixtures](crates/packetcraftr-core/tests/common/ip_fragments.rs), and
[Scapy `fragment`](https://scapy.readthedocs.io/en/stable/api/scapy.layers.inet.html#scapy.layers.inet.fragment).
**Closes when:** an explicit, bounded transformation turns a supported IPv4 or
IPv6 datagram into valid fragments with documented extension/option handling,
preserved transport payload, and checkable reassembly. Live sending must validate
every resulting packet. This reduces manual wire arithmetic in an existing test
workflow; it does not call for implicit fragmentation during send.

### Application inspection and diagnosis

#### GAP-004 — Decode DNS messages from captured TCP streams

**Partial capability · High confidence · P1 · Owner: core analysis and CLI.**
The live DNS workflow supports TCP, but a saved capture of that traffic does not
receive equivalent DNS decoding. Built-in DNS binds only below UDP. The core
codec describes a terminal UDP payload; TCP decode-as supports TLS/raw, and
`follow` exports transport bytes without DNS message framing.

Evidence: [transport bindings](crates/packetcraftr-core/src/protocol/builtin/registry/registration.rs),
[DNS codec](crates/packetcraftr-core/src/protocol/application/dns.rs),
[decode-as contracts](crates/packetcraftr-cli/tests/decode_as.rs), and
[follow](crates/packetcraftr-core/src/analysis/follow.rs). Scapy's
[DNS decoder](https://scapy.readthedocs.io/en/stable/api/scapy.layers.dns.html)
handles DNS-over-TCP framing.
**Closes when:** bounded offline TCP reassembly yields length-prefixed DNS
messages, including split prefixes/bodies and multiple messages in one delivery,
with records, physical-frame provenance, and explicit incomplete-message results.
Existing reassembly and the shared record decoder provide the prerequisites.

#### GAP-005 — Report offline DNS transactions and response latency

**Missing collector · High confidence · P2 · Owner: core analysis and CLI.**
Operators can read individual DNS messages and transport conversation totals,
but cannot directly obtain query-to-response links, DNS response latency, or
unanswered/retransmitted query summaries from a capture. The live query report
has attempt evidence; it does not analyze independently captured transactions.

Evidence: [analysis entry points](crates/packetcraftr-core/src/analysis/mod.rs),
[statistics report](crates/packetcraftr-core/src/analysis/stats/report.rs),
[DNS layer](crates/packetcraftr-core/src/protocol/application/dns.rs), and
[live DNS report](crates/packetcraftr/src/dns/report.rs). Wireshark documents
[`dns.response_in`, `dns.response_to`, `dns.response_missing`, and `dns.time`](https://www.wireshark.org/docs/dfref/d/dns.html).
**Closes when:** a bounded capture analyzer correlates questions and responses
within capture scope, handles ID reuse/retries, and reports latency or missing
evidence without treating capture loss as proof of server failure. UDP is useful
independently; full TCP coverage depends on GAP-004.

#### GAP-006 — Inspect HTTP/1 messages over reassembled TCP

**Missing built-in capability · High confidence · P2 · Owner: core analysis and CLI.**
Web-protocol diagnostics currently stop at raw TCP payload or TLS hello metadata.
There is no built-in HTTP codec or stream message collector to expose request
methods, targets, headers, response status, and message boundaries. Rust callers
can add custom codecs; this is a built-in workflow gap, not missing extensibility.

Evidence: [complete protocol catalog](crates/packetcraftr-core/src/protocol/catalog.rs),
[application modules](crates/packetcraftr-core/src/protocol/application/mod.rs),
[analysis API](crates/packetcraftr-core/src/analysis/mod.rs), and
[follow interface](crates/packetcraftr-cli/src/commands/follow/arguments.rs).
Scapy documents [HTTP/1 decoding with TCP sessions](https://scapy.readthedocs.io/en/stable/layers/http.html);
PcapPlusPlus lists [HTTP request/response headers](https://pcapplusplus.github.io/docs/v25.05/features#supported-network-protocols).
**Closes when:** cleartext HTTP/1 messages receive bounded framing and typed
metadata across segment boundaries, with truncation/ambiguity reported. Existing
TCP reassembly is a prerequisite; HTTPS decryption and HTTP/2/3 are separate
scope decisions. Priority reflects a common diagnostic task but new protocol scope.

#### GAP-007 — Decode and construct DHCPv4/DHCPv6 packets

**Missing built-in capability · High confidence · P2 · Owner: core and CLI.**
Lease-negotiation troubleshooting requires interpreting raw UDP payloads;
PacketcraftR cannot expose message types, transaction identities, assigned
addresses, or DHCP options as typed fields. Neither protocol appears in the
authoritative catalog or UDP registrations, and the codec matrix derives its
coverage from that catalog. Raw bytes and downstream custom codecs remain possible.

Evidence: [catalog](crates/packetcraftr-core/src/protocol/catalog.rs),
[bindings](crates/packetcraftr-core/src/protocol/builtin/registry/registration.rs),
[codec matrix](crates/packetcraftr-core/tests/protocol_codec_matrix.rs), and
[PcapPlusPlus DHCP/DHCPv6 support](https://pcapplusplus.github.io/docs/v25.05/features#supported-network-protocols).
**Closes when:** both lease-protocol families have bounded typed decoding and
fixture construction, retaining unknown options and malformed bytes. This is
one address-configuration workflow, with family coverage tracked explicitly;
running a DHCP server or enabling active discovery is not required.

### Capture selection, storage, and acquisition

#### GAP-008 — Export a conversation with its required physical packets

**Partial capability · High confidence · P1 · Owner: core analysis and CLI.**
After identifying a stream or fragmented transaction, users cannot directly save
a self-contained capture of it. `read` compiles filters with `frames_only`, so
stream selectors fail. `select` copies matching physical records and explicitly
does not include related fragments; normalization has the same physical-frame
semantics. `follow` emits payload chunks, not a replacement capture.

Evidence: [`prepare_decoding`](crates/packetcraftr-cli/src/commands/read/mod.rs),
[`select`](crates/packetcraftr-core/src/analysis/pcap/rewrite.rs), and
[`normalization_filters_physical_frames_without_reassembly`](crates/packetcraftr-cli/tests/normalized_capture_contracts.rs).
Wireshark combines [stream selection](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
with [export of displayed packets](https://www.wireshark.org/docs/wsug_html_chunked/ChIOPacketRangeSection.html).
Including contributing fragments is also motivated by PacketcraftR's own
reassembly workflow; the cited peer pages establish stream-filtered export,
not automatic fragment-dependency inclusion.
**Closes when:** users can export a scoped TCP/UDP conversation or matched
reassembled datagram with its contributing physical records, preserving original
bytes/times and making any unavailable dependencies explicit. This bridges two
existing workflows and does not replace faithful frame-by-frame export.

#### GAP-009 — Merge captures while preserving interface identity

**Missing workflow · High confidence · P2 · Owner: core capture I/O and CLI.**
Comparing captures taken at different points in a lab requires an external merge
step. Each capture command opens one source. Reading multiple PCAPNG sections and
normalizing their interfaces is supported. Concatenated PCAPNG sections can
already represent sequential inputs, but no supplied API/command merges
independent capture streams by timestamp.

Evidence: [capture reader](crates/packetcraftr-core/src/analysis/pcap/reader.rs),
[read arguments](crates/packetcraftr-cli/src/commands/read/arguments.rs),
[normalization tests](crates/packetcraftr-cli/tests/normalized_capture_contracts.rs),
and [command catalog](crates/packetcraftr-cli/src/commands/mod.rs).
[Mergecap](https://www.wireshark.org/docs/man-pages/mergecap.html) supplies ordered
merging and PCAPNG interface handling.
**Closes when:** bounded multi-file merging has deterministic time ordering,
distinct source/interface provenance, and explicit handling of missing or
incompatible timestamps and input ordering assumptions. Existing multi-section
support is a foundation for the output.
Clock correction is a separate possible extension, not implicit in this gap.

#### GAP-010 — Open and write compressed captures directly

**Integration limitation · High confidence · P3 · Owner: core adapters and CLI.**
Users sharing compressed captures need external decompression/compression.
`open_capture` passes a file/stdin directly to the reader, whose format switch
recognizes PCAP/PCAPNG magic only. Core accepts generic `Read`/`Write`, so custom
compression adapters and shell pipelines are viable workarounds; offline stdin
support is already present. Replay remains file-based.

Evidence: [CLI capture opening](crates/packetcraftr-cli/src/input.rs),
[reader format detection](crates/packetcraftr-core/src/analysis/pcap/reader.rs),
[writer](crates/packetcraftr-core/src/analysis/pcap/writer.rs), and
[stdin contracts](crates/packetcraftr-cli/tests/capture_stdin_contracts.rs).
[TShark](https://www.wireshark.org/docs/man-pages/tshark.html) detects compressed
input; [PcapPlusPlus](https://pcapplusplus.github.io/docs/v25.05/features#readingwriting-pcapng-files-with-compression)
supports optional Zstd PCAPNG I/O.
**Closes when:** documented compression formats work directly with capture paths
and outputs, with decompressed-byte/resource ceilings and typed corruption errors.
Priority is lower because current composition already completes the underlying task.

#### GAP-011 — Rotate capture output within a finite retention budget

**Missing CLI workflow · High confidence · P2 · Owner: CLI capture orchestration.**
During a longer bounded diagnostic run, users cannot split output at time/size
thresholds or retain a configured number of complete capture files. Capture has
finite operation/queue limits but initializes one writer on stdout. Restarting
the command changes capture lifecycle; splitting raw stdout arbitrarily does not
produce independently valid PCAP/PCAPNG files.

Evidence: [capture arguments](crates/packetcraftr-cli/src/commands/capture/arguments.rs),
[`initialize_writer`](crates/packetcraftr-cli/src/commands/capture/rendering.rs),
[capture execution at assessment](https://github.com/tyk-swe/pcr/blob/e5e2bf0b8849b79ebf72c3ef50848f0bd406f79d/crates/packetcraftr-cli/src/commands/capture/execution.rs), and
[dumpcap rotation options](https://www.wireshark.org/docs/man-pages/dumpcap.html).
**Closes when:** one bounded capture session can produce valid rotated files with
explicit size/time/file-count limits, named retention behavior, and final loss
and completion evidence. This extends storage control without removing finite
operation budgets or silently overwriting unrelated files.

#### GAP-012 — Capture multiple selected interfaces in one operation

**Composition limitation · High confidence · P2 · Owner: CLI/workflows over netio.**
Capturing both sides of a router, tunnel, or virtual switch currently requires
separate invocations or a custom Rust orchestrator. CLI `interface` is a single
string, execution owns one session, and the output writer starts from one
interface's metadata. Netio can be composed and PCAPNG supports multiple interfaces;
the missing part is a coordinated user workflow.

Evidence: [capture arguments](crates/packetcraftr-cli/src/commands/capture/arguments.rs),
[session execution at assessment](https://github.com/tyk-swe/pcr/blob/e5e2bf0b8849b79ebf72c3ef50848f0bd406f79d/crates/packetcraftr-cli/src/commands/capture/execution.rs),
[netio session/provider contracts](crates/packetcraftr-netio/src/capture.rs), and
[dumpcap repeated `-i`](https://www.wireshark.org/docs/man-pages/dumpcap.html).
**Closes when:** one operation captures an explicit interface set into scoped
PCAPNG with shared finite budgets, readiness/cleanup handling, and per-interface
loss evidence. A backend-provided Linux aggregate device, if usable, would not
by itself supply these selected-interface semantics. GAP-009 is useful for
existing separate captures but is not a prerequisite.

### Capture adaptation and replay

#### GAP-013 — Rewrite capture headers for a different lab topology

**Missing CLI workflow · High confidence · P1 · Owner: core transforms, CLI composition.**
Replaying saved traffic at new MAC/IP addresses or ports requires custom code or
another tool. Core can edit packet layers and rebuild checksums, but capture
`rewrite` means source-record copying. Normalization preserves packet bytes;
replay authorizes and submits the captured frame rather than providing field
mapping, VLAN editing, or checksum-repair controls.

Evidence: [mutable Packet API](crates/packetcraftr-core/src/packet/mod.rs),
[capture rewrite](crates/packetcraftr-core/src/analysis/pcap/rewrite.rs),
[replay engine](crates/packetcraftr/src/replay/engine.rs), and
[replay arguments](crates/packetcraftr-cli/src/commands/replay/arguments.rs).
[Tcprewrite](https://tcpreplay.appneta.com/guides/rewriting-headers/) provides
address/port/MAC/VLAN edits and checksum repair.
**Closes when:** users can explicitly transform supported headers in a capture,
inspect/save the resulting bytes, and replay them under final-endpoint and
final-wire authorization. Unsupported edits, fragments, and metadata effects
must be explicit. This is capture adaptation, not a claim that all packet
editing is absent or that rewritten captures are anonymized.

#### GAP-014 — Map replay traffic to different output interfaces

**Missing workflow · High confidence · P2 · Owner: replay workflow and CLI.**
Bidirectional testing of an inline device cannot assign captured client/server
traffic or source interfaces to different transmit interfaces in one replay.
`replay::Options` holds one interface, and CLI help says it is used for every
transmission. Source interface IDs are retained in evidence but are not an output
mapping. Separate runs do not share ordering or timing.

Evidence: [replay options/evidence](crates/packetcraftr/src/replay/model.rs),
[route selection in replay](crates/packetcraftr/src/replay/engine.rs), and
[CLI arguments](crates/packetcraftr-cli/src/commands/replay/arguments.rs).
[Tcpreplay](https://tcpreplay.appneta.com/reference/man/tcpreplay/) supports
`--intf2` with traffic classification or paired input files.
**Closes when:** an explicit, validated mapping selects each frame's transmit
interface under one schedule and budget, with authorization for every selected
endpoint/interface. GAP-013 is often useful alongside this, but interface mapping
is independently useful with already-correct bytes.

#### GAP-015 — Repeat a capture under one replay budget

**Missing convenience workflow · High confidence · P3 · Owner: replay workflow and CLI.**
Users running repeatability tests must reopen/reinvoke replay for each pass.
The reader is consumed once to EOF; options have timing and limits but no repeat
count or inter-pass delay. Shell loops work but reset per-operation accounting
and require external aggregation.

Evidence: [replay loop](crates/packetcraftr/src/replay/engine.rs),
[options](crates/packetcraftr/src/replay/model.rs),
[arguments](crates/packetcraftr-cli/src/commands/replay/arguments.rs), and
[Tcpreplay loop controls](https://tcpreplay.appneta.com/reference/man/tcpreplay/).
**Closes when:** a finite repeat count and optional inter-pass delay share one
packet/byte/time budget, preserve source position plus pass identity, and stop
cleanly on cancellation or error. Existing timing modes remain sufficient;
unbounded looping is not required.

### Authorized endpoint diagnostics

#### GAP-016 — TCP connect scanning without raw capture privileges

**Missing scan mode · High confidence · P1 · Owner: workflows/CLI over netio TCP.**
Users with ordinary socket access can run direct TCP DNS, but cannot use `scan`
to test TCP port reachability without the capture/raw packet backend. Its TCP
strategy is SYN probing; the transport enum exposes TCP/UDP/ICMP, not an
OS-managed connection mode.

Evidence: [scan arguments](crates/packetcraftr-cli/src/commands/scan/arguments.rs),
[probe construction](crates/packetcraftr/src/scan/probe.rs),
[scan executor](crates/packetcraftr/src/scan/executor.rs), and
[ordinary TCP provider](crates/packetcraftr-netio/src/tcp.rs).
[Nmap connect scan](https://nmap.org/book/man-port-scanning-techniques.html)
provides the corresponding unprivileged workflow.
**Closes when:** explicitly selected connect probes work in the portable profile
with destination authorization, finite connection/deadline budgets, and accurate
socket outcome evidence. The output must distinguish socket operations from
captured/raw packets, as direct TCP DNS already does.

#### GAP-017 — Scan an explicit bounded set of hosts or networks

**Partial capability · High confidence · P2 · Owner: workflow target selection and CLI.**
Users testing a small authorized fleet must orchestrate one invocation per
declared target. A hostname can resolve to multiple addresses, and ports support
lists/ranges, but `Request` holds one `Target`, whose variants are one IP address
or hostname. There is no host-list/CIDR selection with shared deduplication,
exclusions, limits, and results. Filter CIDRs and packet axes do not provide this
scan request model.

Evidence: [target parsing](crates/packetcraftr/src/target/model.rs),
[scan request](crates/packetcraftr/src/scan/request.rs),
[scan CLI](crates/packetcraftr-cli/src/commands/scan/arguments.rs), and
[Nmap target specifications](https://nmap.org/book/man-target-specification.html).
**Closes when:** explicit host sets and bounded CIDR expansion can be validated,
deduplicated, excluded, and authorized under one aggregate operation budget.
This does not require broad automatic discovery. It is independently useful
with serial execution; GAP-018 improves its running time.

#### GAP-018 — Keep a bounded number of scan probes in flight

**Missing scheduling capability · High confidence · P1 · Owner: scan workflow.**
Multi-port scans wait for each probe's response window before advancing, so a
higher rate setting cannot remove cumulative timeout cost. `build_batches`
generates one probe per batch and `worst_case_duration` sums every timeout plus
pacing delay. CLI help and the deterministic scan regression explicitly confirm
serial behavior; this is not an inferred throughput measurement.

Evidence: [scan planner](crates/packetcraftr/src/scan/plan.rs),
[batch runner](crates/packetcraftr/src/probe/runner.rs),
[`scan_single_probe_attempts_rate_and_timeout_evidence_are_deterministic`](crates/packetcraftr/src/scan/tests.rs),
and [Nmap parallelism controls](https://nmap.org/book/man-performance.html).
**Closes when:** a configured finite in-flight limit overlaps response windows
while preserving probe correlation, capture readiness, shared policy/resource
budgets, deadlines, cancellation, and deterministic evidence identity. This is
useful on one host without GAP-017. No particular throughput target is assumed.

#### GAP-019 — Select UDP payloads and response checks per service

**Partial capability · High confidence · P2 · Owner: scan workflow and CLI.**
A single UDP scan can carry exact user bytes, but those same bytes are cloned
for every selected port. Transport/ICMP correlation does not establish that a
response satisfies a particular application request. Testing several unlike UDP
services therefore requires separate invocations and manual protocol checks.

Evidence: [scan request](crates/packetcraftr/src/scan/request.rs),
[`build_batches`](crates/packetcraftr/src/scan/plan.rs),
[classification](crates/packetcraftr/src/scan/classification.rs),
[payload regressions](crates/packetcraftr-cli/tests/scan_payloads.rs), and
[README payload contract](README.md). Nmap's
[service-probe format](https://nmap.org/book/vscan-fileformat.html) associates
TCP/UDP payloads with ports and response matches.
**Closes when:** users can supply bounded per-port/service payload selection
with protocol-appropriate response validation and distinguish transport reachability
from application confirmation. The existing arbitrary-payload path must remain
usable. A comprehensive version fingerprint database is a separate scope choice.

### CLI data extraction

#### GAP-020 — Select output fields without emitting full packet records

**Integration limitation · High confidence · P2 · Owner: CLI output over core reflection.**
Users building small reports need full dissection records plus a downstream
processor to extract a few fields. `dissect`/`read` expose filters and full
representations, but no repeatable field projection or delimited table output.
The current versioned JSON/NDJSON contract is already suitable for automation;
the gap is a concise extraction interface, not missing machine output.

Evidence: [dissect arguments](crates/packetcraftr-cli/src/commands/dissect/arguments.rs),
[read arguments](crates/packetcraftr-cli/src/commands/read/arguments.rs),
[output contract](crates/packetcraftr-cli/src/output/contract.rs), and
[reflective field resolution](crates/packetcraftr-core/src/filter/path.rs).
[TShark `-T fields -e ... -E ...`](https://www.wireshark.org/docs/man-pages/tshark.html)
provides selectable fields and table formatting.
**Closes when:** users can select registered fields with documented ordering,
missing-value and repeated-layer semantics, and safe machine-readable rows.
Existing schemas/examples must remain synchronized if the output contract changes.
This builds on reflection and improves common reports, while JSON plus `jq`
remains a practical workaround.

## Open questions, intentional boundaries, and exclusions

- **QUIC and broader TLS inspection:** QUIC handshake decoding is explicitly
  outside the [current TCP TLS collector](crates/packetcraftr-core/src/analysis/tls/mod.rs).
  It counts UDP/443 frames as possible QUIC, not confirmed decoded sessions.
  The collector closes at ServerHello; other handshake messages are untyped in
  [the model](crates/packetcraftr-core/src/protocol/application/tls/model.rs).
  [Wireshark QUIC fields](https://www.wireshark.org/docs/dfref/q/quic.html) and
  [Scapy certificate messages](https://scapy.readthedocs.io/en/stable/api/scapy.layers.tls.handshake.html)
  show adjacent opportunities, but QUIC, certificate analysis and key-log-based
  decryption need an explicit product-scope decision. They are not counted as
  defects in the existing hello analyzer. GAP-002 only concerns fixture authoring.
- **Stateful protocol scenarios and fuzz minimization:** deterministic mutations,
  live exchanges, case replay and shrink values exist. A server/client scenario
  engine, crash oracle, or automated failure-preserving minimizer would be a
  larger testing-framework commitment. No demand or approved scope was found;
  supplied shrink candidates must not be described as automatic crash minimization.
- **Custom protocols in the stock CLI:** runtime Rust registries and custom
  codecs are implemented and tested. Offline decode-as changes bindings among
  compatible built-ins. A dynamically loaded CLI extension format may be useful,
  but the need for one versus a custom Rust binary is unresolved; “no plugin
  support” would be an inaccurate blanket claim.
- **Distribution:** workspace `publish = false` means the assessed crates are
  not configured for registry publication. Git/path use and packaged CLI releases
  are available. Whether crates.io publication is intended needs maintainer
  direction; it is not assumed to be an accidental omission.
- **Native/platform uncertainty:** this pass did not exercise native backends.
  [CONTRIBUTING](CONTRIBUTING.md) explicitly records unexercised privileged
  Windows/macOS lanes. The documented macOS complete-header raw IPv6 restriction
  and feature/privilege prerequisites are platform limitations, not missing
  cross-platform architecture. No performance or loss-rate comparison is claimed.
- **Intentional architecture and safety boundaries:** core remains independent
  of native I/O, live operations require authorization, and workflows use finite
  budgets. Missing bypasses, hidden active resolution, unlimited capture/scan
  modes, or unrestricted packet transmission are not gaps.
- **Scope not assessed for parity:** exhaustive industrial/routing/wireless
  protocol catalogs, monitor-mode Wi-Fi, encrypted DNS transports/DNSSEC
  validation, HTTP/2/3, object export, Nmap vulnerability scripts/OS fingerprinting,
  GUI editing, remote agents, and line-rate DPDK/AF_XDP/PF_RING appliances.
  DHCP and cleartext HTTP/1 were selected for concrete address-configuration and
  application-diagnostic workflows, not to imply every peer protocol is required.
  Regex filters are explicitly absent but existing sets/CIDRs/contains/slices cover
  substantial filtering; no separate regex requirement was established.
- **Evidence limits:** local support was assessed from source, public interfaces,
  examples and test assertions. No new fixtures or binaries were built, peer
  software was not executed, and private plans were unavailable. Rolling external
  pages and the public issue/PR state can change after this assessment.

## Review and prioritization notes

The strongest next opportunities are GAP-001, GAP-003, GAP-004, GAP-008,
GAP-013, GAP-016 and GAP-018: each makes an existing construction, capture, replay
or diagnostic workflow substantially more useful. GAP-004 enables the TCP portion
of GAP-005; GAP-017 and GAP-018 are independently useful; capture merging,
multi-interface acquisition, output mapping and header rewriting have distinct
inputs and observable outcomes rather than being duplicate “multi-interface” gaps.

The inventory was reviewed against alternative APIs and recent changes. Packet
sets, decode-as, DNS TCP/fallback, EDNS, arbitrary DNS type codes, decoded DNS
records, UDP scan payloads, replay bps, filter sets/CIDRs, IP/TCP reassembly,
capture normalization, stdin, mutable packet APIs and custom registries are
present and intentionally not listed as absent. Lower-priority findings retain
their existing composition workarounds. No features were implemented and no
external issues were created by this analysis.
