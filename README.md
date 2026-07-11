# PacketcraftR

[![CI](https://github.com/tyk-swe/pcr/actions/workflows/ci.yml/badge.svg)](https://github.com/tyk-swe/pcr/actions/workflows/ci.yml)

PacketcraftR is a Rust packet-construction, dissection, capture, and network-testing framework with a first-class CLI. The v0.2 line is rebuilding the project around arbitrary layer stacks, reflective fields, an explicit protocol registry, exact wire-byte preservation, and bounded parsers.

> **Prerelease warning:** `0.2.0-alpha.1` remains a prerelease version, but this
> checkout contains the reviewed v0.2 beta-candidate freezes for the public Rust
> API, CLI, packet documents, and output documents. Any incompatible change to
> those contracts is now a release blocker unless the compatibility policy
> explicitly permits it.

PacketcraftR is licensed under the [GNU Affero General Public License v3.0 only](LICENSE) and has a Rust 1.96 minimum supported Rust version (MSRV) throughout the v0.2 series.

## Project status

This checkout contains the portable v0.2 kernel, passive native route providers,
and policy-gated live CLI workflows. The table describes the beta-candidate
contract; privileged qualification remains a separate release gate.

| Area | Beta-candidate status |
| --- | --- |
| Ordered `Packet`, object-safe `Layer`, reflective schemas and field values | Frozen public API and invariant-tested implementation |
| Immutable `ProtocolRegistry`, external codecs and deterministic bindings | Frozen public API and compile-tested external extension path |
| Strict/permissive generic building, layouts, and diagnostics | Stable built-in protocol matrix implemented and invariant-tested; beta Rust API candidate is frozen and diff-checked |
| Bounded dissection with raw/malformed preservation | All declared codecs and capture roots covered by the stable matrix and authoritative corpus |
| Runtime-neutral captured-frame records and offline capture I/O | Bounded streaming read/write and metadata-preserving PCAP/PCAPNG copy are available through the API and `read` |
| Packet expressions and `packetcraftr.packet/v1` documents | Frozen mapping with bounded JSON/YAML parsing and schema gates |
| Complete v0.2 command set: `build`, `dissect`, `plan`, `send`, `exchange`, `capture`, `read`, `replay`, `scan`, `traceroute`, `dns`, `fuzz`, `interfaces`, and `routes` | Frozen CLI grammar, exit classes, and output contracts |
| Routing, neighbor discovery, live send/capture, and exchange | Injectable APIs and CLI composition are available with passive Linux/macOS/Windows routes, native Layer 2 I/O, bounded gateway-aware ARP/NDP, raw Layer 3 adapters, finite traffic/capture budgets, and typed capability failures |
| Reassembly, templates, scans, traceroute, DNS, and fuzzing | Bounded fragment/TCP stages, templates, structured scan/traceroute/DNS, and deterministic field-aware fuzzing are available |
| Built-in protocol catalog and extracted component crates | Stable codec/root catalog complete; core, protocols, I/O, and session packages are extracted behind unchanged façade paths |

Run `packetcraftr --help` for the complete frozen command grammar and finite
defaults; CI compares that text with the reviewed beta-candidate golden.

The exact v0.2 packet-layer promise is published in the
[stable built-in protocol matrix](docs/protocol-support.md) and through the
serializable `BUILTIN_PROTOCOL_SUPPORT` Rust manifest
(`packetcraftr.protocol-support/v1`). It covers all 22 codecs, nine registered
capture roots, four response matchers, and every stable CLI workflow.

## Design overview

A `Packet` is exactly one ordered wire stack. It contains layers and their fields, but no interface, route, listener, retry, logging, or transmission settings. Those belong to workflow options or a high-level client.

```text
packet recipe / Rust Packet
            |
            v
     immutable registry
       /           \
      v             v
strict/permissive   bounded
    builder        dissector
      |               |
      v               v
 exact bytes       packet + original bytes
 layouts           layouts
 diagnostics       diagnostics
```

The beta-candidate public façade is centered on:

- `Packet`, `Layer`, `LayerSchema`, `FieldSchema`, and `FieldValue` for typed and reflective editing.
- `WireValue<T>` for dependent values that are automatic, exact, or deliberately raw.
- `RegistryBuilder` and immutable `ProtocolRegistry` values instead of global registration.
- `Builder` and `Dissector`, which return exact bytes, materialized packets, byte layouts, and typed diagnostics.
- `Raw`, `Padding`, and `MalformedLayer`, which retain content that cannot be decoded safely.
- `CapturedFrame`, which retains link type, timestamps, captured/wire lengths, interface metadata, and all bytes up to the snap length. Its fallible constructors reject lengths that cannot represent the supplied bytes, and dissection revalidates records before reading them. Exchange results retain bounded, undecodable frames in this raw form instead of discarding their evidence.

A minimal beta-candidate API shape looks like this:

```rust
use packetcraftr::{Packet, Raw};

let mut packet = Packet::new();
packet.push(Raw::new(vec![0xde, 0xad, 0xbe, 0xef]));

assert_eq!(packet.len(), 1);
assert_eq!(packet.get::<Raw>().unwrap().bytes.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
```

External Rust crates can implement `Layer`, `LayerCodec`, and `ProtocolModule`, then register the module through a `RegistryBuilder`. Registration is compile-time Rust composition: v0.2 deliberately has no native dynamic-library plugin system and no global mutable registry.

Native and injected networking providers implement platform-neutral contracts owned by `packetcraftr::io`: interface and route discovery, neighbor resolution, typed Layer 2/Layer 3 send, and owned capture. The root reexports those contracts; the alpha-only `packetcraftr::client::*` provider aliases were removed at the beta freeze. Checked `Layer2Frame` and `Layer3Frame` values keep Ethernet bytes away from raw Layer 3 adapters and vice versa. Native handles never enter the public traits. The complete [stable Rust API contract](docs/public-api.md) records ownership, bounds, errors, completeness, extension examples, and compatibility review.

The repository is an acyclic Cargo workspace with synchronized, unpublished
`packetcraftr-core`, `packetcraftr-protocols`, `packetcraftr-io`, and
`packetcraftr-session` implementation packages. Ordinary applications should
continue to import `packetcraftr`; its `core`, `protocols`, `io`, and `session`
modules and intentional top-level reexports preserve the documented façade.
Client policy, reusable tools, output contracts, and CLI composition remain
façade-owned so no component depends back on the root package. Release
artifacts are assembled as one buildable GitHub workspace archive, and every
package has `publish = false` to prevent accidental registry publication.

The architecture decisions are recorded in [docs/adr](docs/adr/README.md).

## Building from source

The `0.2.0-alpha.1` Cargo version in this checkout is an unpublished development
baseline: the repository currently has no corresponding tag or GitHub Release.
PacketcraftR packages are not published to a public registry. Install an exact
reviewed checkout locally, or use only assets and checksums attached to the
[GitHub Releases page](https://github.com/tyk-swe/pcr/releases) once a Release is
published. The complete source/archive, checksum, local-install, and versioned
API-reference procedure is in the
[installation and Release guide](docs/install-and-release.md).

Install Rust 1.96 through `rustup`, then build the portable surface:

```console
rustup toolchain install 1.96.0 --profile minimal --component clippy,rustfmt
cargo build --no-default-features
cargo test --no-default-features
```

The portable packet kernel and offline capture path do not require libpcap. On
Linux and macOS, the default `live` feature enables the isolated legacy
interface enumerator without capture or injection. Windows default and every
target's `--no-default-features` build remain portable. The explicit
`native-route` feature selects passive native route, source, MTU, and interface
discovery through Linux route netlink, macOS routing sockets/`getifaddrs`, or
Windows IP Helper. It does not require libpcap, Npcap, raw-socket privileges,
ARP/NDP, capture, or transmission.

Build and test the current target's native providers with:

```console
cargo test --features native-route
# Linux/macOS: requires the system libpcap development/runtime files.
cargo test --features native-layer2
# Raw IPv4/IPv6 sockets on Linux, macOS, or Windows:
cargo test --features native-layer3
# Equivalent to the complete CI native-provider profile:
cargo test --all-features
```

`native-layer2` provides owned, bounded capture and complete-frame injection through libpcap 2.4 on Linux/macOS. Windows x86_64 MSVC loads the Npcap 1.88 runtime dynamically using the pinned SDK 1.16 ABI, so compilation does not require an SDK or import library. `SystemNeighborResolver` composes those providers with interface metadata to perform bounded ARP or NDP; pair it with `native-route` for target-native route, gateway, source, and MTU selection. `native-layer3` provides `SystemLayer3Io` through target raw sockets, constrains the route-selected path separately from crafted source fields, and validates that mandatory kernel header processing cannot change the intended wire bytes. Live use still requires the relevant native runtime and operating-system privileges; missing dependencies, devices, permissions, unsupported packet classes, and unsupported modes are typed errors rather than fallbacks.

See the [platform and capability matrix](docs/platform-support.md) before depending on a live workflow.

## CLI direction

The final v0.2 command set is:

```text
build       dissect      plan         send         exchange
capture     read         replay       scan         traceroute
dns         fuzz         interfaces   routes
```

One packet recipe comes from exactly one of `--packet`, `--packet-file`, or standard input. A concise expression is intended for one-off work:

```console
packetcraftr build --packet 'ether()/ipv4(dst="192.0.2.10")/tcp(dport=443)/raw(hex="010203")'
```

Versioned JSON or YAML documents are intended for generated, complex, or reviewable packets. Workflow settings such as interface, timeout, output format, replay timing, or traffic policy never belong inside a packet document. The versioned [packet and output JSON Schemas](schemas/README.md) and [example documents](examples/documents) are included in the repository.

Machine-readable aggregate output uses one typed `packetcraftr.output/v1` JSON envelope. Streaming commands use independently valid NDJSON records; every success and error has a `sequence`. Per-item errors retain their input sequence, while a terminal error after prior records takes the next unused value. JSON and NDJSON are distinct `--output` values rather than command-dependent meanings of `json`. Raw and hexadecimal formats always refer to the complete captured or built frame, never payload-only bytes. Golden success/error documents cover every command, and exact-byte tests compare JSON `bytes_hex`, raw, hex, NDJSON, PCAP, and PCAPNG. The complete command/format matrix is part of the [output schema contract](schemas/README.md#commandformat-matrix).

The [stable CLI contract](docs/cli-contract.md) freezes the 14-command grammar,
help/defaults, recipe exclusivity, exit classes, streaming behavior, permitted
platform variance, and beta compatibility-review gate.
The [executable workflow examples](docs/cli-examples.md) cover every command;
CI runs their offline paths and proves that native/live paths fail with a typed
capability error before side effects under the portable build.

### Offline capture and replay

`read` applies explicit frame, byte, per-frame/block, and PCAPNG-interface
ceilings. In addition to text, NDJSON, and whole-frame hex, it can stream a
classic PCAP input back to PCAP or copy either format to PCAPNG. The copy keeps
byte order, open link types, interface identities, snap lengths, timestamp
resolution/offset, directions, captured/original lengths, and complete bytes;
PCAPNG-to-PCAP metadata loss is rejected.

`replay` streams complete Ethernet or raw IPv4/IPv6 frames through an exact
interface and link mode. Original, scaled-speed, fixed-rate, and immediate
timing use an injectable clock. Public destinations are denied by default,
truncated records cannot be replayed, and malformed evidence requires both
`--allow-malformed-live` and `--allow-permissive-packets`. Every successful
frame has exact backend-confirmed wire evidence; missing evidence and partial
sends fail closed. Text, aggregate JSON, NDJSON, PCAP, and PCAPNG renderers
share the same bounded operation. See the
[capture/replay contract](docs/capture-replay.md).

The [v0.1 to v0.2 migration guide](docs/migration-v0.1-to-v0.2.md) maps common legacy commands and explains removed subsystems.

### Structured scans

`scan` generates bounded TCP SYN, UDP, or ICMP echo probes for every authorized
IPv4/IPv6 target selected by the request. Hostnames are authorized before DNS
and every answer is authorized before probe construction. Homogeneous batches
reuse capture-ready `exchange`; finite attempts, rate, batch, packet, byte,
duration, queue, and evidence limits apply before or during the operation.

```console
packetcraftr --output json scan 192.168.56.10 \
  --transport tcp --ports 22,443 --attempts 2 \
  --timeout-ms 750 --batch-size 2 --rate 20
```

Results distinguish correlated response evidence, timeouts, closed,
filtered, unreachable, and unknown endpoints. Policy denials and runtime
failures remain typed errors. See the [structured scan contract](docs/scan.md).

### Structured traceroute

`traceroute` sends bounded UDP, ICMP echo, or TCP SYN hop batches over IPv4 or
IPv6. It authorizes hostname intent before DNS and every answer before choosing
the first requested-family address. Every attempt retains its timing, status,
responder, terminal/intermediate meaning, and bounded exact response evidence.

```console
packetcraftr --output ndjson traceroute 192.168.56.10 \
  --strategy udp --max-hops 20 --attempts 3 \
  --timeout-ms 750 --rate 12
```

Only checksum-valid direct replies or ICMP errors quoting the exact original
probe can advance or terminate the trace. Capture readiness precedes each hop
burst, cleanup is joined on success and failure, and unsupported native paths
remain typed errors before transmission. See the
[structured traceroute contract](docs/traceroute.md).

### Structured DNS

`dns` sends bounded IPv4/IPv6 UDP queries through the same policy-gated,
capture-ready exchange lifecycle. It authorizes a server hostname before every
resolution and every returned address before each retry, validates the exact
reverse tuple, transaction, question, compression, record, and message bounds,
and separates accepted question-relevant data from rejected section records.

```console
packetcraftr --output json dns 192.168.56.53 www.example.test \
  --type a --attempts 2 --timeout-ms 750
```

Truncation, timeout, unrelated traffic, decode failure, and correlated network
failure remain distinct typed outcomes. TXT and unknown RDATA retain exact hex;
terminal text is escaped. See the [structured DNS contract](docs/dns.md).

### Deterministic field-aware fuzzing

`fuzz` mutates reflective packet fields with explicit boundary, random,
bit-flip, and malformed-derived-field strategies. It is offline by default:
generation, exact building, and bounded dissection have no resolver, route, or
native-I/O seam. Absolute case indices derive independent seeds, so one case
can be reproduced without replaying its predecessors.

```console
packetcraftr --output json fuzz \
  --packet 'ipv4(src="192.0.2.1",dst="192.0.2.2")/udp(sport=40000,dport=9)/raw(text="hello")' \
  --seed 42 --cases 64 --strategy boundary,random,bit-flip
```

`--live` is a separate opt-in and sends built cases through the shared traffic
policy and capture-ready exchange lifecycle. Permissive or malformed live
bytes additionally require both `--allow-malformed-live` and
`--allow-permissive-packets`. Case, packet, aggregate byte, field/list,
shrink, rate, timeout, duration, capture, and evidence bounds are finite. See
the [bounded fuzz contract](docs/fuzz.md).

### Route-aware and live workflows

`plan` and `routes` are passive. `plan` selects the route, interface-owned
source, MTU, next hop, and final link mode for one packet recipe; it never
performs neighbor discovery, capture, or transmission. `routes` reports one
interface-bound passive `RouteDecision` for each up interface. It is a provider-neutral
provider inventory, not a verbatim dump of the operating system's route table.

```console
packetcraftr --output json plan \
  --packet 'ipv4(dst="192.0.2.10")/udp(dport=9)/raw(text="hello")' \
  --interface "$LAB_INTERFACE" --link-mode layer3
packetcraftr --output json routes
```

`send`, `capture`, and `exchange` reuse the same exclusive packet-expression,
packet-document, or standard-input recipe and the same `--destination`,
`--interface`, `--source`, and `--link-mode` constraints. Live commands require
the matching native Cargo features, runtime dependencies, devices, and
privileges described in the [platform matrix](docs/platform-support.md).

```console
# Transmit one authorized lab packet and preserve its exact sent bytes.
packetcraftr --output pcapng send \
  --packet 'ipv4(dst="192.0.2.10")/udp(dport=9)/raw(text="hello")' \
  --interface "$LAB_INTERFACE" --link-mode layer3 \
  --max-packets 1 --max-bytes 1500 > sent.pcapng

# Capture from the packet's planned interface for one finite second.
packetcraftr --output ndjson capture \
  --packet 'ipv4(dst="192.0.2.10")/udp(dport=9)' \
  --interface "$LAB_INTERFACE" --timeout-ms 1000 \
  --max-queue-frames 64 --max-captured-bytes 1048576

# Arm and await capture before sending, then retain at most one response.
packetcraftr --output json exchange \
  --packet 'ipv4(dst="192.0.2.10")/udp(dport=9)' \
  --interface "$LAB_INTERFACE" --timeout-ms 1000 \
  --max-responses 1 --max-unsolicited 0 --max-queue-frames 64
```

Public destinations and hostname resolution are denied by default. They need
the separate `--allow-public-destinations` and
`--allow-hostname-resolution` acknowledgements. A permissive live build needs
both `--allow-permissive-live` and `--allow-permissive-packets`. Packet and
byte budgets are evaluated before active neighbor or transmission work and
bound the frames/bytes emitted by standalone capture;
capture/exchange timeouts, queue frames, retained bytes, snap length, and
overflow behavior are finite and validated before route or live I/O. Use only
on networks where you have explicit authorization.

Exchange capture-file output includes timestamped exact sent frames and all
retained response, unsolicited, and undecodable capture evidence. PCAPNG uses
separate interface descriptions when a raw Layer 3 request and captured Layer
2 response have different link types. Classic PCAP can represent only one link
type and returns an explicit output error for such a mixed stream.

## Safety model

Packet construction and transmission can disrupt networks or violate policy. Only use PacketcraftR against systems and networks where you have explicit authorization.

The v0.2 contracts are:

- Planning may inspect local route and interface state, but never performs ARP, NDP, capture, or transmission.
- A hostname is policy-authorized before resolver or route side effects. Every distinct address selected by each resolution or re-resolution is then policy-authorized before route use; hostname resolution is disabled by default.
- Ethernet/VLAN intent never silently falls back to Layer 3.
- Off-link neighbor resolution targets the route gateway, not the final destination.
- Complete non-IP Layer 2 packets use passive, explicit-interface selection; they do not invent an IP route or trigger neighbor resolution.
- A spoofed packet source is kept distinct from the interface-owned source used for ARP or NDP.
- Active ARP/NDP arms an owned capture before sending, uses the selected interface and exact VLAN stack, accepts only correlated protocol-valid replies, retains bounded evidence, and always stops and joins capture work.
- Neighbor failure is explicit after finite attempts and never changes the selected route or link mode. Successful mappings use a finite, bounded cache keyed by the complete logical-link identity.
- Strict builds validate dependent fields and layer bindings.
- Permissive builds retain requested inconsistencies and emit diagnostics. Sending their bytes requires a second, explicit live-transmission opt-in.
- A known discriminator (for example, IPv4 EtherType) cannot label a `Raw` child in strict mode when the registry requires a typed child. Unknown discriminators can still preserve opaque bytes; permissive mode reports the known-discriminator mismatch and requires the live opt-in.
- Decode-only multiplexing roots must explicitly admit each concrete protocol they return. The raw-IP root therefore continues registry binding from the decoded IPv4 or IPv6 layer rather than misrepresenting it as a generic link layer.
- Padding records an explicit ownership boundary when its bytes sit outside an IPv4, IPv6, or UDP declared length or the fixed ARP body. Invalid or unsupported boundaries fail strict builds; preserved network/datagram trailers emit diagnostics and require the live opt-in.
- Synthesized or resolved Layer 2 bytes are part of the exact built frame. Byte-policy checks include that envelope before neighbor traffic, and a backend-reported partial send is a typed failure.
- Raw Layer 3 adapters accept only complete IPv4/IPv6 datagrams for the selected route and MTU. They reject header values the operating system would change, preserve spoofed packet sources separately from the bound interface source, and report partial native writes as typed failures.
- Replay authorizes each fully captured frame before interface or route I/O, fixes its Layer 2/Layer 3 provider from the capture root, applies finite timing/frame/byte ceilings, and requires backend-confirmed bytes before emitting success evidence.
- Scan authorizes the declared hostname before DNS and every resolved address before probe construction, then uses bounded capture-ready exchanges and accepts only checksum-valid matcher- or quote-correlated responses.
- DNS authorizes the complete operation before probe construction, repeats hostname and every-answer authorization for each retry, and accepts only checksum-valid reverse-tuple responses with the exact transaction and question; unrelated section data remains rejected audit evidence.
- Fuzzing is offline by default and derives each case directly from its operation seed and absolute index. Live fuzzing authorizes the complete packet/wire budget before route I/O and requires independent operation and policy opt-ins for permissive or malformed bytes.
- Route MTU checks measure the actual built network-layer byte span instead of trusting permissive wire length fields. Oversized packets fail before neighbor discovery or live I/O and require an explicit fragmentation transform.
- Capture is ready before an exchange sends its first frame, and one owned receive stream routes every frame rather than silently draining traffic.
- Exchange always attempts to stop and join its capture session after readiness, send, receive, or timeout failures. If the operation and cleanup both fail, both errors remain visible.
- Public live errors carry a stable machine code, one of the documented CLI exit classes, and actionable remediation. Text rendering escapes terminal controls; JSON retains the structured value through JSON escaping.
- Unsupported link types and unknown payloads remain explicit raw data; unsupported combinations produce typed errors.
- Display truncation never truncates the captured bytes stored in a result.

The beta-candidate contracts and guards above are implemented and regression
tested. Privileged live-I/O qualification on the dedicated Linux, macOS, and
Windows runners remains a release gate: inspect plans and exact bytes, use
isolated authorized labs, keep finite budgets, and prefer offline operations
until the relevant target/profile is listed as qualified for the Release you
use.

Default resource ceilings are intentionally finite:

| Resource | Default ceiling |
| --- | ---: |
| Decoded layers | 64 |
| Offline packet or PCAPNG block | 16 MiB |
| Frames / captured bytes per offline write or replay | 10,000 / 256 MiB |
| PCAPNG interfaces per section | 4,096 |
| PCAPNG metadata blocks before the next packet | 4,096 |
| Concrete packets per template expansion | 10,000 |
| Distinct addresses per hostname resolution | 64 (configurable to 4,096) |
| Backend capture queue frames (aggregate) | 4,096 |
| Retained captured bytes per exchange | 256 MiB |
| Exchange reply timeout | 3 seconds (maximum 1 hour) |
| Cumulative replay delay | 1 hour |
| Active neighbor attempts / timeout per attempt | 3 / 1 second |
| Active neighbor evidence frames / bytes | 256 / 1 MiB |
| Active neighbor cache entries / lifetime | 4,096 / 30 seconds |
| DNS attempts / complete message records | 1 (maximum 32) / 512 |
| DNS name pointers / TXT strings / TXT bytes | 32 / 256 / 16 KiB |
| DNS rejected-record / undecoded evidence metadata | 128 / 32 |
| Fuzz cases / maximum cases | 64 / 10,000 (hard maximum 100,000) |
| Fuzz field bytes / list items / shrink values | 4 KiB / 256 / 8 |
| Fuzz packet / aggregate and evidence bytes | 16 MiB / 256 MiB |
| Reassembly flows | 8,192 |
| Buffered/history bytes per reassembly flow | 1 MiB |
| Aggregate reassembly bytes | 256 MiB |
| Fragments per datagram | 256 |
| Pending TCP segments per flow | 4,096 |
| Fragment expiry | 30 seconds |
| Idle TCP-flow expiry | 2 minutes |

All parsers and queues must use checked arithmetic, honor configurable bounds, and fail closed.
The `capture` and `exchange` command grammar reserves `--max-queue-frames`,
`--max-captured-bytes`, `--snap-length`, and `--overflow-policy`. The queue
frame bound is one aggregate backend and retained-evidence limit; response,
unsolicited, and undecodable classes share it rather than adding together. The
stable maxima are 4,096 frames, 256 MiB aggregate bytes, and 16 MiB per frame;
invalid values fail before route or live-I/O side effects. The default overflow policy fails
the operation. Explicit `drop-newest` and `drop-oldest` policies must report
received, dropped, byte, and overflow counters, and any loss is surfaced in
structured diagnostics and operation statistics.

## Development

The pull-request checks exercise formatting and the default, no-default-feature, and all-feature profiles on Linux, macOS, and Windows. No-default profiles are portable; Windows default is also portable and excludes `socket2` along with the other native adapters. All-feature jobs compile the target's native route, Layer 2, and raw Layer 3 adapters, exercise passive providers and injected capture/send lifecycles, and continue to reject static `pcap`, `pnet`, or `Packet.lib` linkage on Windows. Privileged live-I/O qualification remains a separate release-candidate gate.

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo clippy --workspace --no-default-features --all-targets -- -D warnings
cargo test --workspace --no-default-features --all-targets
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features --all-targets
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
bash scripts/verify-release-archive.sh
bash scripts/check-architecture.sh
python3 scripts/validate-fixture-corpus.py
python3 scripts/test-fixture-policy.py
cargo build --locked --no-default-features
python3 scripts/check-documentation-examples.py
```

Tests never rewrite authoritative packet fixtures. The read-only corpus covers
every registered capture root, valid and malformed PCAP/PCAPNG, packet
documents, expected decodes, and output-schema failures; every file is verified
against its reviewed SHA-256 before parsing. Read the [fixture and provenance
policy](tests/fixtures/README.md) before adding or replacing evidence.

Security-sensitive findings should follow [SECURITY.md](SECURITY.md), not a public issue.

## Scope and non-goals

v0.2 targets Rust developers and network engineers who need packet-laboratory primitives and structured CLI results. It does not provide Python bindings, dynamic-library plugins, a rules engine, daemon, REPL, embedded Prometheus server, full TCP/IP endpoint stack, TLS decryption, or an intrusion-prevention service.

## License

Copyright (C) 2026 tyk-swe.

PacketcraftR is distributed under the [AGPL-3.0-only](LICENSE) license. There is no warranty; see the license for details.
