# PacketcraftR

PacketcraftR is a Rust library and CLI for protocol development,
interoperability testing, and authorized network diagnostics. It provides
exact packet construction, bounded dissection, capture-file I/O, offline
analysis, and policy-gated live networking.

Current release: pre-1.0 beta `0.5.0-beta.3`. Rust APIs and versioned serialized
contracts may change between beta releases; review the [changelog](CHANGELOG.md)
and [beta.3 migration note](docs/migration-beta.3.md) before upgrading.

> **Authorized use:** PacketcraftR is designed for controlled labs, protocol
> testing, and diagnostics on systems and networks you own or are explicitly
> authorized to test. Its opt-in flags are technical controls, not permission.

## Quick Start

These offline examples work in every feature profile:

```console
packetcraftr protocols
packetcraftr --output hex build --packet 'raw(text=hello)'
packetcraftr --output json dissect --link-type 228 \
  --hex '450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f'
packetcraftr --output ndjson read examples/captures/tls-handshake.pcapng \
  --max-frames 100
packetcraftr tls examples/captures/tls-handshake.pcapng
packetcraftr --output json build \
  --packet-file examples/documents/packet-ipv4-udp.json
```

The `tls` example assembles ClientHello and ServerHello records across TCP
segments and reports SNI, negotiated parameters, JA3/JA3S/JA4, and status.
Use `packetcraftr --help`, `packetcraftr <COMMAND> --help`, and
`packetcraftr protocols [PROTOCOL]` for the authoritative command, option, and
protocol catalogs.

Recipe commands also accept a packet expression, JSON, or YAML from redirected
stdin when neither `--packet` nor `--packet-file` is supplied. YAML comments and
mapping key order work the same as in `.yaml` files. For example,
`packetcraftr --output hex build < examples/documents/packet-ipv4-udp.json` builds the
document under the same input byte and build limits. Terminal stdin is rejected
instead of waiting for interactive input.

Offline `read`, `expert`, `follow`, `stats`, and `tls` accept `-` as the capture
path to stream PCAP or PCAPNG from redirected stdin. For example,
`packetcraftr --output ndjson read - < examples/captures/tls-handshake.pcapng`.
The same frame, byte, interface, and analysis limits apply to files and pipes.
Terminal stdin is rejected; live `replay` remains file-based. Reads are
synchronous and can block between duration checks while waiting for more input;
a duration limit does not interrupt a pending stdin read.

Capture output from `read` preserves source records and requires the same format
by default. To export matching physical frames from either capture format, use
`packetcraftr --output pcapng read capture.pcap --normalize --filter 'udp' > selected.pcapng`.
Normalization writes one new section with remapped selected interfaces, retaining
packet bytes, captured/original lengths, link types, direction, and interface
snapshot length, timestamp resolution, and offset. It discards comments, unknown
blocks/options, and original section structure; it does not reassemble packets.
Timestamps must be exactly representable as nanosecond capture time and at their
interface resolution. Unrepresentable times and selected frames without timestamps
fail instead of receiving invented times.
Zero matches produce a valid section with no interfaces or packets. Input limits
count filtered-out frames too; the same block and interface ceilings bound output.

| Area | Commands |
| --- | --- |
| Packets and captures | `build`, `dissect`, `protocols`, `read` |
| Offline analysis | `expert`, `follow`, `stats`, `tls`, `fuzz` |
| Native inspection and planning | `interfaces`, `routes`, `plan` |
| Live workflows | `send`, `exchange`, `capture`, `replay`, `scan`, `traceroute`, `dns`, `fuzz --live` |

## Filtered capture export

Save a focused capture in the source format:

```console
packetcraftr --output pcapng read capture.pcapng \
  --filter 'udp.port == 53' > dns.pcapng
```

Selected packet records retain their original bytes, timestamps, and options.
All metadata is retained; PCAPNG section lengths become unknown and interface
statistics still describe the source capture. Filters use original frame numbers
and do not automatically include related packets or fragments. Stream selectors
are unsupported; format conversion requires `--normalize --output pcapng`. All
input packets count toward the finite frame/byte limits, and an empty selection
is valid. Errors can leave partial output. Without `--filter` or `--normalize`,
capture output remains a byte-for-byte rewrite.

`read --dissect` and `dissect` decode DNS answer, authority, and additional
records, including EDNS and exact unknown RDATA. Malformed or truncated DNS
messages produce diagnostics while retaining their captured bytes. The
[migration notes](docs/migration-unreleased.md#offline-dns-records) describe
the structured record fields and bounded core decoder.

## Install

[GitHub releases](https://github.com/tyk-swe/pcr/releases) provide Linux
x86-64, macOS x86-64 and Arm64, and Windows x86-64 MSVC archives. Verify the
matching archive with `SHA256SUMS`, then put `packetcraftr` or
`packetcraftr.exe` on `PATH`.

- `all-features` archives include routing, raw Layer 3, and Layer 2
  capture/injection. They require libpcap on Linux and macOS or Npcap 1.88 on
  Windows.
- `pcap-free` archives include routing and raw Layer 3 without libpcap/Npcap.

Release archives produced by the current workflow include GitHub Artifact
Attestations signed with Sigstore:

```console
gh attestation verify packetcraftr-v<version>-<target>-<variant>.<ext> --owner tyk-swe
```

To build from source, install the toolchain in `rust-toolchain.toml`; the same
supported version is declared in `Cargo.toml`. All-feature Linux builds also
need libpcap development files such as `libpcap-dev`.

Choose the source profile before building:

```console
# Offline construction, capture-file processing, and analysis
cargo build --locked --release -p packetcraftr-cli --no-default-features
# Passive routes/interfaces and raw Layer 3 I/O, without libpcap
cargo build --locked --release -p packetcraftr-cli --no-default-features --features native-layer3
# Every native provider, including capture, Layer 2, and capture-ready exchanges
cargo build --locked --release -p packetcraftr-cli --all-features
./target/release/packetcraftr --version
```

Default features provide passive routes/interfaces. Capture, exchange and
capture-backed probes require the corresponding full-native provider; pcap-free
is intended for offline work, routing, raw Layer 3 send and replay. See
[Contributing](CONTRIBUTING.md) for the ordinary Cargo loop.

Release artifacts use these runtime baselines: Ubuntu 24.04 (glibc 2.39), macOS 14
on arm64, macOS 15 on x86_64, and Windows Server 2022 on x86_64. Older systems are
not a tested binary baseline; build from source for another environment.
Full-native Linux needs the shared libpcap runtime (Ubuntu `libpcap0.8t64`);
Windows capture/Layer 2 needs a working Npcap installation exporting the symbols
required by the loader. Pcap-free archives do not require libpcap/Npcap.
`BUILD-METADATA.json` in each release archive records compiler, commit, target,
feature variant and the executable digest. Linux packaging also runs offline
smokes in a clean Ubuntu 24.04 container.

Read [analysis resources and evidence](docs/analysis-resources.md) for cumulative
versus concurrent limits, clock/filter semantics, cancellation and reproducible
whole-workflow memory measurements. Binary output refuses interactive stdout
unless `--force-binary-stdout` is supplied. For commands with cooperative
cancellation, the first interrupt requests cleanup;
the second forces exit. Cancellation exits 130; a killed process or unwritable
sink cannot promise a terminal NDJSON record.

## Contracts

- Packet JSON/YAML: [`packetcraftr.packet/v1`](schemas/packetcraftr.packet.v1.schema.json)
- Structured command output: [`packetcraftr.output/v2`](schemas/packetcraftr.output.v2.schema.json)
- Published packet and output examples: [`examples/documents`](examples/documents)

Aggregate output consumers must ignore unknown fields in result objects and
nested output records. Shared records follow this rule in NDJSON too. Envelope
fields, enum vocabularies, and embedded packet documents remain strict. Changed
machine contracts receive a new schema version; packet documents and command
output are versioned independently.

Packet documents use bounded JSON/YAML parsing. Put the global `--output`
option before the command, for example `packetcraftr --output json stats
capture.pcapng`. Supported formats depend on the command and include `text`,
`json`, `ndjson`, `hex`, `raw`, `pcap`, and `pcapng`; invalid
combinations fail explicitly. Every output-v2 NDJSON envelope has an `event`
discriminator, including `frame`, `finding`, `chunk`, `session`, `complete`,
and `error`. The payload is in `result` or `error`; consumers never need to
infer a record kind from payload fields. `sequence` starts at zero and advances
for each record. Successful operations end with exactly one `complete`; failed
operations emit one terminal `error` when the output is still writable. A broken
output is reported as incomplete on stderr and cannot guarantee a terminal line.
The packet-document contract remains v1; the old output-v1 contract is retired.

Exit codes are part of the contract: 0 on success, 2 for an invalid invocation
or input (`cli`), 3 for a packet that cannot be built or dissected (`packet`),
4 when a native feature, backend, or privilege is unavailable (`capability`),
5 for a failed system or network operation (`io`), 6 when the traffic policy
denies the operation (`policy`), and 70 for an internal invariant failure.
The name in parentheses is the `error.kind` of the same failure in JSON and
NDJSON output; `packetcraftr --help` lists the table.

Offline `stats`, `expert`, `follow`, and `tls` perform bounded, capture-global
IPv4 and IPv6 fragment reassembly before downstream transport indexing. A
completed datagram is a derived view attached to the physical fragment that
completed it: `frame.*` fields and physical frame/byte totals remain captured
facts, while reconstructed child layers can satisfy display filters and join
TCP or UDP conversations. `stats --table fragments` reports physical fragment
and derived-datagram accounting separately. The shared `--ip-overlap`,
`--ip-idle-expiry-ms`, and `--max-ip-*` options make overlap behavior, expiry,
and every retained-state ceiling explicit.

`follow --stream tcp:N` and `follow --stream udp:N` exit with invocation error
2 when the selected conversation is absent, including in an empty capture.
Existing conversations with no payload still succeed with zero extracted bytes.

## Library

Depend on the crate that owns the capability you need:

| Crate | Ownership and entry points |
|---|---|
| `packetcraftr-core` | `Packet`, protocol codecs/reflection, bounded documents, capture files, filters, and `analysis::run` |
| `packetcraftr-netio` | Interface/route providers, capture/transmit resources, and platform backends |
| `packetcraftr` | `Client` preparation/send/exchange, `policy`, and DNS/replay/scan/traceroute/fuzz workflows |
| `packetcraftr-cli` | Arguments and rendering; its `output` module owns machine representations and the stream encoder |

Core is portable and independent of native I/O. A workflow uses one policy
implementation for operation admission and final-wire checks; resolver and
replay adapters add their specific boundaries. The CLI shares the same policy
instance with its authorizer and executor. `dns::Completion` and `dns::Report`
validate accepted transport and retained evidence at construction.

Offline analysis exposes a physical `FrameRecord` with optional `TcpView` and
`UdpView` observations. Each observation carries its decoded source and scoped
conversation together. Derived datagrams do not add physical frames or bytes.

```console
cargo doc --locked --workspace --all-features --no-deps --open
```

## Live Networking

Live operations enforce destination policy, hostname-resolution opt-ins,
permissive-packet and source-spoofing controls, route/interface and MTU checks,
finite packet/byte/time budgets, and native OS permission requirements. Only
applicable commands expose each control; read that command's `--help` instead
of copying flags between workflows.

Time budgets are checked at workflow boundaries and passed to native I/O where
its interface accepts a deadline. Event publication bounds the caller's wait.
Synchronous provider, reader, and resolver calls use their own I/O timeouts;
workflow checks cannot interrupt them or arbitrary injected callbacks. Timed-out
workers retain their permits and resources until cleanup finishes.

| Platform | Requirements and notable limits |
| --- | --- |
| Linux | Layer 2 and raw Layer 3 usually require root or `CAP_NET_RAW`; complete builds need libpcap. Containers must expose the interface, route, and capability in the same namespace. |
| macOS | Layer 2 needs libpcap and BPF-device access; raw sockets usually require root. Complete-header raw IPv6 transmission is unsupported. |
| Windows | Layer 2 needs Npcap 1.88; raw sockets usually require administrator rights. Windows may reject raw UDP with a non-local source. |

For `capture`, `--capture-filter` is resolver-free native BPF applied before
PacketcraftR queues and budgets; `--filter` runs after capture.

`dns` starts each attempt over UDP. By default, a matching validated response
with the DNS truncation flag triggers one length-prefixed TCP continuation to
the same independently reauthorized numeric server. UDP and TCP share the
single `--timeout-ms` attempt window; TCP failures follow the normal retry
count. Output identifies both attempted phases and the transport of the
accepted response, without presenting socket bytes as captured frames. Use
`--udp-only` when transport diagnostics or compatibility require the previous
terminal-truncation behavior, or when packet-oriented `--interface`, `--source`,
or `--link-mode` overrides must be preserved. IPv6 link-local DNS servers also
require `--udp-only` because the target syntax does not carry a TCP scope ID.

Kernel TCP control and retransmission packets are OS-managed, so DNS
authorization does not mislabel them as an exact raw-packet count. It instead
charges bounded connection and framed-message traffic units, application
bytes, and duration alongside the exact UDP wire budget.

This documentation-address example only prints help and performs no network
operation:

```console
packetcraftr dns 192.0.2.53 example.test --udp-only --help
```

## Contributing, Security, and License

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance. Report
suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

PacketcraftR is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE).
