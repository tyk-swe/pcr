# PacketcraftR

PacketcraftR is a Rust library and CLI for protocol development,
interoperability testing, and authorized network diagnostics. It provides
exact packet construction, bounded dissection, capture-file I/O, offline
analysis, and policy-gated live networking.

Current release: pre-1.0 beta `0.5.0-beta.1`. Rust APIs and versioned
serialized contracts may change between beta releases; review the
[changelog](CHANGELOG.md) before upgrading.

> **Authorized use:** PacketcraftR is designed for controlled labs, protocol
> testing, and diagnostics on systems and networks you own or are explicitly
> authorized to test. Its opt-in flags are technical controls, not permission.

## Quick Start

Offline examples that work in every feature profile:

```console
packetcraftr protocols
packetcraftr protocols ipv4
packetcraftr --output hex build --packet 'raw(text=hello)'
packetcraftr --output json dissect --link-type 228 \
  --hex '450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f'
packetcraftr --output ndjson read capture.pcapng --max-frames 100
packetcraftr --output json build \
  --packet-file examples/documents/packet-ipv4-udp.json
```

Dissect, edit, and rebuild a packet:

```console
$ packetcraftr dissect --hex '020000000002020000000001080045000021000000004011f6c8c0000201c0000202c0000009000d77f468656c6c6f' --output document > pkt.yaml
```

Edit one field in `pkt.yaml`:

```yaml
  - ipv4:
      destination: "192.0.2.3"
```

Rebuild the modified frame:

```console
$ packetcraftr build --packet-file pkt.yaml --output hex
020000000002020000000001080045000021000000004011f6c7c0000201c0000203c0000009000d77f368656c6c6f
```

Use `packetcraftr --help`, `packetcraftr <COMMAND> --help`, and
`packetcraftr protocols [PROTOCOL]` for the authoritative command and protocol
catalog.

| Area | Commands |
| --- | --- |
| Packets and captures | `build`, `dissect`, `protocols`, `read` |
| Offline analysis | `expert`, `follow`, `stats`, `tls`, `fuzz` |
| Native inspection and planning | `interfaces`, `routes`, `plan` |
| Live workflows | `send`, `exchange`, `capture`, `replay`, `scan`, `traceroute`, `dns`, `fuzz --live` |

## TLS Handshakes

`tls` assembles one record per handshake from a capture file, joining the
client's offer to the server's decision across TCP segmentation. The repository
ships a capture to run it on:

```console
$ packetcraftr tls examples/captures/tls-handshake.pcapng
session=0 stream=tcp:0 client=192.0.2.1:54321 server=198.51.100.2:443 status=complete sni=api.example.test version=TLS1.3 cipher=0x1301(TLS_AES_128_GCM_SHA256) group=x25519 alpn=h2,http/1.1 selected_alpn=none ja3=54e2a2e989457808c77e4464d9361826 ja4=t13d0406h2_77f0cd3447db_5d4d534e3685 frames=4..5 rtt_ms=24.000
tls sessions=1 selected=1 omitted=0 evicted=0 complete=1 client_only=0 retry=0 alert=0 malformed=0 gap=0 truncated=0 tcp_streams=1 buffer_limit_hits=0 udp_443_frames=0 frames_matched=8 frames_read=8
```

One `key=value` line per session, so `grep sni=` and `sort | uniq -c` work.
`--output json` and `--output ndjson` carry the same session record with
numeric code points, and a `*_name` companion for the negotiated version,
cipher suite, key-share group, and alert description; the offered lists stay
numeric. JSON emits one document holding the sessions and a summary, while
NDJSON streams each session as it completes and is the format for large
captures.

Sessions are picked after assembly, not by a frame filter: `--stream`,
`--sni`, `--server-port`, and a repeatable `--status`.

Coming from tshark:

| tshark | packetcraftr |
| --- | --- |
| `-Y 'tls.handshake.extensions_server_name'` | `tls capture.pcapng` (assembled, not per frame) |
| `-Y 'tls.handshake.extensions_server_name == "x"'` | `tls capture.pcapng --sni x` |
| `-Y 'tls.handshake.type == 1'` | `tls capture.pcapng` (every session carries its client) |
| `-d tcp.port==4433,tls` | `--tls-port 4433` on `read`, `dissect`, or `tls`; session assembly already reads every TCP stream |
| `-z follow,tls,ascii,0` | `follow capture.pcapng --stream tcp:0` (raw stream bytes, not decrypted TLS payload) |
| `-T fields -e tls.handshake.ja3` | `--output json tls capture.pcapng` → `.result.sessions[].client.ja3` |
| `-e tls.handshake.ciphersuite` | `.result.sessions[].server.cipher_suite` and `.cipher_suite_name` |
| `-e tls.handshake.ja3s` | `.result.sessions[].server.ja3s` (JSON and NDJSON only) |
| `-Y 'tcp.stream == 12 && tls'` | `tls capture.pcapng --stream tcp:12` |

Per-frame and assembled are different views on purpose: `read --filter 'tls.sni
contains "example"'` matches only the hellos that fit in a single segment, while
`tls` reassembles the stream first. `tls.incomplete` filters the frames whose
record continues into the next one.

## Install

[GitHub releases](https://github.com/tyk-swe/pcr/releases) provide Linux
x86-64, macOS x86-64 and Arm64, and Windows x86-64 MSVC archives. Download the
matching archive and `SHA256SUMS`, verify the checksum, then put
`packetcraftr` or `packetcraftr.exe` on `PATH`.

- `all-features` archives include routing, raw Layer 3, and Layer 2
  capture/injection. They require libpcap at runtime on Linux and macOS, or
  Npcap 1.88 on Windows.
- `pcap-free` archives include routing and raw Layer 3 without a libpcap/Npcap
  dependency.

From source, install the toolchain named in `rust-toolchain.toml` (MSRV: `rust-version` in `Cargo.toml`). All-feature Linux
builds also need libpcap development files such as `libpcap-dev`.

```console
cargo build --locked --release -p packetcraftr-cli
./target/release/packetcraftr --help
```

Add `--no-default-features` for an offline-only build or `--all-features` for
all native capabilities. The Cargo manifests and command help are authoritative
for feature selection. Missing features, dependencies, or OS privileges fail
closed.

## Contracts

- Packet JSON/YAML: [`packetcraftr.packet/v2`](schemas/packetcraftr.packet.v2.schema.json)
- Legacy packet contract: [`packetcraftr.packet/v1`](schemas/packetcraftr.packet.v1.schema.json)
- Structured command output: [`packetcraftr.output/v1`](schemas/packetcraftr.output.v1.schema.json)
- Published packet and output examples: [`examples/documents`](examples/documents)

A `packetcraftr.packet/v2` document is a list of single-key layers whose
values are coerced by each field's declared kind, so a fixture spells only the
fields that matter and the builder derives the rest. `docs/packet-v2.md`
describes the shape, the three field tiers, and the error codes;
`packetcraftr convert` rewrites v1 documents.

Put the global `--output` option before the command, for example
`packetcraftr --output json stats capture.pcapng`. Command-specific formats
include `text`, `json`, `ndjson`, `hex`, `raw`, `pcap`, and `pcapng`;
unsupported combinations fail explicitly. Machine and binary formats contain no
terminal colour codes. Streaming commands use NDJSON and finish with either one
completion record or one typed error after any records already emitted.

`dissect --output json` always emits one aggregate document with `matched` and
`dissection`. A filter miss is successful output with `matched: false` and
`dissection: null`.

## Library

Rust users normally depend on the `packetcraftr` facade. It re-exports packet
mechanics as `core`, offline capture tools as `analysis`, and provider/native
I/O as `netio`. The core and offline-analysis path has no live-I/O dependency.
Cargo manifests and `cargo metadata` are the source of truth for the package
graph and features.

```console
cargo doc --locked --all-features --no-deps --open
```

## Live Networking

Live operations enforce destination policy, hostname-resolution opt-ins,
permissive-packet opt-ins, source-spoofing controls, route/interface checks,
MTU checks, budgets, and native OS permission requirements. Only applicable
commands expose each control; read that command's `--help` instead of copying
flags between workflows.

| Platform | Requirements and notable limits |
| --- | --- |
| Linux | Layer 2 and raw Layer 3 usually require root or `CAP_NET_RAW`; complete builds need libpcap. Containers must expose the interface, route, and capability in the same namespace. |
| macOS | Layer 2 needs libpcap and BPF-device access; raw sockets usually require root. Complete-header raw IPv6 transmission is unsupported. |
| Windows | Layer 2 needs Npcap 1.88; raw sockets usually require administrator rights. Windows may reject raw UDP with a non-local source. |

For `capture`, `--capture-filter` is resolver-free native BPF applied before
PacketcraftR queues and budgets; `--filter` runs after capture.

## Contributing, Security, and License

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance. Report
suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

PacketcraftR is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE).
