# PacketcraftR

PacketcraftR is a Rust library and CLI for exact packet construction, bounded
dissection, capture-file I/O, offline analysis, and policy-gated live
networking.

Current release: pre-1.0 beta `0.5.0-beta.1`. Rust APIs and versioned
serialized contracts may change between beta releases; review the
[changelog](CHANGELOG.md) before upgrading.

> **Live-network warning:** run live commands only on systems and networks you
> own or are explicitly authorized to test. PacketcraftR opt-in flags are
> technical controls, not permission.

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

Use `packetcraftr --help`, `packetcraftr <COMMAND> --help`, and
`packetcraftr protocols [PROTOCOL]` for the authoritative command and protocol
catalog.

| Area | Commands |
| --- | --- |
| Packets and captures | `build`, `dissect`, `protocols`, `read` |
| Offline analysis | `expert`, `follow`, `stats`, `fuzz` |
| Native inspection and planning | `interfaces`, `routes`, `plan` |
| Live workflows | `send`, `exchange`, `capture`, `replay`, `scan`, `traceroute`, `dns`, `fuzz --live` |

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

From source, install Rust 1.97.1. Rust 1.96 is the MSRV. All-feature Linux
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

- Packet JSON/YAML: [`packetcraftr.packet/v1`](schemas/packetcraftr.packet.v1.schema.json)
- Structured command output: [`packetcraftr.output/v1`](schemas/packetcraftr.output.v1.schema.json)
- Published packet and output examples: [`examples/documents`](examples/documents)

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
