# PacketcraftR

PacketcraftR is a Rust library and CLI for protocol development,
interoperability testing, and authorized network diagnostics. It provides
exact packet construction, bounded dissection, capture-file I/O, offline
analysis, and policy-gated live networking.

Current release: pre-1.0 beta `0.5.0-beta.2`. Rust APIs and versioned
serialized contracts may change between beta releases; review the
[changelog](CHANGELOG.md) before upgrading.

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

| Area | Commands |
| --- | --- |
| Packets and captures | `build`, `dissect`, `protocols`, `read` |
| Offline analysis | `expert`, `follow`, `stats`, `tls`, `fuzz` |
| Native inspection and planning | `interfaces`, `routes`, `plan` |
| Live workflows | `send`, `exchange`, `capture`, `replay`, `scan`, `traceroute`, `dns`, `fuzz --live` |

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
gh attestation verify packetcraftr-vVERSION-TARGET-VARIANT.EXT --owner tyk-swe
```

To build from source, install the toolchain in `rust-toolchain.toml`; the MSRV
is `rust-version` in `Cargo.toml`. All-feature Linux builds also need libpcap
development files such as `libpcap-dev`.

```console
cargo build --locked --release -p packetcraftr-cli
./target/release/packetcraftr --help
```

Use `--no-default-features` for offline-only builds,
`--no-default-features --features native-route,native-layer3` for pcap-free
native support, or `--all-features` for every native provider. Run
`./scripts/check-features.sh` to validate the complete supported matrix.

## Contracts

- Packet JSON/YAML: [`packetcraftr.packet/v1`](schemas/packetcraftr.packet.v1.schema.json)
- Structured command output: [`packetcraftr.output/v1`](schemas/packetcraftr.output.v1.schema.json)
- Published packet and output examples: [`examples/documents`](examples/documents)

Packet documents use bounded JSON/YAML parsing. Put the global `--output`
option before the command, for example `packetcraftr --output json stats
capture.pcapng`. Supported formats depend on the command and include `text`,
`json`, `ndjson`, `hex`, `raw`, `pcap`, and `pcapng`; invalid
combinations fail explicitly. Streaming NDJSON ends with one completion record
or one typed error.

## Library

Rust users normally depend on the `packetcraftr` facade. It re-exports packet
mechanics as `core`, offline capture tools as `analysis`, and providers/native
I/O as `netio`. The core and offline-analysis path has no live-I/O dependency.

```console
cargo doc --locked --all-features --no-deps --open
```

## Live Networking

Live operations enforce destination policy, hostname-resolution opt-ins,
permissive-packet and source-spoofing controls, route/interface and MTU checks,
finite packet/byte/time budgets, and native OS permission requirements. Only
applicable commands expose each control; read that command's `--help` instead
of copying flags between workflows.

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
