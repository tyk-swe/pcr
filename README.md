# PacketcraftR

PacketcraftR is a Rust library and CLI for exact packet construction, bounded
dissection, capture-file I/O, offline analysis, and policy-gated live
networking.

The current release is a pre-1.0 beta (`0.5.0-beta.1`). Rust APIs and
versioned serialized contracts may change between beta releases; review the
[changelog](CHANGELOG.md) before upgrading. The
[pre-1.0 roadmap](docs/roadmap/README.md) defines the release blockers,
contract work, and demand-driven candidates leading to 1.0.

> **Live-network warning:** use live commands only on systems and networks you
> own or are explicitly authorized to test. PacketcraftR's opt-in flags are
> technical policy controls, not permission to target a network.

## Quick start

These examples are offline and work in every feature profile:

```console
packetcraftr protocols
packetcraftr protocols ipv4
packetcraftr --output hex build --packet 'raw(text=hello)'
packetcraftr --output json dissect --link-type 228 \
  --hex '450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f'
packetcraftr --output ndjson read capture.pcapng --max-frames 100
```

From a source checkout, build a published packet document with:

```console
packetcraftr --output json build \
  --packet-file examples/documents/packet-ipv4-udp.json
```

Use `packetcraftr --help` to discover commands,
`packetcraftr <COMMAND> --help` for current options and limits, and
`packetcraftr protocols [PROTOCOL]` for the authoritative built-in protocol
catalog.

| Area | Commands |
| --- | --- |
| Packet and capture files | `build`, `dissect`, `protocols`, `read` |
| Offline analysis | `expert`, `follow`, `stats`, `fuzz` (default mode) |
| Native inspection and planning | `interfaces`, `routes`, `plan` |
| Live workflows | `send`, `exchange`, `capture`, `replay`, `scan`, `traceroute`, `dns`, `fuzz --live` |

## Install

[GitHub releases](https://github.com/tyk-swe/pcr/releases) provide Linux x86-64,
macOS x86-64 and Arm64, and Windows x86-64 MSVC archives. Download the matching
archive and `SHA256SUMS`, verify the checksum, then place `packetcraftr` (or
`packetcraftr.exe`) on `PATH`.

- `all-features` archives include routing, raw Layer 3, and Layer 2
  capture/injection. They require libpcap at runtime on Linux and macOS, or
  Npcap 1.88 on Windows.
- `pcap-free` archives include routing and raw Layer 3 without a
  libpcap/Npcap dependency.

To build from source, install the pinned Rust 1.97.1 toolchain. Rust 1.96 is the
MSRV. The project does not configure a compiler wrapper or linker, so Cargo and
the Rust toolchain use their platform defaults. All-feature Linux builds also
require libpcap development files such as `libpcap-dev`.

```console
cargo build --locked --release -p packetcraftr-cli
./target/release/packetcraftr --help
```

Add `--no-default-features` for an offline-only build or `--all-features` for
all native capabilities. The Cargo manifests and command help are authoritative
for finer-grained feature selection. Missing features, dependencies, or OS
privileges fail closed.

## Documents and output contracts

- Packet JSON/YAML: [`packetcraftr.packet/v1`](schemas/packetcraftr.packet.v1.schema.json)
- Structured command output: [`packetcraftr.output/v1`](schemas/packetcraftr.output.v1.schema.json)
- Published packet and output examples: [`examples/documents`](examples/documents)

The global `--output` option accepts command-specific combinations of `text`,
`json`, `ndjson`, `hex`, `raw`, `pcap`, and `pcapng`. Put it before the command,
for example `packetcraftr --output json stats capture.pcapng`. Unsupported
combinations fail explicitly. Machine and binary formats contain no terminal
colour codes. Streaming commands use NDJSON.

Structured errors include a stable code, kind, message, remediation, and typed
domain context when a source frame, probe, attempt, or fuzz case is known. The
v1 schema and checked-in examples are the contract reference.

Scan, traceroute, DNS, fuzz, and exchange NDJSON are execution-time streams,
not renderings of completed aggregate results. Scan and traceroute publish a
probe after its current batch evidence is final; stopping at that callback does
not undo sends already confirmed in the batch. DNS publishes each attempt,
accepted or rejected record, and retained undecodable frame before a later
retry. Fuzz publishes each final case in deterministic case order. Exchange
publishes a send after the packet-I/O receipt is confirmed, capture evidence
after its classification is final, and unanswered requests only after capture
completion. A diagnostic event is published when an operation-wide warning
becomes final.

The corresponding Rust event callbacks execute on a bounded one-event worker.
The operation waits for each callback result, aborts later work on a classified
callback error, and charges backpressure to the same finite operation deadline.
If a callback never returns, the live operation still reaches its deadline,
shuts capture down, and returns without waiting for that worker. Callbacks must
therefore own their state and tolerate the worker finishing after the operation
has returned. Every successful stream has one final complete record; a later
failure preserves earlier records and replaces completion with one typed error
at the next envelope sequence when the output sink remains writable.

`dissect --output json` always emits one aggregate document. Its result contains
`matched` and `dissection`; a filter no-match is a successful document with
`matched: false` and `dissection: null`, while a match has `matched: true` and
the complete dissection.

## Library layout

Rust users normally depend on the `packetcraftr` facade. It re-exports packet
mechanics as `core`, offline capture tools as `analysis`, and provider/native
I/O as `netio`. The core and offline-analysis path has no live-I/O dependency.
Cargo manifests and `cargo metadata` are the source of truth for the package
graph and features. Build API documentation with:

```console
cargo doc --locked --all-features --no-deps --open
```

## Live-network safety

Live operations enforce several independent boundaries:

- Globally routable and multicast destinations are denied by default.
  `--allow-public-destinations` is a command opt-in, not legal authorization or
  an OS privilege grant.
- Hostnames require `--allow-hostname-resolution`; resolution is bounded and
  every returned address must pass destination policy.
- Permissive or malformed live packets require both the operation-specific
  opt-in and `--allow-permissive-packets` where those flags are exposed.
- Packet, byte, duration, queue, and evidence budgets remain active. Active
  capture-backed workflows establish capture readiness before transmission.
- Interface identity, route consistency, source ownership, MTU, and final wire
  bytes are checked again at the native boundary.

Only applicable commands expose each control. Read that command's `--help`
instead of copying flags between workflows. For `capture`, `--capture-filter`
is resolver-free native BPF applied before PacketcraftR's queue and budgets;
`--filter` is applied after capture, so rejected frames have already consumed
those resources.

Native operations also need the minimum OS permission for the selected path:

| Platform | Requirements and notable limits |
| --- | --- |
| Linux | Layer 2 and raw Layer 3 usually require root or `CAP_NET_RAW`; complete builds need libpcap. Containers must expose the interface, route, and capability in the same namespace. |
| macOS | Layer 2 needs libpcap and BPF-device access; raw sockets usually require root. Complete-header raw IPv6 transmission is unsupported. |
| Windows | Layer 2 needs Npcap 1.88; raw sockets usually require administrator rights. Windows may reject raw UDP with a non-local source. |

## Contributing, security, and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance. Report
suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

PacketcraftR is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE).
