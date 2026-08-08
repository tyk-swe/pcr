# PacketcraftR

PacketcraftR is a Rust library and command-line tool for exact packet
construction, bounded dissection, capture-file I/O, offline analysis, and
policy-gated live networking.

The current release is `0.4.0`. PacketcraftR is stable but pre-1.0, so Rust
APIs and versioned serialized contracts may change between minor releases.
Review the [changelog](CHANGELOG.md) before upgrading.

Use live networking only on systems and networks you own or are explicitly
authorized to test.

## Capabilities

- Build strict or deliberately permissive packet stacks from expressions,
  JSON, or YAML and emit exact bytes.
- Dissect bounded frames while preserving unknown and malformed bytes with
  diagnostics.
- Read, filter, write, and transcode classic PCAP and PCAPNG files.
- Analyze captures offline with statistics, conversation following, expert
  findings, and bounded IP/TCP reassembly.
- Inspect interfaces and routes, send or replay packets, and run bounded
  exchange, scan, traceroute, DNS, capture, and fuzz workflows.

Run `packetcraftr protocols` for the authoritative built-in protocol list and
`packetcraftr <COMMAND> --help` for current options and limits. Built-ins cover
common capture/link formats, IPv4 and IPv6, control and transport protocols,
tunnels, overlays, and raw or malformed payload preservation.

Packet documents use the
[`packetcraftr.packet/v1` schema](schemas/packetcraftr.packet.v1.schema.json).
Structured results use the
[`packetcraftr.output/v1` schema](schemas/packetcraftr.output.v1.schema.json).
Representative documents are in [`examples/documents`](examples/documents).

## Installation

### Release archives

The [GitHub releases](https://github.com/tyk-swe/pcr/releases) provide Linux
x86-64, macOS x86-64 and Arm64, and Windows x86-64 MSVC archives. Each target
has two variants:

- `all-features` includes native routes, raw Layer 3 transmission, and
  libpcap/Npcap Layer 2 capture and injection.
- `pcap-free` includes native routes and raw Layer 3 transmission without a
  libpcap/Npcap dependency.

Download the archive and `SHA256SUMS`, verify its checksum, extract it, and put
`packetcraftr` (or `packetcraftr.exe`) on `PATH`. All-features archives require
libpcap at runtime on Linux and macOS, or Npcap 1.88 on Windows. Pcap-free
archives do not.

### Build from source

The repository pins Rust 1.97.1; Rust 1.96 is the minimum supported version.
Linux builds require clang and lld. Install libpcap development files (for
example, `libpcap-dev` on Debian/Ubuntu) for an all-feature build.

```console
cargo build --locked --release -p packetcraftr-cli
./target/release/packetcraftr --help
```

The CLI feature profiles are:

| Profile | Cargo arguments after `-p packetcraftr-cli` | Native behavior |
| --- | --- | --- |
| Portable | `--no-default-features` | Offline commands only; native providers fail closed. |
| Default | none | Portable commands plus interface enumeration. |
| Pcap-free | `--no-default-features --features native-route,native-layer3` | Interfaces, passive routes, and raw Layer 3 send/replay. |
| Complete | `--all-features` | Pcap-free behavior plus Layer 2 capture/injection and capture-backed workflows. |

`native-route` is independent. `native-layer2` and `native-layer3` each enable
`native-interfaces`; `native-interfaces` is the default. Features are
package-scoped, and there are no `portable`, `pcap-free`, or `cli` feature
names.

The `packetcraftr` crate is the facade for library consumers. Depend directly
on a domain crate when a smaller capability surface matters; in particular,
`packetcraftr-analysis` is offline-only. Cargo manifests and `cargo metadata`
are the source of truth for the workspace graph.

The dependency layers put `packetcraftr-packet` at the bottom. Offline
`packetcraftr-analysis` and native `packetcraftr-network` depend only on that
packet layer. Policy-gated `packetcraftr-live` builds on all three; the facade
builds on the four domain crates, and the CLI builds only on the facade.
Analysis has no direct or transitive dependency on the network or live layer,
so adding a resolver, route, capture, or transmission seam there requires an
explicit Cargo graph change.

## Quick start

These commands are offline and work in every build profile:

```console
packetcraftr protocols
packetcraftr --output hex build --packet 'raw(text=hello)'
packetcraftr --output json dissect \
  --hex '45000014000000004001f6e7c0000201c6336402'
packetcraftr --output ndjson read capture.pcapng \
  --max-frames 100 --max-bytes 10485760
packetcraftr fuzz --packet 'raw(hex="00")' \
  --seed 9 --cases 4 --strategy bit-flip --field 0.bytes
```

From a source checkout, build a published document with:

```console
packetcraftr --output json build \
  --packet-file examples/documents/packet-ipv4-udp.json
```

For a live lab, replace `eth0` and `192.168.56.10` with an authorized current
interface and private destination:

```console
packetcraftr interfaces
packetcraftr plan \
  --packet 'ipv4(dst=192.168.56.10)/icmpv4(type=8,code=0)' \
  --interface eth0 --link-mode layer3
packetcraftr send \
  --packet 'ipv4(dst=192.168.56.10)/icmpv4(type=8,code=0)' \
  --interface eth0 --link-mode layer3
```

`plan` is passive. `send --link-mode layer3` needs the pcap-free or complete
profile and raw-socket permission. Live capture and capture-backed workflows
need the complete profile, libpcap/Npcap, and capture permission:

```console
packetcraftr capture \
  --packet 'ipv4(dst=192.168.56.53)/udp(dport=53)' \
  --interface eth0 --timeout-ms 1000 \
  --capture-filter 'udp port 53' \
  --filter 'udp.source_port == 53'
```

`--capture-filter` is resolver-free native BPF applied before PacketcraftR's
queue and budgets. `--filter` is PacketcraftR's display language applied after
capture, so rejected frames have already consumed queue and operation budget.

## Live-operation safety

Live commands fail closed at separate authorization boundaries:

- Traffic policy rejects globally routable and multicast destinations by
  default. `--allow-public-destinations` is a per-command opt-in, not legal
  authorization or an OS privilege grant. Every declared and decoded
  route-bearing destination is checked before native I/O.
- Hostnames require `--allow-hostname-resolution`; resolution is bounded by
  `--max-resolved-addresses`, and every result must pass destination policy.
- Permissive or malformed live bytes require both the operation opt-in
  (`--allow-permissive-live` or `--allow-malformed-live`) and
  `--allow-permissive-packets` where the command exposes them.
- Packet, byte, duration, queue, and evidence limits remain active regardless
  of other opt-ins. Capture-backed active workflows establish capture
  readiness before transmitting.
- Interface identity, route consistency, source ownership, MTU, and final wire
  bytes are revalidated at the native boundary.

Only applicable commands expose each flag. Use the command's `--help` rather
than copying flags between operations.

Grant the minimum native permission required:

| Platform | Native requirements and limits |
| --- | --- |
| Linux | Layer 2 and raw Layer 3 normally require root or `CAP_NET_RAW`. All-features needs libpcap; routes use route netlink. Containers must expose the interface, route, and capability in the same namespace. |
| macOS | Layer 2 needs libpcap and BPF-device access; raw sockets normally require root. Exact complete-header raw IPv6 transmission is unsupported, so use an authorized Layer 2 path. |
| Windows | Layer 2 needs Npcap 1.88, and raw sockets require administrator rights. PacketcraftR loads Npcap from the system Npcap directory. Windows may reject raw UDP whose source is not assigned locally. |

## Output and diagnostics

Global `--output` supports command-specific combinations of `text`, `json`,
`ndjson`, `hex`, `raw`, `pcap`, and `pcapng`. Machine and binary formats never
contain terminal styling; `--color auto|always|never` affects only human-facing
output. Unsupported format/command combinations fail explicitly.

Add `--output json` before a command for classified errors with a stable code,
kind, message, and remediation. Common failures are:

| Error | Check |
| --- | --- |
| `capability.missing_dependency` | Install libpcap/Npcap or use a pcap-free path. |
| `capability.privilege` | Grant the minimum platform capture/raw-socket permission. |
| `capability.route` | Enable `native-route`; use pcap-free or complete for the CLI. |
| `io.interface_not_found`, `io.route_selection` | List interfaces again and verify name/index, source, family, and route constraints. |
| `io.capture`, `io.capture_readiness` | Verify the complete profile, interface state, dependency, and capture permission. |
| `policy.public_destination` | Prefer an authorized private lab target or explicitly opt in; hostnames also require resolution authorization. |

## Contributing, security, and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and review guidance.
Report suspected vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

PacketcraftR is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE).
