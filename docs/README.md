# PacketcraftR manual

## Builds

The default build enables portable interface enumeration. A build with
`--no-default-features` retains packet construction, dissection, documents,
capture-file I/O, replay planning, and injectable providers without native
network access.

| Feature | Capability |
| --- | --- |
| `live` | System interface enumeration |
| `native-route` | System routes and source selection |
| `native-layer2` | Live Layer 2 capture and injection |
| `native-layer3` | Raw IPv4 and IPv6 transmission |

Linux and macOS Layer 2 builds require libpcap. Windows loads Npcap at runtime;
Npcap-backed live I/O is experimental. Live capture and transmission normally
require administrator, root, raw-socket, or packet-device privileges. Prefer
the smallest feature set and privilege level that supports the operation.

## CLI

The commands are:

| Area | Commands |
| --- | --- |
| Packet processing | `build`, `dissect`, `plan` |
| Capture and I/O | `send`, `exchange`, `capture`, `read`, `replay` |
| Tools | `scan`, `traceroute`, `dns`, `fuzz` |
| System discovery | `interfaces`, `routes` |

Packet-taking commands accept one source: `--packet`, `--packet-file`, or
standard input. Expressions compose layers with `/`:

```console
packetcraftr build \
  --packet 'ether()/ipv4(dst="192.0.2.10")/udp(dport=53)/raw(hex="0102")' \
  --output hex

packetcraftr dissect --link-type 1 --file frame.bin --output json
packetcraftr read trace.pcapng --output ndjson
packetcraftr fuzz --packet 'ipv4()/udp()/raw(hex="00")' --cases 16 --output json
```

Use `packetcraftr <command> --help` for command-specific formats, bounds, and
native requirements. JSON/YAML packet files use
[`packetcraftr.packet/v1`](../schemas/packetcraftr.packet.v1.schema.json).
Machine-readable results use
[`packetcraftr.output/v1`](../schemas/packetcraftr.output.v1.schema.json).

Supported protocol layers are Ethernet, VLAN (802.1Q and 802.1ad), ARP, IPv4,
IPv6, IPv6 hop-by-hop/destination/fragment/SRH extensions, ICMPv4, ICMPv6,
TCP, UDP, BSD NULL/LOOP, Linux SLL/SLL2, raw data, padding, and explicit
malformed data. Capture roots include DLT/LINKTYPE 0, 1, 12, 101, 108, 113,
228, 229, and 276; unknown roots remain raw bytes.

## Rust API

Applications normally use the root `packetcraftr` crate. The workspace crates
separate the packet model, protocols, I/O, and session stages but are not
independent distribution units.

```rust
use packetcraftr::{default_registry, BuildContext, BuildOptions, Builder, Packet, Raw};
use std::sync::Arc;

let registry = Arc::new(default_registry()?);
let mut packet = Packet::new();
packet.push(Raw::new(vec![0xde, 0xad, 0xbe, 0xef]));
let built = Builder::new(registry).build(
    packet,
    BuildContext::default(),
    BuildOptions::default(),
)?;
assert_eq!(built.bytes.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`ProtocolRegistry::builder()` accepts application-defined codecs and matchers.
I/O traits accept injected route, neighbor, capture, and transmission providers,
so portable tests do not need platform handles or network privileges.

## Safety

- Live targets must pass the traffic policy before route lookup or I/O.
- Malformed or permissive packets require explicit opt-ins for live use.
- Parsers, captures, retries, queues, templates, and retained evidence have
  finite validated limits.
- Requested Layer 2 or Layer 3 modes fail explicitly; providers do not silently
  fall back to another transmission mode.
- Machine output preserves typed errors and exact bytes; terminal text escapes
  control characters.

## Development

The CI-equivalent checks are:

```console
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --no-default-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

All-feature Linux builds need the libpcap development package. The same checks
run on Linux, macOS, and Windows in CI.
