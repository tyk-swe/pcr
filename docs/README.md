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

Commands that accept packet recipes require exactly one source: `--packet`,
`--packet-file`, or non-empty piped standard input. `dissect` instead accepts
`--hex`, `--file`, or raw standard input; `read` and `replay` take capture
paths. Expressions compose layers with `/`:

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
The package architecture does not alter command names, flags, exit-code
behavior, packet bytes, field ordering, omission rules, or either versioned
schema identifier.

Supported protocol layers are Ethernet, VLAN (802.1Q and 802.1ad), ARP, IPv4,
IPv6, IPv6 hop-by-hop/destination/fragment/SRH extensions, ICMPv4, ICMPv6,
TCP, UDP, BSD NULL/LOOP, Linux SLL/SLL2, raw data, padding, and explicit
malformed data. Capture roots include DLT/LINKTYPE 0, 1, 12, 101, 108, 113,
228, 229, and 276; unknown roots remain raw bytes.

## Rust API

The single `packetcraftr` package provides a library and binary. Its public Rust
API is grouped by domain: `packet`, `protocol`, `capture`, `net`, `session`,
`client`, `workflow`, `output`, and `error`. Types use concise names inside
their owning namespace; for example, build options are
`packet::build::Options` and an offline capture record is `capture::Frame`.

```rust
use std::sync::Arc;

use packetcraftr::{
    packet::{build, layer::Raw, Packet},
    protocol,
};

let registry = Arc::new(protocol::builtin::registry()?);
let mut value = Packet::new();
value.push(Raw::new(vec![0xde, 0xad, 0xbe, 0xef]));
let built = build::Builder::new(registry).build(
    value,
    build::Context::default(),
    build::Options::default(),
)?;
assert_eq!(built.bytes.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Applications extend packet handling through `packet::codec::Codec`,
`packet::registry::Module`, and `packet::matcher::Matcher`. The registry at
`protocol::builtin::registry()` installs the built-in protocols in a
deterministic order. Provider traits under `net::route`, `net::neighbor`,
`net::capture`, and `net::transmit` support portable tests without platform
handles or network privileges. Reassembly under `session::fragment` and
`session::tcp` remains explicit and caller-owned.

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

The core local checks are:

```console
cargo fmt -- --check
cargo check --locked --all-targets --no-default-features
cargo check --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

CI also installs `cargo-deny` 0.19.7 and runs `cargo deny check`. The temporary
`RUSTSEC-2024-0436` exception in `deny.toml` expires on 2026-10-12, and CI
requires it to be reviewed before then.

All-feature Linux builds need the libpcap development package. CI runs both
feature-profile checks, Clippy, and all-feature tests on Linux x86-64, macOS
x86-64 and arm64, and Windows MSVC. Formatting runs on Linux, while Windows
also runs `cargo test --locked --lib`.
