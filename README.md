# PacketcraftR

[![CI](https://github.com/tyk-swe/pcr/actions/workflows/ci.yml/badge.svg)](https://github.com/tyk-swe/pcr/actions/workflows/ci.yml)

PacketcraftR is a Rust library and CLI for building, dissecting, capturing, and
testing network packets. Use live networking only on systems and networks you
own or are authorized to test. One Cargo package provides both the
`packetcraftr` library and binary.

## Install

Rust 1.96 is required. The portable build has no native networking dependency:

```console
cargo install --locked --path . --no-default-features
```

Enable native providers when needed:

```console
cargo install --locked --path . \
  --features native-route,native-layer2,native-layer3
```

Linux and macOS Layer 2 builds need libpcap. Windows Layer 2 use needs an Npcap
runtime.

## Use

```console
packetcraftr build \
  --packet 'ether()/ipv4(dst="192.0.2.10")/tcp(dport=443)/raw(hex="010203")' \
  --output hex

packetcraftr read traffic.pcapng --output ndjson
```

Run `packetcraftr --help` for the full command surface.

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

See the [manual](docs/README.md), [changelog](CHANGELOG.md), and versioned
[packet](schemas/packetcraftr.packet.v1.schema.json) and
[output](schemas/packetcraftr.output.v1.schema.json) schemas.

The Rust API is organized into domain namespaces. This API redesign does not
change CLI commands, flags, exit-code behavior, packet bytes, or serialized
output contracts.

## Development

```console
cargo fmt -- --check
cargo check --locked --all-targets --no-default-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

Licensed under [AGPL-3.0-only](LICENSE).
