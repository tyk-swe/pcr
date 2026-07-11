# PacketcraftR

[![CI](https://github.com/tyk-swe/pcr/actions/workflows/ci.yml/badge.svg)](https://github.com/tyk-swe/pcr/actions/workflows/ci.yml)

PacketcraftR is a Rust framework and command-line toolkit for constructing,
dissecting, capturing, replaying, and testing network packets. It combines
arbitrary protocol stacks, reflective fields, exact wire-byte preservation,
bounded parsers, and explicit native-I/O boundaries.

Use PacketcraftR only on systems and networks you own or are authorized to
test. Live workflows enforce traffic policy and finite limits, but they do not
grant authorization.

## Capabilities

- Build and dissect ordered Ethernet, VLAN, ARP, IPv4, IPv6, ICMP, TCP, UDP,
  raw, padding, and malformed layers.
- Extend the immutable protocol registry with application-defined Rust codecs
  and response matchers.
- Read and write bounded PCAP and PCAPNG streams while preserving link types,
  timestamps, interface metadata, lengths, and captured bytes.
- Plan routes and perform typed Layer 2 or Layer 3 I/O through injectable or
  native providers.
- Run replay, scan, traceroute, DNS, and deterministic field-aware fuzzing
  through the same packet, policy, capture, and output contracts.
- Emit text, JSON, NDJSON, hexadecimal, raw, PCAP, or PCAPNG output where the
  selected command supports it.

The [protocol matrix](docs/protocol-support.md), [platform matrix](docs/platform-support.md),
and [CLI contract](docs/cli-contract.md) define the exact supported surface.

## Install

PacketcraftR uses Rust 1.96 and is installed from its source workspace:

```console
git clone https://github.com/tyk-swe/pcr.git
cd pcr
rustup toolchain install 1.96.0 --profile minimal --component clippy,rustfmt
cargo install --locked --path . --no-default-features
```

The portable profile supports packet processing, documents, offline capture,
and custom providers without native networking dependencies. Build native
providers explicitly when needed:

```console
cargo build --locked --features native-route
cargo build --locked --features native-route,native-layer2,native-layer3
```

Linux and macOS Layer 2 builds require libpcap. Windows Layer 2 builds load a
system-installed Npcap runtime dynamically. Real Npcap-backed capture,
injection, and dependent live workflows on Windows are experimental; portable
processing and native route discovery do not require Npcap. See the
[installation guide](docs/installation.md) and [platform matrix](docs/platform-support.md)
for dependencies and privileges.

## CLI

The command surface is:

```text
build       dissect      plan         send         exchange
capture     read         replay       scan         traceroute
dns         fuzz         interfaces   routes
```

Build a packet from an expression:

```console
packetcraftr build \
  --packet 'ether()/ipv4(dst="192.0.2.10")/tcp(dport=443)/raw(hex="010203")' \
  --output hex
```

Read a capture as structured records:

```console
packetcraftr read --input traffic.pcapng --output ndjson
```

Each packet-taking command accepts exactly one recipe source: `--packet`,
`--packet-file`, or standard input. JSON and YAML packet documents use the
`packetcraftr.packet/v1` schema. Aggregate JSON and streaming NDJSON use the
typed `packetcraftr.output/v1` envelope.

Run `packetcraftr --help` for command options and finite defaults. The
[executable examples](docs/cli-examples.md) cover every command.

## Rust API

Applications normally depend on the root `packetcraftr` façade. The component
crates are internal workspace boundaries and are not published independently.

```rust
use packetcraftr::{Packet, Raw};

let mut packet = Packet::new();
packet.push(Raw::new(vec![0xde, 0xad, 0xbe, 0xef]));

assert_eq!(packet.len(), 1);
assert_eq!(
    packet.get::<Raw>().unwrap().bytes.as_ref(),
    &[0xde, 0xad, 0xbe, 0xef]
);
```

The [Rust API contract](docs/public-api.md) documents ownership, extension,
error, resource-bound, and native-provider rules.

## Safety model

- Strict building validates protocol bindings, derived lengths, and checksums.
- Permissive or malformed live bytes require explicit opt-ins in addition to
  traffic-policy authorization.
- Packet documents, captures, queues, retries, retained evidence, and live
  operations have finite defaults and validated maxima.
- Route, link-mode, dependency, privilege, policy, send, capture, and cleanup
  failures are typed; providers never silently change the requested mode.
- Human output escapes terminal controls. Machine output retains structured
  values through JSON escaping.

## Documentation

- [CLI contract](docs/cli-contract.md) and [examples](docs/cli-examples.md)
- [Rust API](docs/public-api.md), [protocols](docs/protocol-support.md), and
  [schemas](schemas/README.md)
- [Platform support](docs/platform-support.md) and [capture/replay](docs/capture-replay.md)
- [Scan](docs/scan.md), [traceroute](docs/traceroute.md), [DNS](docs/dns.md),
  and [fuzzing](docs/fuzz.md)
- [Architecture decisions](docs/adr/README.md)

## Development

Run the portable checks without native privileges:

```console
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --no-default-features -- -D warnings
cargo test --locked --workspace --all-targets --no-default-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps --no-default-features
bash scripts/check-architecture.sh
```

Schema validation additionally needs the pinned Python tool:

```console
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -r scripts/requirements.txt
PATH="$PWD/.venv/bin:$PATH" bash scripts/check-schemas.sh
python3 scripts/validate-fixture-corpus.py
```

The fixture corpus is immutable during ordinary tests; see its
[provenance policy](tests/fixtures/README.md) before changing it.

PacketcraftR is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE).
