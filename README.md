# PacketcraftR

[![CI](https://github.com/tyk-swe/pcr/actions/workflows/ci.yml/badge.svg)](https://github.com/tyk-swe/pcr/actions/workflows/ci.yml)

PacketcraftR is a Rust packet-construction, dissection, capture, and network-testing framework with a first-class CLI. The v0.2 line is rebuilding the project around arbitrary layer stacks, reflective fields, an explicit protocol registry, exact wire-byte preservation, and bounded parsers.

> **Alpha warning:** `0.2.0-alpha.1` is an intentionally breaking development release. The Rust API, packet documents, output documents, and command-line interface are not stable until the beta API freeze. Do not depend on v0.1 flags or JSON shapes surviving the alpha series.

PacketcraftR is licensed under the [GNU Affero General Public License v3.0 only](LICENSE) and has a Rust 1.96 minimum supported Rust version (MSRV) throughout the v0.2 series.

## Project status

This checkout contains the new portable v0.2 kernel and CLI only. The table describes the alpha checkpoint, not the final v0.2 promise.

| Area | Alpha status |
| --- | --- |
| Ordered `Packet`, object-safe `Layer`, reflective schemas and field values | Available as an alpha API |
| Immutable `ProtocolRegistry`, external codecs and deterministic bindings | Available as an alpha API |
| Strict/permissive generic building, layouts, and diagnostics | Available as an alpha API; built-in protocol coverage is incomplete |
| Bounded dissection with raw/malformed preservation | Available as an alpha API; built-in protocol coverage is incomplete |
| Runtime-neutral captured-frame records and offline capture I/O | Available as a streaming, pure-Rust alpha API and through `read` |
| Packet expressions and `packetcraftr.packet/v1` documents | Available with bounded JSON/YAML parsing |
| v0.2 `build`, `dissect`, `read`, and `interfaces` commands | Available; all final command names are reserved in `--help` |
| Routing, neighbor discovery, live send/capture, and exchange | Injectable planning/client/session APIs are available; native adapters and CLI workflows are later alphas |
| Reassembly, templates, scans, traceroute, DNS, and fuzzing | Bounded fragment/TCP stages and templates are available; tool workflows are later alphas |
| Broad built-in protocol catalog and extracted component crates | Beta milestone |

Run `packetcraftr --help` for the commands implemented in this checkpoint. Unavailable final command names return the capability exit code instead of falling through to a legacy command.

## Design overview

A `Packet` is exactly one ordered wire stack. It contains layers and their fields, but no interface, route, listener, retry, logging, or transmission settings. Those belong to workflow options or a high-level client.

```text
packet recipe / Rust Packet
            |
            v
     immutable registry
       /           \
      v             v
strict/permissive   bounded
    builder        dissector
      |               |
      v               v
 exact bytes       packet + original bytes
 layouts           layouts
 diagnostics       diagnostics
```

The emerging public façade is centered on:

- `Packet`, `Layer`, `LayerSchema`, `FieldSchema`, and `FieldValue` for typed and reflective editing.
- `WireValue<T>` for dependent values that are automatic, exact, or deliberately raw.
- `RegistryBuilder` and immutable `ProtocolRegistry` values instead of global registration.
- `Builder` and `Dissector`, which return exact bytes, materialized packets, byte layouts, and typed diagnostics.
- `Raw`, `Padding`, and `MalformedLayer`, which retain content that cannot be decoded safely.
- `CapturedFrame`, which retains link type, timestamps, captured/wire lengths, interface metadata, and all bytes up to the snap length. Its fallible constructors reject lengths that cannot represent the supplied bytes, and dissection revalidates records before reading them. Exchange results retain bounded, undecodable frames in this raw form instead of discarding their evidence.

A minimal alpha API shape looks like this:

```rust
use packetcraftr::{Packet, Raw};

let mut packet = Packet::new();
packet.push(Raw::new(vec![0xde, 0xad, 0xbe, 0xef]));

assert_eq!(packet.len(), 1);
assert_eq!(packet.get::<Raw>().unwrap().bytes.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
```

External Rust crates can implement `Layer`, `LayerCodec`, and `ProtocolModule`, then register the module through a `RegistryBuilder`. Registration is compile-time Rust composition: v0.2 deliberately has no native dynamic-library plugin system and no global mutable registry.

The architecture decisions are recorded in [docs/adr](docs/adr/README.md).

## Building from source

Install Rust 1.96 through `rustup`, then build the portable surface:

```console
rustup toolchain install 1.96.0 --profile minimal --component clippy,rustfmt
cargo build --no-default-features
cargo test --no-default-features
```

The portable packet kernel and offline capture path do not require libpcap. On Linux and macOS, the default `live` feature currently enables interface enumeration without enabling capture or injection. Windows default and `--no-default-features` builds are deliberately portable: they do not resolve `pnet`, link `Packet.lib`, or require Npcap. The Windows `interfaces` command reports a capability error until the dedicated native adapter is available. Later capture and injection adapters will require libpcap on Linux/macOS and Npcap on Windows, plus the relevant operating-system privileges.

See the [platform and capability matrix](docs/platform-support.md) before depending on a live workflow.

## CLI direction

The final v0.2 command set is:

```text
build       dissect      plan         send         exchange
capture     read         replay       scan         traceroute
dns         fuzz         interfaces   routes
```

One packet recipe comes from exactly one of `--packet`, `--packet-file`, or standard input. A concise expression is intended for one-off work:

```console
packetcraftr build --packet 'ether()/ipv4(dst="192.0.2.10")/tcp(dport=443)/raw(hex="010203")'
```

Versioned JSON or YAML documents are intended for generated, complex, or reviewable packets. Workflow settings such as interface, timeout, output format, replay timing, or traffic policy never belong inside a packet document. The versioned [packet and output JSON Schemas](schemas/README.md) and [example documents](examples/documents) are included in the repository.

Machine-readable aggregate output uses the `packetcraftr.output/v1` envelope. Streaming commands use NDJSON. Raw and hexadecimal formats always refer to the complete captured or built frame, never payload-only bytes.

The [v0.1 to v0.2 migration guide](docs/migration-v0.1-to-v0.2.md) maps common legacy commands and explains removed subsystems.

## Safety model

Packet construction and transmission can disrupt networks or violate policy. Only use PacketcraftR against systems and networks where you have explicit authorization.

The v0.2 contracts are:

- Planning may inspect local route and interface state, but never performs ARP, NDP, capture, or transmission.
- Ethernet/VLAN intent never silently falls back to Layer 3.
- Off-link neighbor resolution targets the route gateway, not the final destination.
- Complete non-IP Layer 2 packets use passive, explicit-interface selection; they do not invent an IP route or trigger neighbor resolution.
- A spoofed packet source is kept distinct from the interface-owned source used for ARP or NDP.
- Strict builds validate dependent fields and layer bindings.
- Permissive builds retain requested inconsistencies and emit diagnostics. Sending their bytes requires a second, explicit live-transmission opt-in.
- A known discriminator (for example, IPv4 EtherType) cannot label a `Raw` child in strict mode when the registry requires a typed child. Unknown discriminators can still preserve opaque bytes; permissive mode reports the known-discriminator mismatch and requires the live opt-in.
- Decode-only multiplexing roots must explicitly admit each concrete protocol they return. The raw-IP root therefore continues registry binding from the decoded IPv4 or IPv6 layer rather than misrepresenting it as a generic link layer.
- Padding records an explicit ownership boundary when its bytes sit outside an IPv4, IPv6, or UDP declared length or the fixed ARP body. Invalid or unsupported boundaries fail strict builds; preserved network/datagram trailers emit diagnostics and require the live opt-in.
- Synthesized or resolved Layer 2 bytes are part of the exact built frame. Byte-policy checks include that envelope before neighbor traffic, and a backend-reported partial send is a typed failure.
- Route MTU checks measure the actual built network-layer byte span instead of trusting permissive wire length fields. Oversized packets fail before neighbor discovery or live I/O and require an explicit fragmentation transform.
- Capture is ready before an exchange sends its first frame, and one owned receive stream routes every frame rather than silently draining traffic.
- Exchange always attempts to stop and join its capture session after readiness, send, receive, or timeout failures. If the operation and cleanup both fail, both errors remain visible.
- Unsupported link types and unknown payloads remain explicit raw data; unsupported combinations produce typed errors.
- Display truncation never truncates the captured bytes stored in a result.

Alpha releases do not yet implement every final guard on every execution path. Inspect the plan and built bytes, use isolated labs, set finite budgets, and prefer offline operations while the live APIs are under development.

Default resource ceilings are intentionally finite:

| Resource | Default ceiling |
| --- | ---: |
| Decoded layers | 64 |
| Offline packet or PCAPNG block | 16 MiB |
| PCAPNG interfaces per section | 4,096 |
| PCAPNG metadata blocks before the next packet | 4,096 |
| Concrete packets per template expansion | 10,000 |
| Queued captured or unsolicited frames | 4,096 |
| Retained captured bytes per exchange | 256 MiB |
| Reassembly flows | 8,192 |
| Buffered/history bytes per reassembly flow | 1 MiB |
| Aggregate reassembly bytes | 256 MiB |
| Fragments per datagram | 256 |
| Pending TCP segments per flow | 4,096 |
| Fragment expiry | 30 seconds |
| Idle TCP-flow expiry | 2 minutes |

All parsers and queues must use checked arithmetic, honor configurable bounds, and fail closed.

## Development

The pull-request checks exercise formatting and the default, no-default-feature, and all-feature profiles on Linux. Default and no-default profiles also compile and test on macOS. Windows CI names and tests both profiles as portable and verifies that neither dependency graph contains `pnet` or its `Packet.lib` link requirement.

```console
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo clippy --no-default-features --all-targets -- -D warnings
cargo test --no-default-features --all-targets
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features --all-targets
RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps
cargo package --locked
```

Tests never rewrite authoritative packet fixtures. Read the [fixture and provenance policy](tests/fixtures/README.md) before adding or replacing capture data.

Security-sensitive findings should follow [SECURITY.md](SECURITY.md), not a public issue.

## Scope and non-goals

v0.2 targets Rust developers and network engineers who need packet-laboratory primitives and structured CLI results. It does not provide Python bindings, dynamic-library plugins, a rules engine, daemon, REPL, embedded Prometheus server, full TCP/IP endpoint stack, TLS decryption, or an intrusion-prevention service.

## License

Copyright (C) 2026 tyk-swe.

PacketcraftR is distributed under the [AGPL-3.0-only](LICENSE) license. There is no warranty; see the license for details.
