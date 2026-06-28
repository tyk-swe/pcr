# PacketcraftR

PacketcraftR is a Rust toolkit for building, previewing, transmitting, and
automating crafted network packets in authorized lab and protocol-development
environments.

The stable CLI surface focuses on deterministic dry-run previews, packet
validation, and finite transmission planning. Operational tools such as scan,
traceroute, daemon mode, metrics, fuzzing, and the interactive REPL are enabled
through Cargo features.

## Quick Start

Preview a UDP packet without transmitting it:

```sh
cargo run -- dry-run -d 127.0.0.1 --data hello udp --dport 9
```

Request JSON output for automation:

```sh
cargo run -- --output-format json dry-run -d 127.0.0.1 --data hello udp --dport 9
```

Build all optional tools:

```sh
cargo build --all-features
```

## Feature Flags

PacketcraftR's default feature set is intentionally empty.

| Feature | Enables |
| --- | --- |
| `pcap` | Packet capture/listener support through `pcap`. |
| `scan` | Experimental scan commands and engine paths. |
| `traceroute` | Experimental traceroute commands and engine paths. |
| `fuzz` | Experimental fuzzing support. |
| `daemon` | Daemon command handling on Unix platforms. |
| `repl` | Interactive REPL plus `pcap`, `scan`, and `traceroute`. |
| `metrics` | Prometheus metrics exporter. |
| `experimental` | Convenience bundle for scan, traceroute, fuzz, daemon, REPL, and metrics. |
| `test_utils` | Test support exports for integration tests. |
| `net_integration` | Opt-in host/network integration tests. |

## Library Surface

The public crate entry points are `run_cli` and `PacketcraftApp`. The crate also
exports `engine`, `output`, and `rules` as public modules. The `cli`, `network`,
and `util` modules are public but marked `#[doc(hidden)]` for compatibility with
existing tests and downstream tooling.

Behavior-preserving refactors should keep CLI flags, JSON output, error text,
feature gates, and public exports stable unless an explicit API migration is
approved.
