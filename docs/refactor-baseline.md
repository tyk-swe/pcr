# Refactor Baseline

This document records the behavior and public surface that the modernization
work is intended to preserve.

## Public Surface Inventory

The crate root exports:

| Item | Status |
| --- | --- |
| `run_cli` | Public CLI entry point. |
| `PacketcraftApp` | Public application bootstrap and dispatch type. |
| `app` | Public module. |
| `engine` | Public module. |
| `output` | Public module. |
| `rules` | Public module. |
| `cli` | Public `#[doc(hidden)]` compatibility module. |
| `network` | Public `#[doc(hidden)]` compatibility module. |
| `util` | Public `#[doc(hidden)]` compatibility module. |

The `test_utils` feature remains a compatibility feature and should not be
removed or folded into default builds during behavior-preserving cleanup.

## Feature Matrix

| Feature | Default | Notes |
| --- | --- | --- |
| `pcap` | No | Enables packet capture/listener support. |
| `scan` | No | Enables experimental scan command and engine paths. |
| `traceroute` | No | Enables experimental traceroute command and engine paths. |
| `fuzz` | No | Enables experimental fuzzing support. |
| `daemon` | No | Enables Unix daemon command handling. |
| `repl` | No | Enables interactive mode and depends on REPL-only async trait boxing plus `pcap`, `scan`, and `traceroute`. |
| `metrics` | No | Enables Prometheus exporter support. |
| `experimental` | No | Bundles scan, traceroute, fuzz, daemon, REPL, and metrics. |
| `test_utils` | No | Exposes test support APIs. |
| `net_integration` | No | Opts into host/network integration tests. |

## Parity Checklist

Modernization changes should preserve:

- CLI command names, flags, defaults, help text intent, and hidden legacy
  one-shot behavior.
- JSON output shape and field names used by CLI and tests.
- Existing error variants and user-facing error strings where tests or callers
  depend on them.
- Daemon text commands and command parsing compatibility.
- Rejection of the legacy rule `options` wrapper.
- TLS 1.0 record compatibility in protocol validation.
- Legacy ICMP payload encoding behavior.
- Feature-gated availability of scan, traceroute, fuzz, daemon, listener,
  metrics, and REPL code paths.
- Ignored host/network integration tests remaining ignored unless explicitly
  requested.

## Validation Matrix

Run the following after each refactor pass:

```sh
cargo fmt --all -- --check
cargo check --all-targets
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --no-default-features
cargo test --all-features
```

Package and documentation validation:

```sh
cargo package --allow-dirty --no-verify --list
cargo doc --no-deps --all-features
```
