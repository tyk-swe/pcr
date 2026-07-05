# Repository Guidelines

## Project Structure & Module Organization

`packetcraftr` is a Rust 2021 CLI/library crate. `src/main.rs` stays thin, and
`src/lib.rs` exposes the entrypoint. Keep CLI parsing in `src/cli`, startup and
dependency wiring in `src/app`, request/spec/policy types in `src/domain`,
execution orchestration in `src/engine`, packet I/O and protocol code in
`src/network`, user-facing tools in `src/tools`, automation logic in `src/rules`,
rendering in `src/output`, and shared helpers in `src/util`. Tests live beside
implementation in `#[cfg(test)] mod tests`; there is no top-level `tests/`
directory.

## Build, Test, and Development Commands

- `cargo build` builds the default crate with the `traceroute` feature enabled.
- `cargo run -- --help` shows the stable CLI surface.
- `cargo run -- dry-run -d 127.0.0.1 udp --dport 9 --data hello` is a safe local
  smoke check.
- `cargo build --features experimental` enables `scan`, `fuzz`, `daemon`, `repl`,
  and `metrics`; add `pcap` when working on capture or listener paths.
- `cargo test` runs the inline unit and async tests.
- `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings`
  enforce formatting and lint cleanliness.

## Coding Style & Naming Conventions

Use the pinned toolchain in `rust-toolchain.toml` (`1.96.0`). Formatting follows
`rustfmt.toml`: Rust 2021, 100-column width, Unix newlines. Match existing Rust
naming: `snake_case` for functions and modules, `PascalCase` for types, and
`SCREAMING_SNAKE_CASE` for constants. Preserve existing `#[cfg(feature = "...")]`
boundaries when changing optional behavior.

## Testing Guidelines

Add tests in the same file as the code they cover. Use `#[test]` for synchronous
logic and `#[tokio::test]` for engine, CLI, and tool flows. Prefer deterministic
assertions over live network traffic, and feature-gate tests that depend on
`pcap`, daemon mode, or experimental tools.

## Commit & Pull Request Guidelines

Recent history mostly uses `(<type>): <imperative summary>`, for example
`(fix): harden runtime error handling` and `(test): expand deterministic
coverage`. Keep commits single-purpose. PR descriptions should explain the
behavior change, list commands run, call out affected feature flags, and include
terminal output only when CLI behavior changes.

## Security & Configuration Tips

Raw packet send paths may require root or `CAP_NET_RAW`. Do not commit local
interface names, packet captures, generated rule files, or machine-specific
socket paths.
