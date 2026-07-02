# Repository Guidelines

## Project Structure & Module Organization

`packetcraftr` is a Rust 2021 CLI/library crate. `src/main.rs` delegates to
`packetcraftr::run_cli`, while `src/lib.rs` exposes the application entry point.
Keep CLI parsing in `src/cli`, bootstrap and dispatch wiring in `src/app`, domain
models and packet specs in `src/domain`, orchestration in `src/engine`, packet I/O
and protocol logic in `src/network`, user-facing commands in `src/tools`, rule
automation in `src/rules`, output formatting in `src/output`, and shared helpers
in `src/util`. Tests are embedded next to the code under `mod tests`; there is no
top-level `tests/` directory.

## Build, Test, and Development Commands

- `cargo build` builds the default crate with the default `traceroute` feature.
- `cargo test` runs the inline unit and async tests.
- `cargo fmt --check` verifies formatting using `rustfmt.toml`.
- `cargo clippy --all-targets --all-features -- -D warnings` checks all feature
  combinations with the pinned Clippy toolchain.
- `cargo run -- --help` prints CLI usage. Enable optional tools with features,
  for example `cargo run --features experimental -- --help`.

## Coding Style & Naming Conventions

Use the pinned Rust toolchain in `rust-toolchain.toml` and respect the MSRV in
`clippy.toml`. Formatting is Rust 2021 with Unix newlines and 100-column width.
Follow existing Rust naming: `snake_case` functions/modules, `PascalCase` types,
and `SCREAMING_SNAKE_CASE` constants. Preserve feature gates such as `scan`,
`fuzz`, `daemon`, `repl`, `pcap`, and `metrics` when adding optional behavior.

## Testing Guidelines

Add tests in the same file as the behavior they cover, under `#[cfg(test)] mod
tests`. Use `#[test]` for synchronous logic and `#[tokio::test]` for async engine
or tool flows. Prefer deterministic unit coverage for parsing, validation,
planning, and output formatting; avoid tests that require live network access
unless they are explicitly feature-gated and isolated.

## Commit & Pull Request Guidelines

Use lowercase type labels in parentheses followed by a colon and imperative
summary, for example `(feat): add DNS retry policy`, `(test): expand traceroute
coverage`, or `(docs): update contributor guide`. Common types are `(feat)`,
`(fix)`, `(test)`, `(docs)`, `(refactor)`, and `(chore)`. Keep commits focused on
one change, and use the same format for PR titles. PR descriptions should explain
the behavior change, list commands run, mention affected feature flags, link
related issues, and include terminal output or screenshots only when CLI behavior
changes.

## Security & Configuration Tips

Packet sending, capture, daemon, and pcap flows may require elevated privileges or
platform-specific capabilities. Do not commit local interface names, packet
captures, generated secrets, or environment-specific daemon paths.
