# Repository Guidelines

## Project Structure & Module Organization

This Rust 2024 workspace has four crates: `packetcraftr-core` for packets and offline analysis, `packetcraftr-netio` for native I/O, `packetcraftr` for policy-gated workflows, and `packetcraftr-cli` for commands and rendering. Unit tests sit beside modules; integration tests live under `crates/*/tests/`. Keep `schemas/` synchronized with `examples/documents/`.

PacketcraftR is intended for protocol engineering, interoperability testing, and authorized network diagnostics. Keep examples and tests on loopback, documentation address ranges, or isolated fixtures; preserve the live-operation authorization and finite-budget gates.

## Build, Test, and Development Commands

Rust 1.97.1 is pinned (MSRV 1.96). Linux all-feature builds require `libpcap-dev`.

- `cargo build --locked`: build the workspace.
- `cargo run -p packetcraftr-cli -- --help`: exercise the CLI.
- `cargo nextest run --locked --workspace`: run tests; repeat with `--no-default-features` and `--all-features` when affected.
- `cargo test --locked --workspace --all-features --doc`: run doctests, which nextest omits.
- `cargo fmt --all -- --check`; `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`: check style and lints.
- `cargo deny check`: enforce dependency policy.

## Coding Style & Naming Conventions

Use `rustfmt` defaults (four-space indentation). Name modules, functions, and tests in `snake_case`; types and traits in `UpperCamelCase`; constants in `SCREAMING_SNAKE_CASE`. Prefer checked conversions. Keep `unsafe` in `packetcraftr-netio/src/platform/`, with a specific `SAFETY` explanation, and preserve the acyclic crate dependency direction.

## Testing Guidelines

Use Rust's test framework through cargo-nextest 0.9.143. Put unit tests in `mod tests` and public contracts in descriptive integration files such as `reassembly_contracts.rs`. Name tests after observable behavior and cover regressions across affected feature profiles. No numeric coverage target is configured.

## Commit & Pull Request Guidelines

Use focused Conventional Commits, for example `fix(reassembly): handle stream timeout`; omit the `packetcraftr-` prefix from scopes. Mark breaking changes with `!` and a `BREAKING CHANGE:` footer. PRs need one responsibility, a linked issue, impact notes, and exact validation results. Update `[Unreleased]` for user-visible changes, synchronize schemas with examples, and request applicable CODEOWNERS reviewers.
