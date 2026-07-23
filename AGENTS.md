# Repository Guidelines

## Project Structure & Module Organization

This Rust 2024 package provides the `packetcraftr` library and CLI. `src/lib.rs` exposes the canonical domains: `capture`, `client`, `error`, `net`, `output`, `packet`, `protocol`, `session`, and `workflow`. CLI code lives in `src/cli/` and enters through `src/main.rs`. Keep unit tests beside modules in `tests.rs`; place API, architecture, and end-to-end tests in `tests/*.rs`. Test data belongs in `tests/fixtures/`, CLI snapshots in `tests/golden/`, published documents in `examples/documents/`, and JSON contracts in `schemas/`. The separate `fuzz/` package holds libFuzzer targets, corpora, and dictionaries.

## Build, Test, and Development Commands

- `cargo build --locked` builds with the checked-in dependency graph.
- `cargo run -- --help` runs the CLI and lists available commands.
- `cargo test --locked` runs the default test profile. Also test portability with `--no-default-features` and the complete profile with `--all-features`.
- `cargo fmt --all -- --check` verifies formatting.
- `cargo clippy --locked --all-targets --all-features -- -D warnings` applies the CI lint gate.
- `cargo deny check` validates dependency, license, and advisory policy.

Rust 1.97 is pinned; 1.96 is the MSRV. Linux all-feature builds require `libpcap-dev`.

## Coding Style & Naming Conventions

Use rustfmt defaults and four-space indentation. Name modules, functions, and tests in `snake_case`, types and traits in `UpperCamelCase`, and constants in `SCREAMING_SNAKE_CASE`. Preserve canonical filesystem modules: architecture tests reject `internal`, `_impl`, and `#[path = ...]` modules. Keep unsafe code confined to `src/net/platform/`; every unsafe block needs a specific `SAFETY` explanation.

## Testing Guidelines

Tests use Rust's built-in `#[test]` harness and descriptive behavior names, such as `classic_pcap_rejects_zero_snapshot_length`. Add focused regression tests. Update fixtures, goldens, examples, and schemas together when serialized or CLI contracts change. CI enforces 75% line coverage with `cargo llvm-cov --locked --all-features --workspace --fail-under-lines 75` and smoke-tests every fuzz target.

## Commits, Changelog & Pull Requests - IMPORTANT

Use Conventional Commits: `<type>(<scope>): <description>`, for example `fix(session): handle reassembly timeout`. Common types are `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, and `build`. Mark breaking changes with `!` and a `BREAKING CHANGE:` footer. Keep commits focused.

Maintain root `CHANGELOG.md` in Keep a Changelog format. Record user-visible work under `## [Unreleased]` with relevant `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or `Security` headings. On release, move entries into `## [x.y.z] - YYYY-MM-DD`; do not use it as a commit dump.

PRs should explain intent and impact, link issues, list validation, and identify feature or platform effects. For output changes, include updated goldens or representative CLI output. Keep all CI profiles green.

## Other instructions

Good code is maintainable code. Rust source files above 20 KiB (20,480 bytes,
roughly 600 lines) are too large and should be split or refactored.
