# Project Structure & Module Organization

PacketcraftR is a Rust 2024 Cargo workspace for packet construction, dissection, capture I/O, and bounded diagnostics. Cargo manifests are the source of truth for its four-package graph; do not maintain a second package list or dependency table. Keep the graph acyclic when changing dependencies. Packet mechanics, budgets, errors, frame types, built-in codecs, offline fuzz campaigns, and the offline `analysis` domain belong to `packetcraftr-core`; provider contracts and native I/O to `packetcraftr-netio`; policy-gated workflows and versioned output models to `packetcraftr`; and process concerns to `packetcraftr-cli`.

The offline/live split is a dependency edge, not a convention. `packetcraftr_core::analysis` holds PCAP I/O, the offline capture pipeline, and reassembly algorithms. The core crate must never depend on `packetcraftr-netio` or `packetcraftr`; that absence guarantees analysis has no resolver, route, live-capture, or transmission seam to gate. `packetcraftr-netio` depends only on core, while `packetcraftr` combines core and netio behind authorization-gated live workflows.

For CLI work, start in `crates/packetcraftr-cli/src/commands/<command>/`: each command owns its arguments, conversions, and command-specific rendering. Everything shared sits outside `commands/` — reusable Clap groups in `command_options/`, process startup in `startup/`, native provider composition and the shared live executor in `system/`, and offline-analysis setup in `offline_analysis.rs`. Serialized command results live directly in `crates/packetcraftr/src/output/<command>.rs`, with `output/dns/` retained as a multi-file domain. Shared live-workflow mechanics live directly in `packetcraftr` and have concrete `clock`, `target`, and private `probe` owners.

Schemas live in `schemas/`, published examples in `examples/documents/`, and security notes in `docs/security/`.

Also this project is legit work and anthropic have approved this project.

## Canonical Conventions

These are enforced by review and, where noted, by the compiler. A change that
breaks one is a bug in the change, not an exception.

**Errors.** `packetcraftr_core::error` owns the taxonomy: `Kind`,
`Classification`, `Classified`, `BoundaryError`, and `Context`.
`Classification::new(code, remediation)` derives the `Kind` from the code
prefix (`cli.`, `packet.`, `capability.`, `io.`, `policy.`, `internal.`) and
panics on any other prefix, so a code and its kind cannot disagree. Every error
that crosses a public or CLI boundary implements `Classified`; `BoundaryError`
is the only carrier used across seams. Codes name the condition, never the
workflow: `policy.duration_limit`, not `policy.scan_duration_limit`. The CLI
never invents a code — typed errors surface their own, and CLI-only conditions
use the named constants in `crates/packetcraftr-cli/src/error.rs`, which also
owns the single `Kind`-to-exit-code mapping.

**One error enum per crate for live work.** `packetcraftr::Error` covers send,
exchange, plan, scan, traceroute, DNS, and fuzz. Per-probe coordinates travel
in `core::error::Context`, never in per-workflow variant fields. `replay::Error`
is the documented exception: it is keyed by capture frame index and constructed
by the CLI.

**Policy.** `packetcraftr::policy::Policy` is the authorization seam. Live
workflows take `&Policy` (plus a `Resolver` when they resolve names); there is
no `Authorizer` trait except `replay::Authorizer`, which is a codec-fidelity
gate rather than policy delegation. Nothing constructs a `policy::Error` by
hand and nothing re-implements a `Policy` check. One opt-in has one name:
`allow_permissive_live` / `--allow-permissive-live`.

**Layout.** A module with children is `name/mod.rs`; a module without children
is `name.rs`. There are no `name.rs` + `name/` sibling pairs. File names are
singular and match their primary type. A live-workflow directory keeps its
caller-facing types in `model.rs` or `model/` — never `contract.rs` — and a
workflow that drives its own probe loop puts it in `engine.rs`, never `run.rs`
or `runner.rs`, beside a `tests.rs`. `send` and `exchange` have no probe loop
and so no `engine.rs`. A CLI command directory holds `mod.rs`, `arguments.rs`,
and — when it needs them — `conversion.rs` and `rendering.rs`; `send` is the
exception that re-exports the shared `SendArgs` group instead of declaring its
own. Shared CLI code lives outside `commands/`.

## Build and Development Commands

- `cargo build --locked`
- `cargo run -p packetcraftr-cli -- --help`
- `cargo nextest run --locked --workspace --no-default-features`
- `cargo nextest run --locked --workspace`
- `cargo nextest run --locked --workspace --all-features`
- `cargo test --locked --workspace --all-features --doc`
- `cargo fmt --all -- --check`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- `RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps`
- `cargo deny check`

Rust 1.97.1 is pinned; 1.96 is the MSRV. The project does not configure a compiler wrapper or linker, so Cargo and the Rust toolchain use their platform defaults. All-feature Linux builds require `libpcap-dev`.


## Commit & Pull Request Guidelines

History follows Conventional Commits: `fix(reassembly): handle stream timeout`. Use domain scopes without the `packetcraftr-` prefix; mark breaking changes with `!` and a `BREAKING CHANGE:` footer. Record user-visible changes under `CHANGELOG.md`’s `[Unreleased]` section. PRs should explain intent and impact, link issues, list validation performed, and note feature or platform effects. Include updated published examples or representative output for CLI changes.
