# Agent Guidelines

- Ignore backward compatibility unless explicitly requested.
- Prefer self-explanatory code with clear, descriptive names and obvious control flow.
- Avoid comments. Add them only when necessary to explain an unavoidable non-obvious workaround or genuinely complex algorithm.
- Use `pnpm`.
- Keep functions under 100 lines and source files under 30 KB.
- Avoid unnecessary wrappers, facades, indirection, and speculative abstractions.
- Prefer the simplest structure that clearly expresses intent.
- Do not make maintainability more complex

# Repository Guidelines

## Project Structure & Module Organization

PacketcraftR is a Rust 2024 Cargo workspace for packet construction, dissection, capture I/O, and bounded diagnostics. Cargo manifests are the source of truth for its four-package graph; do not maintain a second package list or dependency table. Keep the graph acyclic when changing dependencies. Packet mechanics, budgets, errors, frame types, built-in codecs, offline fuzz campaigns, and the offline `analysis` domain belong to `packetcraftr-core`; provider contracts and native I/O to `packetcraftr-netio`; policy-gated workflows and versioned output models to `packetcraftr`; and process concerns to `packetcraftr-cli`.

The offline/live split is a dependency edge, not a convention. `packetcraftr_core::analysis` holds PCAP I/O, the offline capture pipeline, and reassembly algorithms. The core crate must never depend on `packetcraftr-netio` or `packetcraftr`; that absence guarantees analysis has no resolver, route, live-capture, or transmission seam to gate. `packetcraftr-netio` depends only on core, while `packetcraftr` combines core and netio behind authorization-gated live workflows.

For CLI work, start in `crates/packetcraftr-cli/src/commands/<command>/`: each command owns its arguments, execution adapters, conversions, and command-specific rendering. Reusable Clap groups are in `command_options`; process startup is in `startup.rs`, and native provider composition is in `system`. Serialized command results live directly in `crates/packetcraftr/src/output/<command>.rs`, with `output/dns/` retained as a multi-file domain. Shared live-workflow mechanics live directly in `packetcraftr` and have concrete `clock`, `target`, and private `probe` owners.

Schemas live in `schemas/`, published examples in `examples/documents/`, and security notes in `docs/security/`.

## Build and Development Commands

- `cargo build --locked`: build the workspace with pinned dependencies.
- `cargo run -p packetcraftr-cli -- --help`: run the CLI locally.
- `cargo nextest run --locked --workspace --no-default-features`: run the portable test profile.
- `cargo nextest run --locked --workspace`: run the default-feature test profile.
- `cargo nextest run --locked --workspace --all-features`: run the complete feature test profile.
- `cargo test --locked --workspace --all-features --doc`: run doctests separately from nextest.
- `cargo fmt --all -- --check`: verify formatting.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: apply the lint gate.
- `RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps`: verify API documentation.
- `cargo deny check`: verify dependency policy.

Rust 1.97.1 is pinned; 1.96 is the MSRV. The project does not configure a compiler wrapper or linker, so Cargo and the Rust toolchain use their platform defaults. All-feature Linux builds require `libpcap-dev`.

## Coding Style & Naming Conventions

Use rustfmt defaults and four-space indentation. Name modules and functions in `snake_case`, types and traits in `UpperCamelCase`, and constants in `SCREAMING_SNAKE_CASE`. Every Rust source file under `crates/` needs the copyright and SPDX header. Keep `unsafe` code inside `crates/packetcraftr-netio/src/platform/`, with a specific `SAFETY` explanation.

`overflow-checks` cannot see through an `as` conversion, so narrowing casts are denied. Prefer `From`, `TryFrom`, or keeping the wire-width value alongside its widened form. Where a cast is genuinely lossless, attach `#[expect(clippy::cast_possible_truncation, reason = "…")]` to the tightest enclosing item and name the guard or invariant that bounds it, the same way an `unsafe` block names its `SAFETY` argument. Use `#[expect]` rather than `#[allow]` so an annotation that stops applying fails the build.

## Commit & Pull Request Guidelines

History follows Conventional Commits: `fix(reassembly): handle stream timeout`. Use domain scopes without the `packetcraftr-` prefix; mark breaking changes with `!` and a `BREAKING CHANGE:` footer. Record user-visible changes under `CHANGELOG.md`’s `[Unreleased]` section. PRs should explain intent and impact, link issues, list validation performed, and note feature or platform effects. Include updated published examples or representative output for CLI changes.

## Security & Live Operations

Use live networking only on explicitly authorized systems. Preserve `TrafficPolicy`, authorization checks, finite budgets, and the separation between offline and live workflow entry points. Consult `README.md` for safety gates and `SECURITY.md` for vulnerability reporting.

## Tool preference

- Avoid complex inline shell, heredocs, nested quoting, and multi-stage pipelines.
- Keep tool output bounded; save full logs to a file and return only relevant diagnostics.
