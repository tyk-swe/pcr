# Repository Guidelines

## Project Structure & Module Organization

PacketcraftR is a Rust 2024 Cargo workspace for packet construction, dissection, capture I/O, and bounded diagnostics. Cargo manifests are the source of truth for its package graph; do not maintain a second package list or dependency table. Keep the graph acyclic when changing dependencies. Reassembly belongs to analysis, native adapters to `packetcraftr-net/src/platform/`, policy-gated send/exchange to client, live diagnostic operations to workflow, and versioned serialized output models to the facade.

The offline/live split is a dependency edge, not a convention. `packetcraftr-analysis` holds the offline capture pipeline and reassembly algorithms and must never depend on `packetcraftr-client` or `packetcraftr-net`; that absence is what guarantees it has no resolver, route, capture, or transmission seam to gate. Live probing lives in `packetcraftr-workflow`. Both use the bottom-layer budgets and errors in `packetcraftr-core`.

For CLI work, start in `crates/packetcraftr-cli/src/commands/<command>/`: each command owns its arguments, execution adapters, conversions, and command-specific rendering. Reusable Clap groups are in `command_options`; process startup is in `startup.rs`, and native provider composition is in `system`. Serialized command results live directly in `crates/packetcraftr/src/output/<command>.rs`, with `output/dns/` retained as a multi-file domain. Shared live-workflow mechanics have concrete `clock`, `target`, and private `probe` owners.

Schemas live in `schemas/`, published examples in `examples/documents/`, and security notes in `docs/security/`.

## Build and Development Commands

- `cargo build --locked`: build the workspace with pinned dependencies.
- `cargo run -p packetcraftr-cli -- --help`: run the CLI locally.
- `cargo fmt --all -- --check`: verify formatting.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: apply the lint gate.
- `RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps`: verify API documentation.
- `cargo deny check`: verify dependency policy.

Rust 1.97 is pinned; 1.96 is the MSRV. Linux builds require clang and lld; all-feature Linux builds also require `libpcap-dev`.

## Coding Style & Naming Conventions

Use rustfmt defaults and four-space indentation. Name modules and functions in `snake_case`, types and traits in `UpperCamelCase`, and constants in `SCREAMING_SNAKE_CASE`. Every Rust source file under `crates/` needs the copyright and SPDX header. Keep `unsafe` code inside `crates/packetcraftr-net/src/platform/`, with a specific `SAFETY` explanation.

`overflow-checks` cannot see through an `as` conversion, so narrowing casts are denied. Prefer `From`, `TryFrom`, or keeping the wire-width value alongside its widened form. Where a cast is genuinely lossless, attach `#[expect(clippy::cast_possible_truncation, reason = "…")]` to the tightest enclosing item and name the guard or invariant that bounds it, the same way an `unsafe` block names its `SAFETY` argument. Use `#[expect]` rather than `#[allow]` so an annotation that stops applying fails the build.

## Commit & Pull Request Guidelines

History follows Conventional Commits: `fix(reassembly): handle stream timeout`. Use domain scopes without the `packetcraftr-` prefix; mark breaking changes with `!` and a `BREAKING CHANGE:` footer. Record user-visible changes under `CHANGELOG.md`’s `[Unreleased]` section. PRs should explain intent and impact, link issues, list validation performed, and note feature or platform effects. Include updated published examples or representative output for CLI changes.

## Security & Live Operations

Use live networking only on explicitly authorized systems. Preserve `TrafficPolicy`, authorization checks, finite budgets, and the separation between offline and live workflow entry points. Consult `README.md` for safety gates and `SECURITY.md` for vulnerability reporting.

## Tool preference

- Prefer built-in Read, Edit, Write tools for file operations.
- Avoid shell-based file reading, searching, or editing when a built-in tool can perform the operation.
- Avoid complex inline shell, heredocs, nested quoting, and multi-stage pipelines.
- Keep tool output bounded; save full logs to a file and return only relevant diagnostics.
