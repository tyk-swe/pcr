# Repository Guidelines

## Project Structure & Module Organization

PacketcraftR is a Rust 2024 Cargo workspace for packet construction, dissection, capture I/O, and bounded diagnostics. Cargo manifests are the source of truth for its package graph; do not maintain a second package list or dependency table. Keep the graph acyclic and run `scripts/check-arch` after dependency changes. Reassembly belongs to analysis, native adapters to `packetcraftr-net/src/platform/`, policy-gated send/exchange to client, live diagnostic operations to workflow, and versioned serialized output models to the facade.

The offline/live split is a dependency edge, not a convention. `packetcraftr-analysis` holds the offline capture pipeline and reassembly algorithms and must never depend on `packetcraftr-client` or `packetcraftr-net`; that absence is what guarantees it has no resolver, route, capture, or transmission seam to gate. Live probing lives in `packetcraftr-workflow`. Both use the bottom-layer budgets and errors in `packetcraftr-core`.

For CLI work, start in `crates/packetcraftr-cli/src/commands/<command>/`: each command owns its arguments, execution adapters, conversions, tests, and command-specific rendering. Reusable Clap groups are in `command_options`; process startup is in `startup.rs`, and native provider composition is in `system`. Serialized command results live directly in `crates/packetcraftr/src/output/<command>.rs`, with `output/dns/` retained as a multi-file domain. Shared live-workflow mechanics have concrete `clock`, `target`, and private `probe` owners.

Place unit tests beside their modules. Integration tests live in `crates/packetcraftr/tests/`, CLI tests and goldens in `crates/packetcraftr-cli/tests/`, fixtures in `tests/fixtures/`, schemas in `schemas/`, published examples in `examples/documents/`, benchmarks in `crates/packetcraftr/benches/`, and fuzz targets in `fuzz/`.

## Build, Test, and Development Commands

- `cargo build --locked`: build the workspace with pinned dependencies.
- `cargo run -p packetcraftr-cli -- --help`: run the CLI locally.
- `cargo nextest run --locked`: run the default unit/integration test profile; also test `--no-default-features` and `--all-features` before release. Run matching `cargo test --doc` commands because nextest does not execute doctests.
- `cargo fmt --all -- --check`: verify formatting.
- `scripts/check-arch`: derive the Cargo graph and enforce acyclicity plus the offline/live capability boundary.
- `scripts/check-conventions`: enforce source headers and the native unsafe-code boundary.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: apply the CI lint gate.
- `cargo fmt --manifest-path fuzz/Cargo.toml -- --check` and `cargo clippy --manifest-path fuzz/Cargo.toml --locked --all-targets -- -D warnings`: apply the same gates to the fuzz workspace, which the root `--all` flags do not reach.

Rust 1.97 is pinned; 1.96 is the MSRV. Normal test execution requires cargo-nextest 0.9.140. Linux builds require clang and mold; all-feature Linux builds also require `libpcap-dev`.

## Coding Style & Naming Conventions

Use rustfmt defaults and four-space indentation. Name modules, functions, and tests in `snake_case`, types and traits in `UpperCamelCase`, and constants in `SCREAMING_SNAKE_CASE`. Every Rust source file under `crates/` and `fuzz/fuzz_targets/` needs the copyright and SPDX header. Keep `unsafe` code inside `crates/packetcraftr-net/src/platform/`, with a specific `SAFETY` explanation.

`overflow-checks` cannot see through an `as` conversion, so narrowing casts are denied. Prefer `From`, `TryFrom`, or keeping the wire-width value alongside its widened form. Where a cast is genuinely lossless, attach `#[expect(clippy::cast_possible_truncation, reason = "…")]` to the tightest enclosing item and name the guard or invariant that bounds it, the same way an `unsafe` block names its `SAFETY` argument. Use `#[expect]` rather than `#[allow]` so an annotation that stops applying fails the build.

`fuzz/` is a separate workspace and cannot inherit `[workspace.lints]`, so `fuzz/Cargo.toml` mirrors the root lint table by hand. Root `Cargo.toml` is the source of truth; change both together.

## Testing Guidelines

Use Rust’s built-in `#[test]` harness and descriptive behavior names, such as `classic_pcap_rejects_zero_snapshot_length`. Add focused regressions and use controlled providers instead of real sockets. CI requires 85% line coverage. Update fixtures, schemas, and published examples together when contracts change.

## Commit & Pull Request Guidelines

History follows Conventional Commits: `fix(reassembly): handle stream timeout`. Use domain scopes without the `packetcraftr-` prefix; mark breaking changes with `!` and a `BREAKING CHANGE:` footer. Record user-visible changes under `CHANGELOG.md`’s `[Unreleased]` section. PRs should explain intent and impact, link issues, list validation performed, and note feature or platform effects. Include updated goldens or representative output for CLI changes.

## Security & Live Operations

Use live networking only on explicitly authorized systems. Preserve `TrafficPolicy`, authorization checks, finite budgets, and the separation between offline and live workflow entry points. Consult `README.md` for safety gates and `SECURITY.md` for vulnerability reporting.

## Tool preference

- Prefer built-in Read, Edit, Write tools for file operations.
- Avoid shell-based file reading, searching, or editing when a built-in tool can perform the operation.
- Avoid complex inline shell, heredocs, nested quoting, and multi-stage pipelines.
- Keep tool output bounded; save full logs to a file and return only relevant diagnostics.
