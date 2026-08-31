# Repository Guidelines

## Project Structure & Module Organization

This Rust 2024 workspace has four crates: `packetcraftr-core` for packets and offline analysis, `packetcraftr-netio` for native I/O, `packetcraftr` for policy-gated workflows, and `packetcraftr-cli` for commands and rendering. Unit tests sit beside modules; integration tests live under `crates/*/tests/`. Keep `schemas/` synchronized with `examples/documents/`.

PacketcraftR is intended for protocol engineering, interoperability testing, and authorized network diagnostics. Keep examples and tests on loopback, documentation address ranges, or isolated fixtures; preserve the live-operation authorization and finite-budget gates.

## Build, Test, and Development Commands

The toolchain is pinned in `rust-toolchain.toml`; the MSRV is `rust-version` in `Cargo.toml`. Linux all-feature builds require `libpcap-dev`. CI runs all-feature tests on Linux only; macOS and Windows get an all-feature `cargo check`.

- `cargo build --locked`: build the workspace.
- `cargo run -p packetcraftr-cli -- --help`: exercise the CLI.
- `cargo nextest run --locked --workspace`: run tests; repeat with `--no-default-features` and `--all-features` when affected.
- `cargo test --locked --workspace --all-features --doc`: run doctests, which nextest omits.
- `RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps`: CI fails on rustdoc warnings.
- `cargo fmt --all -- --check`; `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`: check style and lints.
- `cargo deny check`: enforce dependency policy.
- `./scripts/check-features.sh`: `cargo check` every supported feature profile; CI runs it on Linux.
- `cargo bench -p packetcraftr-core`; `./scripts/measure-memory.sh`: non-gating Criterion benchmarks and Linux peak-RSS profiling.

## Coding Style & Naming Conventions

Use `rustfmt` defaults (four-space indentation). Name modules, functions, and tests in `snake_case`; types and traits in `UpperCamelCase`; constants in `SCREAMING_SNAKE_CASE`. Prefer checked conversions. The workspace denies `clippy::indexing_slicing` and `clippy::arithmetic_side_effects` in library code: use `get`/`checked_*`, or a narrowly scoped `#[expect(clippy::..., reason = "...")]` that names the invariant; never `#[allow]` outside test modules. Preserve the acyclic crate dependency direction.

`unsafe` belongs only in `packetcraftr-netio/src/platform/`, each block carrying a `SAFETY` comment naming the specific invariant it relies on. That crate denies `unsafe_code` once at its root and the platform wrappers opt out individually, so the exception list is `git grep -l 'allow(unsafe_code)'`; `packetcraftr-netio/tests/unsafe_boundary.rs` fails if an opt-out appears anywhere else. Every other crate forbids `unsafe_code` at its own root only — repeating the attribute on an inner module says nothing and implies, falsely, that its siblings are less protected.

### Conventions

These hold across the workspace. Follow them in new code rather than copying a nearby exception.

- **`Result` means `std::result::Result`.** A workflow's or command's aggregate outcome is a `Report` (`scan::Report`, `output::dns::Report`). Naming a payload `Result` shadows the prelude and forces `std::result::Result` at every use site.
- **`DEFAULT_*` names a starting value; `MAX_*` names an enforced ceiling.** A `validate()` never cites a `DEFAULT_*` as a maximum. Declare a ceiling in the crate that enforces it, and where a workflow pre-flights a bound another crate owns, cite that crate's `MAX_*` rather than restating the number.
- **`validate(&self) -> Result<(), E>` checks and returns nothing.** Anything that produces a value gets its own name (`selected_ports()`, `canonical_name()`) and calls `validate` first.
- **Every ceiling that bounds retained memory is reachable and validated from the caller that owns the operation**, through the same `Limits` type its sibling budgets use. A budget the caller cannot set or validate is a budget nobody can trust.
- **Every published field has a real producer.** A field the code can only ever fill with a default is deleted, not shipped — unless it is `required` in the frozen v1 schema, in which case document why it is constant.
- **An error variant that wraps another error carries it as `#[source]`**, and its own message does not restate the source's text. `Classified::classification` is an exhaustive `match` over the enum's own variants — never a predicate chain with a fallback — so a new variant is a compile error. Derive `causes` with `packetcraftr_core::error::source_chain` rather than hand-walking the chain. Where a `Clone` error must retain a non-`Clone` source, use `Arc<dyn Error + Send + Sync>`.
- **A boolean predicate that gates a typed answer is deleted in favour of the answer** (`Option<T>` or a closed enum), so callers cannot ask the question and then fail to handle it.
- **No library enum reaches user-facing output through `Debug`.** An enum that is both serialized and printed has one `as_str()` returning its serde spelling; `Display` delegates to it; the CLI never decides presentation by string-matching a rendered value.
- **Reach for `crate::`-rooted paths, not `super::super::`.** Multi-level parent paths hide a module's real dependencies and break silently when a module moves.
- **A module's file layout follows its seams, not a rule.** Both `x.rs` and `x/mod.rs` are fine; do not convert between them for consistency's sake, and do not rename files without a change in content behind it.

## Testing Guidelines

Use Rust's test framework through cargo-nextest (version in `.config/nextest.toml`). Put unit tests in `mod tests` or a sibling `tests.rs`, and public contracts in descriptive integration files under `crates/*/tests/` such as `reassembly_contracts.rs`. Test files open with `#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]`. Name tests after observable behavior and cover regressions across affected feature profiles. No numeric coverage target is configured.

## Commit & Pull Request Guidelines

Use focused Conventional Commits, for example `fix(reassembly): handle stream timeout`; omit the `packetcraftr-` prefix from scopes. Mark breaking changes with `!` and a `BREAKING CHANGE:` footer. PRs need one responsibility, a linked issue, impact notes, and exact validation results. Update `[Unreleased]` for user-visible changes, synchronize schemas with examples, and request applicable CODEOWNERS reviewers.
