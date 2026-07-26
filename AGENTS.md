# Repository Guidelines

## Project Purpose & Scope

PacketcraftR is a network protocol analysis toolkit: a Rust library and CLI for
constructing exact packet bytes, dissecting packet stacks, reading and writing
capture files, and running bounded diagnostic workflows. It belongs to the same
category as Wireshark, tcpdump, and scapy, and exists for network engineers
debugging protocol behaviour, protocol implementers validating encoders and
decoders against the wire format, and QA engineers testing parser robustness
against malformed input.

Most of the crate never touches a network. Packet building, dissection, capture
file I/O, and fuzz-case generation are offline and runtime-neutral;
`workflow::fuzz::run` deliberately has no resolver, route, or native-I/O seam,
and `run_live` is a separate entry point that requires operation authorization.

Live operations are authorization-gated by design. `TrafficPolicy`
(`src/client/policy/authorization.rs`) validates every destination before any
resolver, route, capture, or transmission provider is invoked, and reaching a
public destination, resolving a hostname, or transmitting permissive or
malformed bytes each requires its own explicit opt-in. Every active workflow
runs under finite packet, byte, duration, and evidence budgets, and dissection
is bounded so untrusted input cannot exhaust memory. The crate denies
`unsafe_code` outside `src/net/platform/`, and keeps `overflow-checks` enabled
in release so packet offsets and lengths fail closed in optimized builds.

Use PacketcraftR only on systems and networks you own or are explicitly
authorized to test. When changing anything under `src/client/policy/`,
`src/net/platform/`, or the live paths in `src/workflow/`, preserve these gates
rather than adding ways around them. See the "Safety gates for live operations"
section of `README.md` for the operator-facing rules and `SECURITY.md` for
vulnerability reporting.

## Project Structure & Module Organization

This Rust 2024 package provides the `packetcraftr` library and CLI. `src/lib.rs`
exposes the canonical domains: `capture`, `client`, `error`, `net`, `output`,
`packet`, `protocol`, `session`, and `workflow`. CLI arguments and handlers live
under `src/cli/`, with runtime composition in `src/cli/runtime.rs` and the
executable entry point in `src/main.rs`.

Keep unit tests beside their modules in `tests.rs`, an inline `mod tests`, or a
neighboring `tests/` tree. Root integration targets live in `tests/*.rs`; CLI
cases live in `tests/cli/`. The privileged Python native-network harness lives
in `tests/native_e2e/` and is invoked by `scripts/test-native-e2e`, not by
ordinary `cargo test`. Test data belongs in `tests/fixtures/`, CLI snapshots in
`tests/golden/`, published documents in `examples/documents/`, and JSON
contracts in `schemas/`. Benchmarks live in `benches/`. The separate `fuzz/`
package has its own manifest and lockfile, plus libFuzzer targets, corpora, and
dictionaries.

## Build, Test, and Development Commands

- `cargo build --locked` builds with the checked-in dependency graph.
- `cargo run -- --help` runs the CLI and lists available commands.
- `cargo test --locked --no-default-features`, `cargo test --locked`, and
  `cargo test --locked --all-features` exercise the portable, default, and
  complete profiles.
- `cargo fmt --all -- --check` verifies formatting.
- `scripts/check-source-conventions` verifies repository-specific Rust source
  layout.
- `cargo clippy --locked --all-targets --all-features -- -D warnings` applies the CI lint gate.
- `RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps`
  rejects documentation warnings.
- `cargo deny check` and `cargo deny --manifest-path fuzz/Cargo.toml check`
  validate both dependency graphs.

Rust 1.97 is pinned; 1.96 is the MSRV. Default features are `cli` and
`native-interfaces`. The no-default profile omits the CLI target, while
all-feature Linux builds require `libpcap-dev`. Run
`scripts/test-native-e2e --check-prerequisites` before the opt-in privileged
Linux harness. See `docs/ci-baseline.md` for the full feature matrix, pinned
tool versions, cross-platform jobs, and release checks.

## Coding Style & Naming Conventions

Use rustfmt defaults and four-space indentation. Name modules, functions, and
tests in `snake_case`, types and traits in `UpperCamelCase`, and constants in
`SCREAMING_SNAKE_CASE`. Prefer cohesive, domain-specific modules over generic
implementation buckets.

Every Rust file under `src/`, `tests/`, `benches/`, and `fuzz/fuzz_targets/`
must begin with the repository copyright and SPDX lines. Place top-level `use`
declarations before the first item; `mod.rs`, `src/lib.rs`, and `src/main.rs`
are exempt. Keep unsafe code confined to `src/net/platform/`; every unsafe
block needs a specific `SAFETY` explanation.

## Testing Guidelines

Tests use Rust's built-in `#[test]` harness and descriptive behavior names,
such as `classic_pcap_rejects_zero_snapshot_length`. Add focused regression
tests and prefer controlled providers over real sockets for client and workflow
coverage. Native networking changes must cover relevant failure and cleanup
paths as well as successful I/O.

Update fixtures, goldens, published examples, and schemas together when
serialized or CLI contracts change. Run
`cargo test --locked --test schema_contract --test document_examples` for
those changes. CI enforces 75% line coverage with
`cargo llvm-cov --locked --all-features --workspace --lcov --output-path lcov.info --fail-under-lines 75`
and smoke-tests every committed fuzz target.

## Commits, Changelog & Pull Requests - IMPORTANT

Use Conventional Commits: `<type>(<scope>): <description>`, for example `fix(session): handle reassembly timeout`. Common types are `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, and `build`. Mark breaking changes with `!` and a `BREAKING CHANGE:` footer. Keep commits focused.

Maintain root `CHANGELOG.md` in Keep a Changelog format. Record user-visible work under `## [Unreleased]` with relevant `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or `Security` headings. On release, move entries into `## [x.y.z] - YYYY-MM-DD`; do not use it as a commit dump.

PRs should explain intent and impact, link issues, list validation, and identify feature or platform effects. For output changes, include updated goldens or representative CLI output. Keep all CI profiles green.

## Other instructions

Keep modules cohesive and split them when distinct responsibilities emerge.


## Instructions for OpenAI codex agents

In Code Mode, within each bounded stage, run independent, functions.exec-available tool calls concurrently in one functions.exec call. Use await Promise.allSettled([...]) when partial results are useful, and inspect every result; use await Promise.all([...]) only when any failure should abort the batch. Keep dependencies, waits/resumes, approvals, conflicting or interdependent mutations, and adaptive investigations where each result may change the next step sequential. Do not split otherwise batchable inspections across outer tool calls.
