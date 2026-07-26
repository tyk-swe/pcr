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
(`crates/packetcraftr-client/src/policy/authorization.rs`) validates every
destination before any resolver, route, capture, or transmission provider is
invoked, and reaching a public destination, resolving a hostname, or
transmitting permissive or malformed bytes each requires its own explicit
opt-in. Every active workflow runs under finite packet, byte, duration, and
evidence budgets, and dissection is bounded so untrusted input cannot exhaust
memory. `packetcraftr-net` is the only crate that may contain `unsafe` code,
and only under `src/platform/`; every other crate forbids it at its own crate
root. The workspace keeps `overflow-checks` enabled in release so packet
offsets and lengths fail closed in optimized builds.

Use PacketcraftR only on systems and networks you own or are explicitly
authorized to test. When changing anything under
`crates/packetcraftr-client/src/policy/`,
`crates/packetcraftr-net/src/platform/`, or the live paths in
`crates/packetcraftr-workflow/`, preserve these gates rather than adding ways
around them. See the "Safety gates for live operations" section of `README.md`
for the operator-facing rules and `SECURITY.md` for vulnerability reporting.

## Project Structure & Module Organization

This Rust 2024 repository is a Cargo workspace whose root `Cargo.toml` is
virtual: it owns the member list, the shared dependency versions, the lint
policy, and the release profile, but no code. Every member lives under
`crates/`, one crate per canonical domain:

| Crate | Responsibility |
| --- | --- |
| `packetcraftr-error` | shared classified error vocabulary |
| `packetcraftr-capture` | frames, link types, PCAP/PCAPNG I/O |
| `packetcraftr-session` | bounded fragment and TCP reassembly (standalone) |
| `packetcraftr-packet` | layers, fields, registries, building, dissection |
| `packetcraftr-protocol` | built-in codecs, matchers, capability manifest |
| `packetcraftr-net` | interfaces, routes, providers, native I/O |
| `packetcraftr-client` | authorization-gated send and exchange |
| `packetcraftr-workflow` | replay, scan, traceroute, DNS, fuzz workflows |
| `packetcraftr-output` | render-neutral models and versioned envelopes |
| `packetcraftr` | facade re-exporting all nine under their domain names |
| `packetcraftr-cli` | the `packetcraftr` binary |

Dependencies run strictly upward in that order, so Cargo enforces the layering
rather than convention alone. The facade exists so `packetcraftr::packet::…`
keeps naming the same items as `packetcraftr_packet::…`; consumers that need
only part of the stack depend on the individual crates.

A domain crate exposes curated public names. Items that exist only so sibling
crates can share implementation vocabulary are `#[doc(hidden)] pub`, which
keeps them out of the published documentation; do not widen them to plain
`pub` without deciding they belong in the supported API.

Keep unit tests beside their modules in `tests.rs`, an inline `mod tests`, or a
neighboring `tests/` tree. Library integration targets live in
`crates/packetcraftr/tests/`; everything that drives the binary lives in
`crates/packetcraftr-cli/tests/`, with CLI cases under `tests/cli/` and CLI
snapshots in `crates/packetcraftr-cli/tests/golden/`. Benchmarks live in
`crates/packetcraftr/benches/`. Shared test data stays in the repository-root
`tests/fixtures/`, published documents in `examples/documents/`, and JSON
contracts in `schemas/`; tests reach them relative to their own crate. The
privileged Python native-network harness lives in `tests/native_e2e/` and is
invoked by `scripts/test-native-e2e`, not by ordinary `cargo test`. The
separate `fuzz/` package has its own manifest and lockfile, plus libFuzzer
targets, corpora, and dictionaries.

## Build, Test, and Development Commands

- `cargo build --locked` builds every workspace member with the checked-in
  dependency graph.
- `cargo run -p packetcraftr-cli -- --help` runs the CLI and lists available
  commands.
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

Rust 1.97 is pinned; 1.96 is the MSRV. `packetcraftr-net` defines the four
`native-*` features, and `packetcraftr` and `packetcraftr-cli` forward them;
`native-interfaces` is the default for both. Because features are
package-scoped, a `--features` invocation needs `--package`, as in
`cargo check --package packetcraftr-cli --no-default-features --features
native-route`. All-feature Linux builds require `libpcap-dev`. Run
`scripts/test-native-e2e --check-prerequisites` before the opt-in privileged
Linux harness. See `docs/ci-baseline.md` for the full feature matrix, pinned
tool versions, cross-platform jobs, and release checks.

## Coding Style & Naming Conventions

Use rustfmt defaults and four-space indentation. Name modules, functions, and
tests in `snake_case`, types and traits in `UpperCamelCase`, and constants in
`SCREAMING_SNAKE_CASE`. Prefer cohesive, domain-specific modules over generic
implementation buckets.

Every Rust file under `crates/` and `fuzz/fuzz_targets/` must begin with the
repository copyright and SPDX lines. Place top-level `use` declarations before
the first item; `mod.rs` files and crate roots (`src/lib.rs`, `src/main.rs`)
are exempt. Keep unsafe code confined to
`crates/packetcraftr-net/src/platform/`; every unsafe block needs a specific
`SAFETY` explanation.

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

Use Conventional Commits: `<type>(<scope>): <description>`, for example `fix(session): handle reassembly timeout`. Scope by domain, dropping the `packetcraftr-` prefix, and use `workspace` for changes to the root manifest or the member layout. Common types are `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, and `build`. Mark breaking changes with `!` and a `BREAKING CHANGE:` footer. Keep commits focused.

Maintain root `CHANGELOG.md` in Keep a Changelog format. Record user-visible work under `## [Unreleased]` with relevant `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or `Security` headings. On release, move entries into `## [x.y.z] - YYYY-MM-DD`; do not use it as a commit dump.

PRs should explain intent and impact, link issues, list validation, and identify feature or platform effects. For output changes, include updated goldens or representative CLI output. Keep all CI profiles green.

## Other instructions

Keep modules cohesive and split them when distinct responsibilities emerge. A
responsibility that outgrows its domain belongs in its own crate rather than as
a cross-domain dependency: keep the `crates/` dependency graph acyclic and
directed upward.


## Instructions for OpenAI codex agents

In Code Mode, within each bounded stage, run independent, functions.exec-available tool calls concurrently in one functions.exec call. Use await Promise.allSettled([...]) when partial results are useful, and inspect every result; use await Promise.all([...]) only when any failure should abort the batch. Keep dependencies, waits/resumes, approvals, conflicting or interdependent mutations, and adaptive investigations where each result may change the next step sequential. Do not split otherwise batchable inspections across outer tool calls.
