# Repository Guidelines

## Project Structure & Module Organization

This Rust 2024 package provides the `packetcraftr` library and CLI. `src/lib.rs` exposes the canonical domains: `capture`, `client`, `error`, `net`, `output`, `packet`, `protocol`, `session`, and `workflow`. CLI code lives in `src/cli/` and enters through `src/main.rs`. Keep unit tests beside modules in `tests.rs`; place API and end-to-end tests in `tests/*.rs`. Test data belongs in `tests/fixtures/`, CLI snapshots in `tests/golden/`, published documents in `examples/documents/`, and JSON contracts in `schemas/`. The separate `fuzz/` package holds libFuzzer targets, corpora, and dictionaries.

The package is pre-1.0 (`0.4.0-beta.2`) and AGPL-3.0-only. Every `.rs` file opens with the copyright/SPDX header pair, followed by a blank line; `scripts/check-source-conventions` enforces this in CI, so add it to any new file.

## Architecture

### Domain layering

The dependency direction between the nine domains is the load-bearing structure:

- **`packet` + `protocol` are runtime-neutral.** No native I/O and no feature gating. `packet` owns the model, registry, and build/decode engines; `protocol` supplies concrete codecs. Nothing here may reach for a socket.
- **`capture`** is offline PCAP/PCAPNG reading, writing, and transcoding — also runtime-neutral.
- **`session`** is a standalone reassembly *algorithm* API, deliberately not wired into decode. Callers map decoded layers into `fragment::Fragment` / `tcp::Segment` themselves (worked example in the `src/session/mod.rs` doc comment).
- **`net`** is the only place native platform code lives. Platform handles stay private behind `src/net/platform/`, which is also the only place `unsafe` is permitted.
- **`client`** composes registry + route planning + policy + I/O into `Client<R, N, I>`.
- **`workflow`** builds bounded replay/scan/traceroute/DNS/fuzz operations on top of executor traits.
- **`output`** holds the serialized v1 contract types. These are intentionally *not* aliases of workflow result types — the two evolve independently.
- **`error`** is the shared classification vocabulary.
- **`src/cli/`** is a thin adapter over the library, compiled only with the `cli` feature.

### Registry-driven packet pipeline

This is the main extension seam and explains why the engines are generic.

`LayerCodec` (`src/packet/codec/contract.rs`) defines encode / decode / `make_layer` for one protocol. `ProtocolRegistry` (`src/packet/registry/core.rs`) holds codecs keyed by `ProtocolId`, case-insensitive aliases, `roots` mapping numeric DLT/LINKTYPE to a capture entry point, forward `bindings` from `(parent, Discriminator)` to child with priority, reverse bindings so the builder can infer a parent's discriminator from its child, and response `matchers`.

The build engine (`src/packet/build/engine.rs`) and decode engine (`src/packet/decode/engine.rs`) are entirely registry-driven. **Adding a protocol means implementing `LayerCodec` and registering it under `src/protocol/builtin/registry/` — not editing the engines.** Downstream crates extend the same way via the `ProtocolModule` trait and `RegistryBuilder`; `tests/external_protocol.rs` locks that in from outside the crate.

Strictness is a `BuildMode`, not a code path: unknown link types and unknown discriminators degrade to bounded raw bytes, malformed input is preserved as a malformed layer plus diagnostics rather than dropped.

`protocol::support::BUILTIN_PROTOCOL_SUPPORT` is the versioned source of truth for what is actually supported (build, dissect, exact round trip, matcher, capture root, per-workflow obligations). Never infer capability from a type merely existing.

### Provider and executor traits keep native I/O testable

`Client<R, N, I>` is generic over `RouteProvider`, `NeighborResolver`, and `ExchangeIo`/`PacketIo`. Workflows are generic over their own `Executor` (e.g. `ScanExecutor`), a `Clock`, and an `Authorizer`, with a `ClientExecutor` adapter bridging to `Client`. The native implementations (`SystemProvider`, `SystemResolver`, `SystemLayer2`, `SystemLayer3`) sit behind Cargo features and **fail closed with `capability.*` errors when the feature is absent** rather than failing to compile.

### Error classification and exit codes

Public errors crossing a boundary implement `error::Classified`, returning a `Classification { code, kind, category, remediation }`. `Kind` selects the CLI exit family (`src/cli/errors.rs`): cli 2, packet 3, capability 4, io 5, policy 6, internal 70. `Category` is separate on purpose — it distinguishes failures that share an exit code but need different handling (timeout vs. plain io vs. cleanup). Codes are stable strings (`policy.public_destination`, `capability.route`, `io.route_not_found`) and are part of the contract.

### Policy gating order is an invariant

Destination authorization runs **before** interface discovery, route lookup, capture, or transmission; workflows resolve and authorize the entire target set before constructing the first probe. Preserve that ordering when editing these paths — `src/cli/runtime.rs` and `src/workflow/scan/engine.rs` carry explicit comments about it.

Live opt-ins (`--allow-public-destinations`, `--allow-hostname-resolution`, `--allow-permissive-live`, `--allow-malformed-live`, `--allow-permissive-packets`) gate *policy*, and are independent of OS privilege errors — never widen one to work around the other.

### Bounded by construction

Every workflow declares packet, byte, duration, and evidence budgets up front and authorizes the whole budget before the first side effect (`Deadline`, `EvidenceBudget`, per-workflow `Limits`). The release profile keeps `overflow-checks = true` specifically so offset, length, and accounting arithmetic fails closed in optimized builds. Use checked arithmetic in these paths.

### Serialized contracts move together

`output::*` types, `schemas/*.schema.json`, `examples/documents/*.json`, `tests/fixtures/`, and `tests/golden/*.txt` form one contract and must be updated in the same change. `tests/schema_contract.rs` validates against the JSON Schemas; `tests/document_examples.rs` asserts every command has published success and error documents. Goldens are hand-maintained — there is no regeneration flag. CLI help text lives as `*_AFTER_HELP` constants in `src/cli/arguments/root.rs`, so editing help updates `tests/golden/cli-help.txt`.

Envelopes: `envelope::Aggregate` for `--output json`, `envelope::Stream`/`StreamError` for `--output ndjson`. Machine and binary formats (json, ndjson, hex, raw, pcap, pcapng) must never contain terminal styling, even under `--color always`.

### CLI wiring

`src/main.rs` → `cli::run_entrypoint` (`src/cli/runtime.rs`) → clap `Cli` in `src/cli/arguments/root.rs` → per-command handlers in `src/cli/commands/`. `runtime.rs` also composes the concrete system stack (`SystemClient`) and enforces `Command::require_format`, which restricts output formats per command. Parse failures are rendered in the machine format when one was requested, which is why the entrypoint sniffs `--output` from the raw argv before clap succeeds.

## Build, Test, and Development Commands

- `cargo build --locked` builds with the checked-in dependency graph.
- `cargo run -- --help` runs the CLI and lists available commands.
- `cargo test --locked` runs the default test profile. Also test portability with `--no-default-features` and the complete profile with `--all-features`.
- `cargo fmt --all -- --check` verifies formatting.
- `cargo clippy --locked --all-targets --all-features -- -D warnings` applies the CI lint gate.
- `cargo deny check` validates dependency, license, and advisory policy.

Rust 1.97 is pinned; 1.96 is the MSRV. Linux all-feature builds require `libpcap-dev`.

### Feature profiles

Feature selection changes which code even compiles, so most checks are profile-scoped. `--no-default-features` is library-only: Cargo skips the `packetcraftr` binary, its unit tests, and `tests/cli.rs` entirely.

```console
cargo test --locked --no-default-features   # library only, no CLI
cargo test --locked                         # default: cli + native-interfaces
cargo test --locked --all-features          # complete; Linux needs libpcap-dev
cargo check --locked --release --no-default-features \
  --features cli,native-route,native-layer3 # pcap-free release variant
cargo hack check --locked --feature-powerset --depth 2 --all-targets
```

### Running one test

All 520 unit tests live inside the library target, so filters need `--lib`. Integration targets are selected with `--test`.

```console
cargo test --locked --lib -- --list                       # enumerate unit tests
cargo test --locked --lib workflow::scan::tests           # module filter
cargo test --locked --lib -- --exact <full::path::to::test>
cargo test --locked --test cli offline                    # one integration target + filter
cargo test --locked --test schema_contract --test document_examples
cargo test --locked --test external_protocol              # downstream-consumer contract
```

### Additional quality gates

```console
RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps
cargo deny --manifest-path fuzz/Cargo.toml check
cargo llvm-cov --locked --all-features --workspace --fail-under-lines 75
```

### Fuzzing, benchmarks, privileged E2E, API diff

```console
cargo +nightly-2026-07-11 fuzz run <target> fuzz/corpus/<target> \
  -- -runs=1000 -seed=12648430 -timeout=5 -rss_limit_mb=2048 \
  -dict=fuzz/dictionaries/<target>.dict
cargo bench --bench packet_pipeline           # also: reassembly, workflow_scan
scripts/test-native-e2e --check-prerequisites # then: sudo -v && scripts/test-native-e2e
scripts/public-api-diff                       # needs cargo-semver-checks 0.49.0
```

Fuzz targets: `capture_reader`, `decode_roundtrip`, `packet_inputs`, `dns_wire`, `reassembly_state`. The `fuzz/` package has its own lockfile and workspace. `docs/ci-baseline.md` records pinned tool versions and thresholds and must be updated in the same change as any CI edit.

## Coding Style & Naming Conventions

Use rustfmt defaults and four-space indentation. Name modules, functions, and tests in `snake_case`, types and traits in `UpperCamelCase`, and constants in `SCREAMING_SNAKE_CASE`. Prefer cohesive, domain-specific modules over generic implementation buckets. Keep unsafe code confined to `src/net/platform/`; every unsafe block needs a specific `SAFETY` explanation.

Top-level `use` declarations go at the top of the file, before the first item. `mod.rs` module roots are the exception: they declare the module tree and its `pub use` re-exports first, then import. `scripts/check-source-conventions` enforces both this and the license header, because rustfmt does not reorder across items.

### Descriptive internal name, short public re-export

Pervasive and easy to get wrong. Each module names its type descriptively inside, then re-exports it short and namespace-scoped, with a parallel `pub(crate) use` of the long name for internal use:

```rust
pub use contract::{LayerCodec as Codec, CodecError as Error, EncodedLayer as Encoded};
pub(crate) use contract::{CodecError, EncodedLayer, LayerCodec};
```

So public code reads `packet::codec::Codec`, `packet::build::Options`, `net::route::Provider`, `workflow::scan::Result`, while crate-internal code keeps using `LayerCodec`, `BuildOptions`, `RouteProvider`, `ScanResult`. New public types follow the same pattern.

## Testing Guidelines

Tests use Rust's built-in `#[test]` harness and descriptive behavior names, such as `classic_pcap_rejects_zero_snapshot_length`. Add focused regression tests. Update fixtures, goldens, examples, and schemas together when serialized or CLI contracts change. CI enforces 75% line coverage with `cargo llvm-cov --locked --all-features --workspace --fail-under-lines 75` and smoke-tests every fuzz target.

Unit tests sit beside their module in `tests.rs` (or an inline `mod tests`), with nested submodules for grouping. Integration tests live in `tests/`: `cli.rs` (gated on `cli`), `schema_contract.rs`, `document_examples.rs`, `fixture_corpus.rs`, `reassembly_properties.rs`, and the `external_*.rs` files that exercise the crate as a downstream consumer would. `tests/native_e2e/` is a Python harness driven by `scripts/test-native-e2e` and is not part of ordinary `cargo test`.

Because client and workflow types are generic over their providers, these tests run unprivileged with in-process fakes (`src/client/tests/support/`, `src/workflow/*/tests/`). Prefer a controlled provider over touching a real socket. Native changes must also cover failure paths — permission denial, unavailable backend, stale interface identity, timeout and cancellation, partial I/O, queue overflow, accounting failure, and cleanup — not only successful I/O.

## Commits, Changelog & Pull Requests - IMPORTANT

Use Conventional Commits: `<type>(<scope>): <description>`, for example `fix(session): handle reassembly timeout`. Common types are `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, and `build`. Mark breaking changes with `!` and a `BREAKING CHANGE:` footer. Keep commits focused.

Maintain root `CHANGELOG.md` in Keep a Changelog format. Record user-visible work under `## [Unreleased]` with relevant `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or `Security` headings. On release, move entries into `## [x.y.z] - YYYY-MM-DD`; do not use it as a commit dump.

PRs should explain intent and impact, link issues, list validation, and identify feature or platform effects. For output changes, include updated goldens or representative CLI output. Keep all CI profiles green.

## Other instructions

Keep modules cohesive and split them when distinct responsibilities emerge.


## Instructions for OpenAI codex agents

In Code Mode, within each bounded stage, run independent, functions.exec-available tool calls concurrently in one functions.exec call. Use await Promise.allSettled([...]) when partial results are useful, and inspect every result; use await Promise.all([...]) only when any failure should abort the batch. Keep dependencies, waits/resumes, approvals, conflicting or interdependent mutations, and adaptive investigations where each result may change the next step sequential. Do not split otherwise batchable inspections across outer tool calls.
