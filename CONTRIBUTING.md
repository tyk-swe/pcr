# Contributing to PacketcraftR

PacketcraftR welcomes focused fixes, features, and documentation changes.
Report suspected vulnerabilities through [SECURITY.md](SECURITY.md), not a
public issue.

## Development setup

The workspace uses Rust 2024, pins Rust 1.97.1, and supports Rust 1.96 or newer.
Linux builds use clang and lld; all-feature builds also need libpcap development
files. cargo-nextest 0.9.143 or newer is required for the nextest commands.

Run the checks that cover your change:

```console
cargo build --locked
cargo nextest run --locked --workspace --no-default-features
cargo nextest run --locked --workspace
cargo nextest run --locked --workspace --all-features
cargo test --locked --workspace --all-features --doc
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps
cargo deny check
```

Nextest runs unit and integration tests without retries; Cargo runs doctests
separately. The no-default profile keeps native providers disabled, the default
adds interface enumeration, and all-features enables every native provider.
The [CI workflow](.github/workflows/ci.yml) is the authoritative automated
check set.

## Architecture

Cargo manifests and `cargo metadata` are the source of truth for packages,
features, and dependencies. Keep the graph acyclic. In particular,
`packetcraftr-analysis` must not depend directly or transitively on
`packetcraftr-client` or `packetcraftr-net`; this dependency boundary keeps
offline analysis free of resolution, route, capture, and transmission seams.

Start CLI changes in
`crates/packetcraftr-cli/src/commands/<command>/`. Serialized command results
belong in `crates/packetcraftr/src/output/<command>.rs`, offline analysis and
reassembly in `packetcraftr-analysis`, live operations in
`packetcraftr-workflow`, policy-gated send/exchange in `packetcraftr-client`,
and native adapters in `packetcraftr-net/src/platform/`. See [AGENTS.md](AGENTS.md)
for the focused ownership and coding rules.

Keep `unsafe` inside `packetcraftr-net/src/platform/` and give every unsafe
block a specific `SAFETY` explanation. Avoid narrowing `as` conversions; use
checked conversions or the repository's tightly scoped `#[expect]` convention
with the bounding invariant stated.

## Issues and pull requests

Use the general issue form for portable or offline defects and the native
networking form for interfaces, routes, capture, injection, raw sockets, or
live workflows. Include the exact version, feature profile, platform, minimal
reproduction, expected result, actual result, and sanitized diagnostics. Never
post production captures, credentials, public-target details, or exploit
information.

Each pull request should:

- have one primary responsibility and keep mechanical refactoring separate
  from behavior changes;
- use focused Conventional Commits such as
  `fix(reassembly): handle stream timeout`;
- describe public API, schema/output, feature, and platform impact;
- update `[Unreleased]` in `CHANGELOG.md` for user-visible changes;
- update schemas and published examples together when a serialized contract
  changes; and
- list the exact validation commands and outcomes.

Review the full diff before requesting review. Cross-boundary changes need
review from every affected owner. Native networking changes should cover the
relevant unavailable-backend, permission, stale-interface, timeout,
cancellation, partial-I/O, queue, accounting, and cleanup paths.

## Validation by risk

| Change | Minimum focused evidence |
| --- | --- |
| Packet, schema, or output | Representative output plus synchronized schemas and examples. |
| Public Rust API | Affected downstream builds and rustdoc with warnings denied. |
| Feature-gated code | No-default, default, and all-feature checks. |
| Native platform code | Affected-platform success and relevant failure-path evidence. |
| Documentation only | Applicable doc checks and `git diff --check`. |
