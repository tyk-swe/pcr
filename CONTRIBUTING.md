# Contributing to PacketcraftR

PacketcraftR welcomes focused fixes, features, and documentation changes.
Report suspected vulnerabilities through [SECURITY.md](SECURITY.md), not a
public issue.

## Setup and checks

The workspace uses Rust 2024. `rust-toolchain.toml` pins the toolchain and
`rust-version` in `Cargo.toml` is the MSRV; `.config/nextest.toml` names the
cargo-nextest version. The project does not configure a compiler wrapper or
linker, so Cargo and the Rust toolchain use their platform defaults.
All-feature Linux builds also need libpcap development files.

Use locked dependencies and run the checks that cover your change:

```console
cargo build --locked
cargo nextest run --locked --workspace --no-default-features
cargo nextest run --locked --workspace
cargo nextest run --locked --workspace --all-features
cargo test --locked --workspace --all-features --doc
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
cargo deny check
```

Cargo runs doctests separately because nextest does not. No-default features
keep native providers disabled, the default enables interface enumeration and
passive route lookup (Unix enumeration reads the same route backend, so
`native-interfaces` requires `native-route` there), and all features enable
every native provider. The
[CI workflow](.github/workflows/ci.yml) is the authoritative check set. It
runs all-feature tests on Linux only; macOS and Windows get an all-feature
`cargo check`, since their capture backends need Npcap or a system libpcap.

## Architecture

Cargo manifests and `cargo metadata` are the source of truth for packages,
features, and dependencies. Keep the graph acyclic. In particular, the core
crate must remain independent of native I/O and live workflows so offline
analysis cannot acquire a resolver, route, capture, or transmission seam.
See [AGENTS.md](AGENTS.md) for ownership and coding rules.

Keep `unsafe` inside `packetcraftr-netio/src/platform/` and give every unsafe
block a specific `SAFETY` explanation. Avoid narrowing `as` conversions; use
checked conversions or the repository's tightly scoped `#[expect]` convention
with the bounding invariant stated. The same applies to plain indexing and
unchecked arithmetic, which the workspace lints deny in library code.

## Issues and pull requests

Use the general issue form for portable or offline defects and the native form
for interfaces, routes, capture, injection, raw sockets, or live workflows.
Include the version, feature profile, platform, minimal reproduction, expected
and actual results, and sanitized diagnostics. Never post production captures,
credentials, public-target details, or exploit information.

Each pull request should:

- have one primary responsibility and keep mechanical refactoring separate
  from behavior changes;
- use focused Conventional Commits such as
  `fix(reassembly): handle stream timeout`;
- describe public API, schema/output, feature, and platform impact;
- update `[Unreleased]` in `CHANGELOG.md` for user-visible changes;
- update schemas and published examples together when a serialized contract
  changes;
- record work you deliberately left out in [TODOS.md](TODOS.md), with the
  change that deferred it; and
- list the exact validation commands and outcomes.

Review the full diff before requesting review. Cross-boundary changes need
review from every affected owner. Native networking changes should cover the
relevant unavailable-backend, permission, stale-interface, timeout,
cancellation, partial-I/O, queue, accounting, and cleanup paths.
