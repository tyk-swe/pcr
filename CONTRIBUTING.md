# Contributing to PacketcraftR

PacketcraftR welcomes focused fixes, features, and documentation improvements.

Report suspected vulnerabilities through [SECURITY.md](SECURITY.md), not a
public issue.

## Development setup

The package uses Rust 2024. Rust 1.97 is pinned in `rust-toolchain.toml`, and
Rust 1.96 is the minimum supported version. Linux builds use clang as the
linker driver and lld as the linker; all-feature builds also require the
`libpcap-dev` development package.

Common checks are:

```console
cargo build --locked
cargo check --locked --workspace --no-default-features
cargo check --locked --workspace
cargo check --locked --workspace --all-features
cargo nextest run --locked --workspace --no-default-features
cargo nextest run --locked --workspace
cargo nextest run --locked --workspace --all-features
cargo test --locked --workspace --all-features --doc
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps
cargo deny check
```

Nextest 0.9.143 or newer is required by the repository configuration. Nextest
runs unit and integration tests without retries; doctests use Cargo's standard
test runner and must be run separately with the command above.

The no-default profile builds every crate with its native features turned off,
so native providers fail closed with a capability error. Default and
all-feature profiles add interface enumeration and the remaining native
providers.

## Issues

Use the general bug form for portable packet, capture-file, output, CLI, or
workflow defects. Use the native-networking form for failures involving live
interfaces, routes, capture, injection, raw sockets, libpcap, or Npcap. Include
the exact version, feature profile, operating system, minimal reproduction,
expected result, actual result, and sanitized diagnostics.

Do not post production packet captures, credentials, public-target details, or
exploit information. Create the smallest synthetic input that demonstrates the
issue.

## Pull request scope

Every pull request must have one primary responsibility.

- Keep mechanical refactoring separate from behavior changes. If both are
  needed, land the behavior-preserving refactor first and review the behavioral
  change independently.
- Keep commits focused and use Conventional Commits:
  `<type>(<scope>): <description>`.
- Record user-visible work under the appropriate `[Unreleased]` heading in
  `CHANGELOG.md`.
- Disclose public Rust API changes explicitly.
- Disclose schema, output, envelope, manifest, and published-document changes
  explicitly.
- Keep modules cohesive and split them along existing domain boundaries when
  distinct responsibilities emerge.
- Update published examples and schemas together when an approved serialized
  or CLI contract changes.

Responsibility, rather than a fixed topology, determines package and module
ownership:

- `packetcraftr-core` owns cross-domain budgets and classified boundary errors.
- `packetcraftr-capture` owns portable, bounded capture-file I/O.
- `packetcraftr-packet` owns runtime-neutral packet models, registries,
  construction, dissection, filtering, and protocol identity.
- `packetcraftr-protocol` owns built-in codecs, matchers, capture roots, and
  their deterministic registration.
- `packetcraftr-analysis` owns the offline capture pipeline, statistics,
  following, expert diagnostics, and reassembly.
- `packetcraftr-net` owns interfaces, route/neighbor planning, provider traits,
  and the narrowly reviewable native adapters under `src/platform/`.
- `packetcraftr-client` owns traffic policy plus policy-gated send and exchange
  lifecycles; `packetcraftr-workflow` owns bounded replay, scan, traceroute,
  DNS, and fuzz operations.
- `packetcraftr` is the consumption facade and owns serialized output contracts;
  `packetcraftr-cli` owns process behavior and command-line presentation.

Cargo manifests and `cargo metadata` are the only complete description of the
workspace graph. Keep the graph acyclic and preserve the semantic boundary
that `packetcraftr-analysis` has no direct or transitive path to the live
capability owners `packetcraftr-client` and `packetcraftr-net`. Adding a
legitimate package or dependency does not require editing a global registry or
edge table.

Common changes start here:

- Add or change one CLI option in
  `crates/packetcraftr-cli/src/commands/<command>/arguments.rs`; execution,
  command-specific conversion, and rendering stay in the same command subtree.
- Change a serialized result in `crates/packetcraftr/src/output/<command>.rs`
  (or the multi-file `output/dns/` domain) without changing its workflow model.
- Add an offline operation under `crates/packetcraftr-analysis/src/` and compose
  it from the matching CLI command without introducing a live dependency.
- Add a live workflow under `crates/packetcraftr-workflow/src/`; shared target,
  clock, batch, correlation, or evidence mechanics belong to the existing
  `target`, `clock`, or private `probe` owners rather than a generic bucket.
- Add a native backend only under
  `crates/packetcraftr-net/src/platform/`, keeping provider-facing contracts in
  the surrounding network domain.
- Add a built-in protocol beside its protocol family, then add its neutral
  identity/capability row to `packetcraftr-packet/src/protocol_catalog.rs` and
  its payload edges or capture roots to the focused registration modules. This
  split prevents a packet-framework → built-in-codec dependency cycle.

Unsafe code and FFI are confined to `crates/packetcraftr-net/src/platform/`;
every unsafe block needs a specific `SAFETY` explanation. Prefer module names
that describe their responsibility and keep the Cargo graph acyclic.

## Code review

Every pull request requires code review approval. A cross-boundary pull
request needs approval for every affected boundary.

Native networking changes must account for relevant failure paths, not only
successful I/O. Depending on the change, cover permission or
unavailable-backend errors, stale interface identity, timeouts and cancellation,
partial I/O, queue overflow, accounting failure, and cleanup or shutdown. Add
platform evidence when backend code changes.

## Validation plan

List exact commands and outcomes in the pull request. Select checks according
to risk:

- Packet, schema, or output changes: inspect representative output and keep
  published examples and schemas synchronized.
- Public API changes: build affected downstream packages and generate API
  documentation with warnings denied.
- Feature-gated changes: check no-default, default, and all-feature profiles.
- Platform changes: include the affected platform and relevant failure-path
  evidence.
- Documentation-only changes: run the repository formatting/documentation
  checks that apply and `git diff --check`.

Before requesting review, inspect the full diff and confirm that unrelated
runtime behavior, packet semantics, CLI behavior, schemas, and output
serialization did not move.

## Labels

Use one or more area labels and one type label.

| Label | Use |
| --- | --- |
| `area/platform` | Native platform backends, interfaces, routes, capture, and transmission. |
| `area/client` | Client planning, send, policy, and exchange lifecycle. |
| `area/protocol` | Protocol codecs, registry, matching, catalog, and support tables. |
| `area/workflow` | Replay, scan, traceroute, DNS, and fuzz workflows. |
| `area/cli` | CLI arguments, execution, help, diagnostics, and rendering. |
| `area/output` | Output models, envelope, schemas, and published documents. |
| `area/docs` | Repository and user documentation. |
| `type/refactor` | Behavior-preserving structural work. |
| `type/bug` | A defect or regression. |

Do not use `type/refactor` for a change that intentionally alters behavior.
