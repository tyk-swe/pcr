# Contributing to PacketcraftR

PacketcraftR welcomes focused fixes, tests, and documentation improvements.

Report suspected vulnerabilities through [SECURITY.md](SECURITY.md), not a
public issue.

## Development setup

The workspace uses Rust 2024. Rust 1.97 is pinned in `rust-toolchain.toml`, and
Rust 1.96 is the minimum supported version, declared once in
`[workspace.package]`. Linux all-feature builds require the `libpcap-dev`
development package.

The root `packetcraftr` package is a façade over the member crates in
`crates/`; see [AGENTS.md](AGENTS.md) for the crate map and the dependency
direction. Add implementation to the member crate that owns the domain, never
to the root package.

Common checks are:

```console
cargo build --locked
cargo test --locked --workspace --no-default-features
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo fmt --all -- --check
scripts/check-source-conventions
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
cargo deny check
```

The no-default test profile is intentionally library-only: Cargo skips the
`packetcraftr` binary and `tests/cli.rs` unless the `cli` feature is enabled.
`packetcraftr-cli` itself still compiles and runs its own unit tests, because a
member crate has no feature gates of its own. Default and all-feature profiles include `cli` and run the
complete CLI test suite.

The complete enforced matrix, tool versions, thresholds, release checks, and
artifacts are recorded in the [CI baseline](docs/ci-baseline.md).

Linux native networking also has a strict, opt-in namespace harness. It is not
part of ordinary unprivileged `cargo test`; its dedicated entry point fails
when prerequisites or privileges are unavailable:

```console
sudo -v && scripts/test-native-e2e
```

The harness builds the all-feature PacketcraftR binary once, then exercises
isolated IPv4/IPv6 route planning, native Layer 3 send, and UDP exchange paths
with independent socket fixtures. See
[Linux native E2E testing](docs/native-e2e.md) for topology, prerequisites,
diagnostics, and CI details.

The separate `fuzz/` package has its own lockfile, targets, corpora, and
dictionaries. CI smoke-tests every committed fuzz target.

## Issues

Use the general bug form for portable packet, capture-file, output, CLI, or
workflow defects. Use the native-networking form for failures involving live
interfaces, routes, capture, injection, raw sockets, libpcap, or Npcap. Include
the exact version, feature profile, operating system, minimal reproduction,
expected result, actual result, and sanitized diagnostics.

Do not post production packet captures, credentials, public-target details, or
exploit information. Create the smallest synthetic fixture that demonstrates
the issue.

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
- Update fixtures, goldens, examples, and schemas together when an approved
  serialized or CLI contract changes.

The canonical library domains are `capture`, `client`, `error`, `net`,
`output`, `packet`, `policy`, `protocol`, `session`, and `workflow`, each backed
by the member crate of the same name. Prefer specific module names that describe
their responsibility. Unsafe code is confined to
`crates/packetcraftr-net-native/src/platform/`, and every unsafe block needs a
specific `SAFETY` explanation.

## Code review

Every pull request requires code review approval. A cross-boundary pull
request needs approval for every affected boundary.

Native networking changes must test relevant failure paths, not only successful
I/O. Depending on the change, cover permission or unavailable-backend errors,
stale interface identity, timeouts and cancellation, partial I/O, queue
overflow, accounting failure, and cleanup or shutdown. Prefer deterministic
unit tests with controlled providers; add platform evidence when backend code
changes.

## Test plan

List exact commands and outcomes in the pull request. Select checks according
to risk:

- Packet, schema, or output changes: run the focused regression tests plus
  `cargo test --locked --test schema_contract --test document_examples`.
- Public API changes: run the relevant downstream `external_*` integration
  tests.
- Feature-gated changes: test no-default, default, and all-feature profiles.
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
| `area/protocol` | Protocol codecs, registry, matching, catalog, and support manifest. |
| `area/workflow` | Replay, scan, traceroute, DNS, and fuzz workflows. |
| `area/cli` | CLI arguments, execution, help, diagnostics, and rendering. |
| `area/output` | Output models, envelope, schemas, and published documents. |
| `area/docs` | Repository and user documentation. |
| `type/refactor` | Behavior-preserving structural work. |
| `type/bug` | A defect or regression. |
| `type/test` | Test coverage or test infrastructure. |

Do not use `type/refactor` for a change that intentionally alters behavior.
