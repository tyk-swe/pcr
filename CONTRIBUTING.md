# Contributing to PacketcraftR

PacketcraftR welcomes focused fixes, tests, and documentation improvements.

Report suspected vulnerabilities through [SECURITY.md](SECURITY.md), not a
public issue.

## Development setup

The package uses Rust 2024. Rust 1.97 is pinned in `rust-toolchain.toml`, and
Rust 1.96 is the minimum supported version. Normal test execution requires
cargo-nextest 0.9.140. Linux builds use clang as the linker driver and mold as
the linker; all-feature builds also require the `libpcap-dev` development
package. Install the pinned test runner with
`cargo install --locked cargo-nextest --version 0.9.140` if it is not already
available.

Common checks are:

```console
cargo build --locked
cargo nextest run --locked --no-default-features
cargo test --doc --locked --no-default-features
cargo nextest run --locked
cargo test --doc --locked
cargo nextest run --locked --all-features
cargo test --doc --locked --all-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps
cargo deny check
```

The no-default test profile builds every crate with its native features turned
off, so the CLI and its tests still run but every native provider fails closed
with a capability error. Default and all-feature profiles add interface
enumeration and the remaining native providers.

The complete enforced matrix, tool versions, thresholds, release checks, and
artifacts live in the [CI workflows](.github/workflows/).

Linux native networking also has a strict, opt-in namespace harness. It is not
part of ordinary unprivileged `cargo nextest run`; its dedicated entry point
fails when prerequisites or privileges are unavailable:

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

The canonical library domains are `analysis`, `budget`, `capture`, `client`,
`error`, `net`, `output`, `packet`, `protocol`, `session`, and `workflow`, each
a crate under `crates/` named `packetcraftr-<domain>`. Prefer specific module
names that describe their responsibility, and keep the inter-crate dependency
graph acyclic. Unsafe code is confined to
`crates/packetcraftr-net/src/platform/`, and every unsafe block needs a
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
  `cargo nextest run --locked --test schema_contract --test document_examples`.
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
| `area/protocol` | Protocol codecs, registry, matching, catalog, and support tables. |
| `area/workflow` | Replay, scan, traceroute, DNS, and fuzz workflows. |
| `area/cli` | CLI arguments, execution, help, diagnostics, and rendering. |
| `area/output` | Output models, envelope, schemas, and published documents. |
| `area/docs` | Repository and user documentation. |
| `type/refactor` | Behavior-preserving structural work. |
| `type/bug` | A defect or regression. |
| `type/test` | Test coverage or test infrastructure. |

Do not use `type/refactor` for a change that intentionally alters behavior.
