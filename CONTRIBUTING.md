# Contributing to PacketcraftR

PacketcraftR welcomes focused fixes, tests, and documentation improvements.
During the `0.4.0-beta.2` cycle, start with the
[Phase 0 stabilization scope](docs/roadmap/0.4.0-beta.2-phase-0.md). New
protocols, new commands, output v2, async migration, broad platform rewrites,
and crates.io publication are not part of this milestone.

Report suspected vulnerabilities through [SECURITY.md](SECURITY.md), not a
public issue.

## Development setup

The package uses Rust 2024. Rust 1.97 is pinned in `rust-toolchain.toml`, and
Rust 1.96 is the minimum supported version. Linux all-feature builds require
the `libpcap-dev` development package.

Common checks are:

```console
cargo build --locked
cargo test --locked --no-default-features
cargo test --locked
cargo test --locked --all-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps
cargo deny check
```

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
- Do not add a source file larger than 20 KiB or roughly 600 lines. Split code
  along existing domain boundaries before it reaches that size.
- Update fixtures, goldens, examples, and schemas together when an approved
  serialized or CLI contract changes.

The canonical library domains are `capture`, `client`, `error`, `net`,
`output`, `packet`, `protocol`, `session`, and `workflow`. Do not introduce
generic `internal`, `_impl`, or `#[path = ...]` modules. Unsafe code is confined
to `src/net/platform/`, and every unsafe block needs a specific `SAFETY`
explanation.

## Temporary contract freeze

The stabilization freeze covers:

- `schemas/packetcraftr.packet.v1.schema.json`;
- `schemas/packetcraftr.output.v1.schema.json`;
- the output envelope and command/mode vocabulary;
- the protocol-support manifest structure;
- every published document under `examples/documents/`.

Existing fields cannot be removed, renamed, made newly required, or
semantically changed. Only backward-compatible optional additions may be
considered, and they require recorded approval from the Contract Senior Owner.
See the [Phase 0 scope](docs/roadmap/0.4.0-beta.2-phase-0.md) for the complete
freeze and exception criteria.

## Senior review

Safety-sensitive paths require role-specific approval under
[review ownership](docs/governance/review-ownership.md). A cross-boundary pull
request needs approval for every affected boundary. Authors cannot approve
their own changes.

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
- Public API or architecture changes: include `public_surface` and
  `architecture` integration tests.
- Feature-gated changes: test no-default, default, and all-feature profiles.
- Platform changes: include the affected platform and relevant failure-path
  evidence.
- Documentation-only changes: run the repository formatting/documentation
  checks that apply and `git diff --check`.

Before requesting review, inspect the full diff and confirm that unrelated
runtime behavior, packet semantics, CLI behavior, schemas, and output
serialization did not move.

## Labels

Use one or more area labels, one type label, and a priority label when the
stabilization coordinator assigns one.

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
| `priority/p0` | A release-blocking stabilization issue. |
| `priority/p1` | High-priority stabilization work that needs an explicit disposition. |

Do not use `type/refactor` for a change that intentionally alters behavior.
