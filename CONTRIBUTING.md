# Contributing to PacketcraftR

Report bugs with a minimal reproduction, platform, build profile, and sanitized
logs. Report vulnerabilities privately through [SECURITY.md](SECURITY.md).

## Build and check

Use the pinned Rust toolchain and the [build instructions](README.md#build-from-source)
for platform dependencies and feature profiles. Run affected tests while editing.
For a full Linux check:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --no-default-features
cargo test --locked --workspace --all-features
python3 -m unittest discover -s scripts/tests -v
python3 -O -m unittest discover -s scripts/tests -v
```

[CI](.github/workflows/ci.yml) defines the platform and feature checks.
For native I/O changes, follow [native validation](docs/native-validation.md);
skipped checks and cross-compilation are not runtime evidence.

See [Codebase structure](docs/codebase-structure.md) for crate ownership,
fixture locations, and guidance on keeping public paths stable.

## Code and tests

- Keep code with its owner: `packetcraftr-core` for packets and offline analysis,
  `packetcraftr-netio` for providers and native resources, `packetcraftr` for live
  workflows and policy, and `packetcraftr-cli` for arguments and output.
- Keep core independent of native I/O. Native code and unsafe blocks belong in
  `packetcraftr-netio/src/platform/`; every unsafe block needs a `SAFETY` comment.
  Keep platform selection in `build.rs` and `platform::dispatch`.
- Make ownership explicit: reusable services belong to clients; deadlines,
  spending, and preparation state belong to the operation that uses them.
- Name modules for their domain and use module-qualified type names when the
  module supplies the context. Use `foo.rs` beside `foo/`, not `mod.rs`.
- Place CLI implementations in `commands::{packet, files, analyze, network,
  reference}` according to the registry's group assignment. Keep dispatch and
  shared command infrastructure at the commands root; output contracts and
  rendering retain their separate owners.
- Prefer concrete types. Add traits or other abstractions when actual consumers
  need substitution or share meaningful behavior, rather than for one caller.
- Preserve input validation, resource limits, and wire data. Authorize live
  operations before discovery or transmission. Use finite budgets and loopback,
  documentation addresses, or isolated networks in tests and examples.
- Keep the retained public behavior tests in `crates/*/tests/integration/`,
  grouped by domain and registered through `domain.rs` from `main.rs` in one
  `integration` binary per crate. Preserve mixed CLI suites under `contracts`
  and shared fixtures under `tests/common.rs` and `tests/common/`. Anchor
  embedded assets at `CARGO_MANIFEST_DIR`. Portable/native suites are supplemented
  by focused private Rust regressions. Standard-library Python regressions live
  in `scripts/tests/` and run with Python 3.10 or newer; see their
  [guide and ownership index](scripts/tests/README.md). Put regressions in the
  owning suite and share helpers through `support.py`, without imports between
  test modules. Preserve fuzz targets, benchmarks,
  documentation examples, and release packaging checks.
- Keep schemas, examples, tests, and migration notes in sync with public contracts.
  Shared dependency updates must also update the fuzz manifest and lockfile.

Specialized guidance: [forwarding verification](docs/verification-contract.md),
[consumer compatibility](docs/consumer-compatibility.md),
[scanner evidence](docs/scanner-evidence.md), and
[scanner data provenance](docs/scanner-data-policy.md).

## Pull requests

Keep changes focused. Explain the problem, impact, and validation results, including
anything untested. Record user-visible and breaking changes in
[CHANGELOG.md](CHANGELOG.md) under `[Unreleased]`, and request the relevant
[CODEOWNERS](.github/CODEOWNERS) review.

Use Conventional Commits without `packetcraftr-` in scopes. Coding agents use
`tyk/{branch-name}` branches.
