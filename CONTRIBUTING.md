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
cargo test --locked --workspace --all-features
```

[CI](.github/workflows/ci.yml) defines the platform and feature checks.
For native I/O changes, follow [native validation](docs/native-validation.md);
skipped checks and cross-compilation are not runtime evidence.

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
- Prefer concrete types. Add traits or other abstractions when actual consumers
  need substitution or share meaningful behavior, rather than for one caller.
- Preserve input validation, resource limits, and wire data. Authorize live
  operations before discovery or transmission. Use finite budgets and loopback,
  documentation addresses, or isolated networks in tests and examples.
- Put unit tests beside their code and public regressions in
  `crates/*/tests/integration/`, registered in `main.rs`. Test behavior and failure
  paths; avoid source-layout checks and duplicate coverage.
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
