# Repository guide

Use `tyk/{branch-name}` for branches created by coding agents.

PacketcraftR has four directional Rust crates:

- `packetcraftr-core`: packets, codecs/reflection, bounded documents, capture
  formats, filters, and offline analysis.
- `packetcraftr-netio`: provider contracts and native resources. Platform
  selection stays in `build.rs` and `platform::dispatch`; code outside
  `platform/` gates on the capability cfgs `build.rs` emits (`native_route`
  and friends), never on `target_os` directly.
- `packetcraftr`: live workflows, policy, preparation, budgets, and evidence.
- `packetcraftr-cli`: arguments, provider composition, rendering, and the
  versioned machine-output contract.

Keep types, behavior, and tests with their domain owner. Split modules by
responsibility; there is no required filename for types. Expose capabilities,
keep assembly details private, and avoid equivalent public paths. Core must
remain independent of native I/O and workflows.

Use rustfmt and ordinary Cargo commands. Run the relevant tests while editing.
The comprehensive Linux check (requires `libpcap-dev`) is:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

The supported toolchain is pinned in `rust-toolchain.toml` and declared in
`Cargo.toml`. See [CONTRIBUTING.md](CONTRIBUTING.md) for profiles and optional tools.

Preserve checks at untrusted-input and resource boundaries. Keep wire values,
malformed/unknown bytes, capture scope, and timestamps faithful. Live operations
require authorization before active discovery and checks of the final endpoint
and bytes before transmission. Use finite budgets. Examples and tests use
loopback, documentation addresses, or isolated fixtures.

Only `packetcraftr-netio/src/platform/` may contain unsafe code. Every unsafe
block explains its specific invariant in a `SAFETY` comment; other crates
forbid unsafe at their roots. Prefer typed errors with their original sources.

Put unit tests beside their owner and public behavior regressions in
`crates/*/tests/`. Test observable behavior and meaningful failure paths;
avoid source-layout tests and duplicate verification. Keep schemas, examples,
CLI tests, and release assets synchronized when changing machine contracts.

Use focused Conventional Commits without `packetcraftr-` in scopes. Document
breaking changes and user-visible changes in `[Unreleased]`. PRs explain the
problem, impact, linked issue when available, and exact validation results;
request applicable CODEOWNERS review.
