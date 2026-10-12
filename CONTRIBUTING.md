# Contributing to PacketcraftR

Report vulnerabilities through [SECURITY.md](SECURITY.md). Include a minimal
reproduction, platform, feature profile, and sanitized diagnostics in ordinary
bug reports; keep production captures and credentials private.

## Development

Rustup selects the supported toolchain and rustfmt/Clippy components from
`rust-toolchain.toml`; `Cargo.toml` declares the same Rust version. Linux Layer 2
builds need `libpcap-dev`, macOS uses system libpcap, and Windows loads Npcap at
runtime. All profiles need a C compiler for rustls/ring, without OpenSSL.

Run the affected crate's tests while editing, including relevant profiles and
doctests. The comprehensive Linux check is:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

[Build profiles](README.md#build-from-source) own feature selection.
Workspace commands qualify features as `packetcraftr-cli/native-layer2` or
`packetcraftr-cli/native-layer3`. Ordinary TCP providers work independently of
native packet-I/O features. CI's exact commands live in
[ci.yml](.github/workflows/ci.yml): five-profile Clippy on Linux, macOS Intel/Arm64,
and Windows, platform tests, Rust docs, fixtures, decoder comparisons, and fuzz
compilation. Linux results and cross-compilation do not validate another OS's
native runtime.

Keep development debug information and release overflow checks enabled by default.
For a storage-constrained local run, temporary `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`, and `CARGO_INCREMENTAL=0` preserve assertions and
checks while reducing debug detail. After feature changes, build the workspace
then the CLI with `-v` in the same target directory and check artifact reuse.

## Repository boundaries

| Crate | Owns |
| --- | --- |
| `packetcraftr-core` | Packets, codecs/reflection, bounded documents, capture formats, filters, offline analysis |
| `packetcraftr-netio` | Provider contracts and native resources |
| `packetcraftr` | Live workflows, policy, preparation, budgets, evidence |
| `packetcraftr-cli` | Arguments, provider composition, rendering, machine output |

Keep types, behavior, and tests with their domain owner. Core stays independent
of native I/O and workflows. Split modules by responsibility; use `foo.rs` beside
`foo/`, never `mod.rs`. Expose capabilities, keep assembly private, and avoid
equivalent public paths.

Netio's `platform/` contains native code grouped by capability then backend;
shared backend plumbing belongs in `platform::common`. Checks needing no native
call belong to the capability module. Platform selection stays in `build.rs` and
`platform::dispatch`; code outside `platform/` uses emitted capability cfgs such
as `native_route`, never direct `target_os` gates.

Only `packetcraftr-netio/src/platform/` may contain unsafe code. Every unsafe block
has a `SAFETY` comment explaining its specific invariant; other crate roots forbid
unsafe. Prefer typed errors preserving their original sources.

Preserve untrusted-input and resource checks, wire values, unknown/malformed
bytes, capture scope, and timestamps. Live operations authorize before active
discovery and check final endpoints and bytes before transmission. Use finite
budgets; examples and tests use loopback, documentation addresses, or isolation.

## Tests

Unit tests live beside their owner in one inline `mod tests` or `<module>/tests.rs`;
in-crate helpers use `test_support`. Public regressions live in
`crates/*/tests/integration/`, declared by `main.rs` so each crate links one binary.
Shared integration helpers belong in `tests/common/`.

| Suffix | Purpose |
| --- | --- |
| `*_contracts.rs` | Public behavior and meaningful failure paths; default choice |
| `*_conformance.rs` | Schema and wire formats |
| `*_matrix.rs` | Exhaustive combinations |
| `*_smoke.rs` | Shallow checks over real inputs, including fuzz corpora |

Top-level test binaries are reserved for process/crate-root requirements:
`native_isolated.rs`, process-wide counter suites, and `fuzz_smoke.rs` including
fuzz-target sources. Avoid source-layout tests and duplicate verification. Run a
focused regression with `cargo test --locked -p CRATE --test integration MODULE::`.

## Optional tools

Build Rust docs with warnings denied for portable, pcap-free, and full-native
profiles, as CI does:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps --document-private-items
```

- `cargo bench -p packetcraftr-core` runs core benchmarks.
- `cargo deny --locked check` and `cargo deny --locked --manifest-path fuzz/Cargo.toml check advisories` enforce dependency policy.
- `python3 -m unittest discover -s scripts -p 'test_*.py'` checks validation scripts;
  `python3 scripts/check-architecture.py` checks dependency boundaries.
- YAML dependency changes also run `cargo test --locked -p packetcraftr-core --lib document::parse`.

Fuzzing has its own manifest and lockfile; update both dependency graphs when
shared dependencies change. The pinned nightly is shared by
[ci.yml](.github/workflows/ci.yml) and [fuzz.yml](.github/workflows/fuzz.yml).

```sh
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
RUSTFLAGS="-D warnings" cargo +nightly-2026-08-28 check --locked --manifest-path fuzz/Cargo.toml --bins
(cd fuzz && cargo +nightly-2026-08-28 fuzz run --target x86_64-unknown-linux-gnu ip_reassembly corpora/ip_reassembly -- -max_total_time=30)
```

Minimize crashes with `cargo fuzz tmin` and retain regressions with their owner.
A short smoke campaign is not a coverage claim. Update the nightly pin after a
local smoke and record it with corpus changes.

## Validation evidence

[Native validation](docs/native-validation.md) owns prerequisites, isolation,
reviewed workflows, and platform limits. Native/service acceptance requires both
IPv4 and IPv6 loopback. Missing prerequisites, failed isolation, skipped checks,
and unavailable address families do not count as completed runtime evidence.
Reports are retained on failure as well as success; release preflight requires
successful, clean, exact-commit push-CI evidence.

`scripts/validation_evidence.py` owns validation-artifact version 1. Duplicate,
missing, skipped, or contradictory required results fail validation. Regenerate
older reports; change the version and inventory deliberately rather than relabeling
history. This internal contract is separate from product output schemas.

`python3 scripts/benchmark-scanner.py` exercises the independent
[scanner corpus](docs/scanner-corpus.v1.json) through injected scan/traceroute
providers and native loopback connect cells. Each repetition measures 88 conditions,
work, elapsed time, exact retained evidence, and process peak RSS. Optional pinned
Nmap comparisons measure agreement; missing tools remain unavailable.

`python3 scripts/check-decode-oracle.py --binary target/release/packetcraftr`
compares offline fields and TLS JA3 against TShark 4.6.4; `--full` adds the weekly
corpus. `scripts/build-decode-oracle.sh` builds the checksum-pinned oracle.

Forwarding changes run the [regression harness](docs/verification-contract.md#reproduction-bundle)
and [external consumer](docs/consumer-compatibility.md#rust-api-adoption), plus
relevant core/CLI integration modules. Keep schemas, examples, CLI tests, migration
notes, and release assets synchronized when machine contracts change.

## Changes and reviews

Use `tyk/{branch-name}` for coding-agent branches and focused Conventional Commits
without `packetcraftr-` in scopes. Record user-visible and breaking changes in
`[Unreleased]`. PRs explain the problem, impact, linked issue when available, and
exact validation results; request applicable [CODEOWNERS](.github/CODEOWNERS) review.

Native changes cover unavailable backends, stale interfaces, timeouts, cancellation,
partial I/O, accounting, and cleanup with fake providers or isolated fixtures.
Scanner changes retain the separate [evidence vocabularies](docs/scanner-evidence.md).
Bundled scanner data needs a completed [provenance review](docs/scanner-data-policy.md).
Administrator-owned reviewers and merge protections govern privileged validation.
