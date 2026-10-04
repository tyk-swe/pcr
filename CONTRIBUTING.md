# Contributing to PacketcraftR

Report vulnerabilities through [SECURITY.md](SECURITY.md). The compact
[repository guide](AGENTS.md) describes ownership, invariants, and the
comprehensive checks.

## Development

Install Rust with rustup; the repository selects its supported stable toolchain
and rustfmt/Clippy components. Linux full-native builds require `libpcap-dev`;
macOS uses system libpcap; Windows Layer 2 operations load Npcap at runtime.
Cargo uses the platform's default compiler and linker.

While editing, run `cargo test --locked -p <affected-crate>` (doctests included)
and the relevant integration test or feature profile. There is no required test
runner or command wrapper.

The five feature profiles (portable, default, Layer 2 only, pcap-free, full
native) are listed in the README's
[Build from source](README.md#build-from-source). Their arguments apply to
`-p packetcraftr-cli`; workspace-wide commands qualify the features as
`packetcraftr-cli/native-layer2`, as below. Features belong to
netio; workflow and CLI features select those capabilities. The explicitly
selected standard-library TCP provider is independent of these packet-I/O
feature flags; it remains available in the portable library profile.

`.github/workflows/ci.yml` is the source of truth for what CI runs: Clippy with
warnings denied for all five profiles on Linux, Intel macOS, Apple Silicon
macOS, and Windows, runtime tests per platform, documentation, fixtures,
the decoder oracle, and fuzz-target compilation. `fuzz.yml` runs the fuzz
campaigns, and `release.yml` verifies packaged archives, linkage, checksums,
and provenance. To reproduce the Clippy profiles locally:

```sh
cargo clippy --locked --workspace --all-targets --no-default-features -- -D warnings
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --no-default-features --features packetcraftr-cli/native-layer2 -- -D warnings
cargo clippy --locked --workspace --all-targets --no-default-features --features packetcraftr-cli/native-layer3 -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

Use native macOS and Windows CI results when reviewing platform changes. A
Windows GNU cross-check does not validate MSVC or the Npcap adapter at runtime.

The CLI's default features include `packetcraftr/default` so workspace and
focused CLI builds select the same workflow features and reuse artifacts. After
changing features, run `cargo build --locked --workspace` and then
`cargo build --locked -p packetcraftr-cli -v` in the same target directory, and
confirm that `packetcraftr` and `packetcraftr-cli` are reported `Fresh`. Keep
full development debug information and release overflow checks in the repository
and CI defaults. Keep the integration-test layout unless clean, incremental and focused compile
measurements justify a change; narrow regressions remain runnable as
`cargo test --locked -p CRATE --test TEST_NAME`.

For storage-constrained local validation, temporarily omit debug information and
incremental artifacts as below; use the same environment for the relevant Clippy
commands above. Tests, debug assertions, and overflow checks remain enabled, but
debugger/backtrace detail is reduced and incremental build reuse is disabled.
These overrides do not remove old artifacts; if the disk is already full, first
reclaim unneeded build outputs.

```sh
(
  set -e
  export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
  cargo test --locked --workspace --all-features
)
```

## Optional tools

API documentation as CI builds it, with warnings denied:

```sh
export RUSTDOCFLAGS="-D warnings"
cargo doc --locked --workspace --no-default-features --no-deps --document-private-items
cargo doc --locked --workspace --no-default-features --features packetcraftr-cli/native-layer3 --no-deps --document-private-items
cargo doc --locked --workspace --all-features --no-deps --document-private-items
```

- `cargo bench -p packetcraftr-core` runs the benchmarks.
- `cargo deny --locked check` and
  `cargo deny --locked --manifest-path fuzz/Cargo.toml check advisories` apply
  the dependency policy that `dependency-policy.yml` runs weekly, on dependency
  changes, and again at release preflight.
- YAML dependency upgrades must also pass
  `cargo test --locked -p packetcraftr-core --lib document::parse`, which pins
  the untyped end-of-stream error the parser relies on until the YAML dependency
  provides a typed streaming end signal.

Fuzzing has its own manifest and lockfile; update both dependency graphs when
changing shared dependencies. `fuzz.yml` runs daily and on manual dispatch (30,
300 or 900 seconds per target; a 30-second smoke pass is not a coverage claim).
To run locally, use cargo-fuzz and the pinned nightly:

```sh
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
RUSTFLAGS="-D warnings" cargo +nightly-2026-08-28 check --locked --manifest-path fuzz/Cargo.toml --bins
(cd fuzz && cargo +nightly-2026-08-28 fuzz run --target x86_64-unknown-linux-gnu ip_reassembly corpora/ip_reassembly -- -max_total_time=30)
```

Minimize fixed crashes with `cargo fuzz tmin` and check the tiny input into the
owning crate's regression fixtures, not only CI artifacts. Update the nightly
pin (in `ci.yml` and `fuzz.yml`) intentionally after a local smoke and record it
with corpus changes.

`python3 scripts/check-decode-oracle.py --binary target/release/packetcraftr`
compares curated IPv4/IPv6/extension/fragment/TCP-option/DNS fields and TLS JA3
with TShark 4.6.4, accounting explicitly for opaque physical fragment children;
no live traffic is involved. `--full` adds the larger generated corpus that the
weekly CI run uses. `scripts/build-decode-oracle.sh` builds TShark 4.6.4 from
checksum-pinned upstream source when the exact tool is absent.

## Validation evidence

Isolated Linux native validation, its `sudo` and subordinate-ID setup, and the
commit-bound `native-review.yml` workflow are described in
[native validation](docs/native-validation.md#isolated-linux-setup).

Validation reports are strict: missing prerequisites, failed namespace creation
and skipped scenarios are failures, never passing native evidence, and
Windows/macOS privileged runtime scenarios stay explicitly unexercised. Reports
are archived on failure as well as success, and release preflight requires
clean, exact-commit reports from a successful push CI run.
`scripts/validation_evidence.py` defines the content contract (evidence version
1) that producers check before publishing success; duplicate, skipped, missing
or contradictory results fail it. Regenerate older reports rather than editing
or relabeling them, and update the evidence version and shared inventory
deliberately when changing required coverage. This is an internal
validation-artifact contract, not a product output-schema change.

## Changes and reviews

Include a minimal reproduction, platform, feature profile, and sanitized
diagnostics in bug reports. Do not post production captures or credentials.
Native changes should cover affected unavailable-backend, stale-interface,
timeout, cancellation, partial-I/O, accounting, and cleanup behavior using
fake providers or isolated loopback tests. Record unavailable platform checks
as unavailable.

## Verification and consumer changes

Changes to forwarding semantics require the regression and external-consumer
checks described in [verification-contract.md](docs/verification-contract.md)
and [consumer-compatibility.md](docs/consumer-compatibility.md). Run:

```sh
python3 scripts/check-external-consumer.py
python3 scripts/forwarding-regression.py --binary target/debug/packetcraftr
cargo test --locked -p packetcraftr-core --test forwarding_verification_contracts --test invocation_deadline_contracts --test pipeline_limit_contracts
cargo test --locked -p packetcraftr-cli --test forwarding_verification_contracts --test aggregate_schema_conformance
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
```

Native changes require applicable
[reviewed native evidence](docs/native-validation.md); platform compilation is
not substituted for runtime validation. Required environment reviewers and merge
protections are administrator-owned configuration.
