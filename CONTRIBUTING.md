# Contributing to PacketcraftR

Report vulnerabilities through [SECURITY.md](SECURITY.md). The compact
[repository guide](AGENTS.md) describes ownership, invariants, and checks.

## Development

Install Rust with rustup; the repository selects its supported stable toolchain
and rustfmt/Clippy components. Linux full-native builds require `libpcap-dev`;
macOS uses system libpcap; Windows Layer 2 operations load Npcap at runtime.
Cargo uses the platform's default compiler and linker.

For an ordinary change, run `cargo test --locked -p <affected-crate>` and the
relevant integration test or feature profile. Before integrating a broad
change, run the three comprehensive commands in AGENTS.md. Cargo test includes
doctests. There is no required test runner or command wrapper.

| Profile | Cargo arguments | Capability |
|---|---|---|
| Portable | `--no-default-features` | Offline processing; native packet and route providers report unavailable |
| Default | none | Passive interface enumeration and route lookup |
| Layer 2 only | `--no-default-features --features native-layer2` | Default capabilities and Layer 2 capture/injection |
| Pcap-free | `--no-default-features --features native-layer3` | Default capabilities and raw Layer 3 I/O |
| Full native | `--all-features` | All providers, including Layer 2 capture/injection |

Features belong to netio; workflow and CLI features select those capabilities.
The explicitly selected standard-library TCP provider is independent of these
packet-I/O feature flags; it remains available in the portable library profile.
CI denies Clippy warnings for all five profiles on Linux, Intel macOS, Apple
Silicon macOS, and Windows. Runtime tests cover full native, portable and the
exact pcap-free feature profile on Linux; default and all-features contracts
also run on the three other platform runners. PRs run seven jobs: full-native
Linux, portable Linux, the three platform jobs, the compact decoder oracle, and
compilation of every fuzz target on the pinned nightly with warnings denied.
The pcap-free binary is built independently and checked for absence of libpcap.
Linux also runs architecture and validation failure fixtures, archive-verifier failure
fixtures, and documentation checks.
Release builds verify packaged archives, linkage, checksums, and provenance.

To reproduce the Clippy profiles locally:

```sh
cargo clippy --locked --workspace --all-targets --no-default-features -- -D warnings
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --no-default-features --features packetcraftr-cli/native-layer2 -- -D warnings
cargo clippy --locked --workspace --all-targets --no-default-features --features packetcraftr-cli/native-layer3 -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

Use native macOS and Windows CI results when reviewing platform changes. A
Windows GNU cross-check does not validate MSVC or the Npcap adapter at runtime.

## Optional tools

Use `RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps` for API docs,
`cargo bench -p packetcraftr-core` for benchmarks, and
`python3 scripts/measure-analysis.py` against a release build of the portable
CLI for Linux peak-RSS profiling. Dependency advisory/license checks run weekly, for dependency
changes and at release preflight; `cargo deny --locked check` runs the same policy locally.

Fuzzing has its own manifest and lockfile. Update both dependency graphs when
changing shared dependencies. Bounded fuzz runs are scheduled and can also run
locally with cargo-fuzz and the known-working nightly-2026-08-28 toolchain, for example:

```sh
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
RUSTFLAGS="-D warnings" cargo +nightly-2026-08-28 check --locked --manifest-path fuzz/Cargo.toml --bins
(cd fuzz && cargo +nightly-2026-08-28 fuzz run --target x86_64-unknown-linux-gnu ip_reassembly corpora/ip_reassembly -- -max_total_time=30)
```

Scheduled fuzz runs restore and minimize each target's successful corpus, capped
at 32 MiB. Manual campaigns run 30, 300, or 900 seconds per target; 30-second
smoke success is not a coverage claim. Failures retain the compiler, commit and lockfile
identity. Minimize fixed crashes with `cargo fuzz tmin` and check the tiny input
into the owning crate's regression fixtures, not only CI artifacts. Update the
nightly pin intentionally after a local smoke and record it with corpus changes.

`python3 scripts/check-decode-oracle.py --binary target/release/packetcraftr`
compares curated IPv4/IPv6/extension/fragment/TCP-option/DNS fields and TLS JA3
with TShark 4.6.4. It explicitly accounts for opaque physical fragment children;
no live traffic is involved. See [resource measurements](docs/analysis-resources.md)
for complete workflow/scaling/RSS and separate heaptrack profiles.

The compact decoder oracle runs on pull requests as well as main pushes and
manual CI dispatch. The weekly decoder run adds the full generated growth/overlap
corpus. Isolated Linux native validation runs after integration and through
manual dispatch; the explicit, commit-bound `native-review.yml` workflow can
supply pre-merge evidence after operator approval. `scripts/build-decode-oracle.sh` builds
TShark 4.6.4 from checksum-pinned upstream source when the exact tool is absent.
Reports include input/binary digests, tool identity, allowances and failures.

`python3 scripts/test-native-isolated.py --binary PATH_TO_FULL_NATIVE` builds and
runs the ignored native contract target in a fresh Linux user/network namespace.
It checks a local UDP exchange, readiness, idle deadlines/cancellation, repeated
cleanup, queue saturation, native filter errors and interface disappearance.
The initial namespace must contain only loopback; the disappearance case creates
and deletes a namespace-local dummy interface. No external destinations are used.
For restricted hosts, prebuild the test executable and use `sudo` with
`--native-test-binary PATH`; the launcher maps namespace root to the invoking
checkout owner's UID. It does not relax host namespace policy or file permissions.
On util-linux before 2.40, that `sudo` run asks `newuidmap`/`newgidmap` to apply
the mapping, so authorize the owner's UID and GID for root in `/etc/subuid` and
`/etc/subgid` (for example `root:1001:1`); newer util-linux writes the mapping
directly and needs no subid entry.

When these validation jobs run, missing prerequisites, failed namespace
creation and skipped scenarios are failures, never passing native evidence.
Windows/macOS privileged runtime scenarios remain explicitly unexercised.
Reports are archived on failure as well as success. Release preflight requires
clean, exact-commit reports from a successful push CI run. Evidence schema version
1 also requires the complete named corpus for the declared decoder profile,
exact physical-frame counts, all comparison fields, input/tool digests, the
pinned TShark product/version and a matching nonempty TLS JA3 comparison.
Native evidence must identify both distinct positive namespace IDs, the test
executable, every required scenario with a successful exit code, and a successful
namespace launcher. Duplicate, skipped, missing or contradictory results fail
validation. Producers check the same content contract before publishing success
and emit the version through shared provenance. Reports from before this contract
must be regenerated, not edited or relabeled. Update the evidence version and
shared inventory deliberately when changing required coverage. This is
an internal validation-artifact contract, not a product output-schema change.
The weekly full-corpus policy and exact-commit push-CI selection are unchanged.

CI builds documentation with warnings denied for the portable, pcap-free and
full-native profiles. YAML dependency upgrades must also pass the
`document::parse` unit tests (`cargo test --locked -p packetcraftr-core --lib
document::parse`), which pin the untyped end-of-stream error the parser relies
on, until the YAML dependency provides a typed streaming end signal.

The CLI default features include `packetcraftr/default` so workspace and focused
CLI builds select the same workflow features and can reuse their artifacts.
In three paired Linux measurements, the median workspace-to-focused-CLI
transition fell from 28.38 seconds to 0.23 seconds with aligned features.
Timings depend on the host and cache. Native capabilities are unchanged, and
`--no-default-features` still selects the portable profile. Keep full development
debug information and release overflow checks.

When measuring build changes, use separate before/after target directories,
starting each clean-build sample with an empty directory. Keep the toolchain
and feature profile fixed, alternate run order, and compare medians for clean
workspace builds, rebuilds after the same source edit, and focused tests.
Investigate regressions above 5%. For default artifact reuse,
run `cargo build --locked --workspace` followed by
`cargo build --locked -p packetcraftr-cli -v` in the same target directory and
confirm that both `packetcraftr` and `packetcraftr-cli` are reported `Fresh`.

Keep the existing integration-test layout unless clean, incremental and focused
compile measurements justify a change. Narrow regressions remain runnable as
`cargo test --locked -p CRATE --test TEST_NAME`; test count or file size alone is
not a reason to consolidate fixtures.

## Changes and reviews

Include a minimal reproduction, platform, feature profile, and sanitized
diagnostics in bug reports. Do not post production captures or credentials.
Native changes should cover affected unavailable-backend, stale-interface,
timeout, cancellation, partial-I/O, accounting, and cleanup behavior using
fake providers or isolated loopback tests. Record unavailable platform checks
as unavailable. Prefer one authoritative implementation over compatibility
wrappers; version changed machine contracts and migrate their consumers.

## Verification and consumer changes

Changes to forwarding semantics require the regression and external-consumer
checks described in [verification-contract.md](docs/verification-contract.md)
and [consumer-compatibility.md](docs/consumer-compatibility.md). Run:

```sh
python3 scripts/test-output-consumer.py
python3 scripts/test-forwarding-regression.py
python3 scripts/test-native-capture.py
python3 scripts/check-external-consumer.py
cargo test --locked -p packetcraftr-core --test forwarding_verify --test invocation_deadline_contracts --test pipeline_limit_contracts
cargo test --locked -p packetcraftr-cli --test verify_forwarding --test aggregate_schema_conformance
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
```

Native changes require applicable
[reviewed native evidence](docs/native-validation.md); platform compilation is
not substituted for runtime validation. Required environment reviewers and merge
protections are administrator-owned configuration.
