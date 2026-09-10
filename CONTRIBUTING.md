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
| Pcap-free | `--no-default-features --features native-layer3` | Default capabilities and raw Layer 3 I/O |
| Full native | `--all-features` | All providers, including Layer 2 capture/injection |

Features belong to netio; workflow and CLI features select those capabilities.
The explicitly selected standard-library TCP provider is independent of these
packet-I/O feature flags; it remains available in the portable library profile.
CI tests full native, portable and the exact pcap-free feature profile on Linux.
Default and all-features contracts run on Intel macOS, Apple Silicon macOS,
and Windows. PRs run five jobs: full-native Linux, portable
Linux, and the three platform jobs. The pcap-free binary is built independently
and checked for absence of libpcap. Linux also runs architecture and validation
failure fixtures, archive-verifier failure fixtures, and documentation checks.
Release builds verify packaged archives, linkage, checksums, and provenance.

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

The decoder oracle and isolated Linux native validation run on main pushes,
weekly, and through manual CI dispatch; PRs skip both jobs. The weekly decoder
run adds the full generated growth/overlap corpus. `scripts/build-decode-oracle.sh` builds
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
full-native profiles. Dependency upgrades
must also pass `document_limit_contracts::yaml_stream_exhaustion_dependency_contract`
until the YAML dependency provides a typed streaming end signal.

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
