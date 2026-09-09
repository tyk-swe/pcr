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
CI tests full native, portable and the exact pcap-free feature profile on Linux,
checks that the pcap-free binary does not link libpcap, builds documentation with
warnings denied for those profiles, and checks crate dependency direction with
`scripts/check-architecture.py`. macOS and Windows execute deterministic contracts
with all native features. Release checks cover packaging, checksums, and provenance
separately.

## Optional tools

Use `RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps` for API docs,
`cargo bench -p packetcraftr-core` for benchmarks, and
`python3 scripts/measure-analysis.py` against a release build of the portable
CLI for Linux peak-RSS profiling. Dependency advisory/license checks run in CI and
at release preflight; `cargo deny --locked check` runs the same policy locally.

Fuzzing has its own manifest and lockfile. Update both dependency graphs when
changing shared dependencies. Bounded fuzz runs are scheduled and can also run
locally with cargo-fuzz and the known-working nightly-2026-08-28 toolchain, for example:

```sh
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
(cd fuzz && cargo +nightly-2026-08-28 fuzz run --target x86_64-unknown-linux-gnu ip_reassembly corpora/ip_reassembly -- -max_total_time=30)
```

Scheduled fuzz runs seed from the checked-in `fuzz/corpora` and published
examples. Manual campaigns run 30, 300, or 900 seconds per target; 30-second
smoke success is not a coverage claim. Crash inputs are uploaded as artifacts.
Minimize fixed crashes with `cargo fuzz tmin` and check the tiny input into the
owning crate's regression fixtures, not only CI artifacts. Update the nightly pin
intentionally after a local smoke.

`python3 scripts/test-native-isolated.py --binary PATH_TO_FULL_NATIVE` builds and
runs the ignored native contract target in a fresh Linux user/network namespace.
It checks a local UDP exchange, readiness, idle deadlines/cancellation, repeated
cleanup, queue saturation, native filter errors and interface disappearance.
The initial namespace must contain only loopback; the disappearance case creates
and deletes a namespace-local dummy interface. No external destinations are used.
For restricted hosts, prebuild the test executable and use `sudo` with
`--native-test-binary PATH`; the launcher maps namespace root to the invoking
checkout owner's UID. It does not relax host namespace policy or file permissions.

This suite runs in Linux CI. Missing prerequisites, failed namespace creation and
skipped scenarios are failures. Windows/macOS privileged runtime scenarios remain
unexercised.

Dependency upgrades
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
