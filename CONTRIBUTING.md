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
| Portable | `--no-default-features` | Offline processing; native providers report unavailable |
| Default | none | Passive interface enumeration and route lookup |
| Pcap-free | `--no-default-features --features native-layer3` | Default capabilities and raw Layer 3 I/O |
| Full native | `--all-features` | All providers, including Layer 2 capture/injection |

Features belong to netio; workflow and CLI features select those capabilities.
CI tests full native, portable and the exact pcap-free feature profile on Linux.
macOS and Windows execute deterministic contracts with all native features.
The pcap-free binary is built independently and checked for absence of libpcap. Release checks cover
packaging, checksums, and provenance separately.

## Optional tools

Use `cargo doc --locked --workspace --all-features --no-deps` for API docs,
`cargo bench -p packetcraftr-core` for benchmarks, and
`./scripts/measure-memory.sh` for Linux peak-RSS profiling. Coverage is a manual
workflow. Review unsafe wrappers, parser boundaries, rejected authorization and
cleanup branches to choose a short risk backlog; there is no global coverage
percentage gate. Dependency advisory/license checks run weekly, for dependency
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

The opt-in `python3 scripts/test-native-isolated.py --binary PATH_TO_FULL_NATIVE`
requires Linux user/network namespaces and iproute2. It refuses an unchanged
namespace or any interface besides loopback, creates a local UDP responder and
checks a capture-ready native exchange plus its terminal trace. It records OS,
binary feature/version and packet evidence. It is not an ordinary PR gate;
unavailable namespaces are a reported capability limit, not a passing native test.
Hardware Layer 2/neighbor and macOS/Windows live tests still need dedicated labs.

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
