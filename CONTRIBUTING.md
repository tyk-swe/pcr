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
CI tests full native and portable on Linux, tests passive providers on macOS
and Windows, and compiles their full-native backends. The pcap-free binary is
built independently and checked for absence of libpcap. Release checks cover
packaging, checksums, and provenance separately.

## Optional tools

Use `cargo doc --locked --workspace --all-features --no-deps` for API docs,
`cargo bench -p packetcraftr-core` for benchmarks, and
`./scripts/measure-memory.sh` for Linux peak-RSS profiling. Coverage is a manual
workflow. Dependency advisory/license checks run weekly and for dependency
changes; `cargo deny check` is available locally when needed.

Fuzzing has its own manifest and lockfile. Update both dependency graphs when
changing shared dependencies. Bounded fuzz runs are scheduled and can also run
locally with cargo-fuzz and nightly Rust, for example:

```sh
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
cargo +nightly fuzz run ip_reassembly fuzz/corpora/ip_reassembly -- -max_total_time=30
```

## Changes and reviews

Include a minimal reproduction, platform, feature profile, and sanitized
diagnostics in bug reports. Do not post production captures or credentials.
Native changes should cover affected unavailable-backend, stale-interface,
timeout, cancellation, partial-I/O, accounting, and cleanup behavior using
fake providers or isolated loopback tests. Record unavailable platform checks
as unavailable. Prefer one authoritative implementation over compatibility
wrappers; version changed machine contracts and migrate their consumers.
