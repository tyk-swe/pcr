# Continuous integration baseline

This document describes the checks enforced by the workflows under
`.github/workflows/`. The workflow definitions remain the executable source of
truth. Update this document in the same change whenever a trigger, runner,
toolchain, feature profile, command, threshold, artifact, or release target
changes.

## Workflow and permission policy

- `.github/workflows/ci.yml` runs for pull requests, pushes to `main`, and
  manual dispatches. Superseded runs for the same workflow and ref are
  cancelled.
- `.github/workflows/fuzz.yml` runs nightly at `02:17 UTC` and by manual
  dispatch.
- `.github/workflows/release.yml` runs for `v*` tags.
- `.github/workflows/native-e2e.yml` is both callable from the main CI workflow
  and manually dispatchable. A CI event invokes it once through the reusable
  workflow; it does not duplicate the native build.
- Workflow-level permissions are `contents: read`. Only the release publishing
  job raises `contents` to `write`.
- Third-party actions are pinned to reviewed full commit SHAs, with the
  corresponding release version recorded in a comment. New actions must follow
  the same policy.

## Supported build and test platforms

| Contract | GitHub runner | Rust target or role |
| --- | --- | --- |
| Linux tests and quality | `ubuntu-24.04` | Hosted Linux x86-64 |
| macOS Intel tests | `macos-15-intel` | `x86_64-apple-darwin` |
| macOS Arm tests | `macos-14` | `aarch64-apple-darwin` |
| Windows tests | `windows-2022` | `x86_64-pc-windows-msvc` |
| FreeBSD portability | `ubuntu-24.04` | Compile-only `x86_64-unknown-freebsd` |
| Privileged native E2E | `ubuntu-24.04` | Linux network namespaces and veth |

The four release targets are `x86_64-unknown-linux-gnu`,
`x86_64-apple-darwin`, `aarch64-apple-darwin`, and
`x86_64-pc-windows-msvc`. CI does not claim runtime FreeBSD qualification:
that target is cross-checked only.

Linux all-feature jobs install `libpcap-dev`. The native E2E job installs
ethtool, iproute2, libpcap development files, Python jsonschema, and shellcheck.

## Rust versions

- `rust-toolchain.toml` pins Rust `1.97.0` with clippy and rustfmt.
- `Cargo.toml` declares `rust-version = "1.96"`.
- Linux quality installs `1.96.0` and checks both the no-default-feature and
  all-feature profiles with all Cargo targets. This is an MSRV compile
  contract, not a second full test matrix.
- Fuzzing uses `nightly-2026-07-11` and cargo-fuzz `0.13.2`.

## Features and build profiles

The declared features are:

- `default = ["cli", "native-interfaces"]`;
- `cli`, for the binary and its argument and terminal dependencies;
- `native-interfaces`, for portable interface enumeration;
- `native-route`, which also enables `native-interfaces`;
- `native-layer2`, which also enables `native-interfaces`;
- `native-layer3`, which also enables `native-interfaces`.

The cross-platform test matrix runs the library tests without default features,
then all Cargo-discovered unit, binary, integration, and documentation tests in
the default and complete profiles:

```console
cargo test --locked --no-default-features
cargo test --locked
cargo test --locked --all-features
```

It also checks the release-mode pcap-free profile:

```console
cargo check --locked --release --no-default-features \
  --features cli,native-route,native-layer3
```

Linux quality adds the depth-two pairwise feature powerset and a complete
all-target profile:

```console
cargo hack check --locked --feature-powerset --depth 2 --all-targets
cargo check --locked --all-targets --all-features
```

FreeBSD portability checks `native-interfaces` without defaults and then the
complete all-feature/all-target profile.

## Formatting, linting, and documentation

- `cargo fmt --all -- --check` is enforced on Linux.
- `cargo clippy --locked --all-targets --all-features -- -D warnings` is
  enforced on Linux, both macOS architectures, and Windows.
- `RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps`
  rejects documentation warnings on Linux.
- `scripts/check-source-conventions` is enforced on Linux. It checks the two
  conventions rustfmt and clippy cannot express: every Rust file under `src/`,
  `tests/`, `benches/`, and `fuzz/fuzz_targets/` opens with the copyright and
  SPDX header pair, and top-level `use` declarations precede the first item
  (`mod.rs` module roots exempted). The script needs no toolchain beyond bash
  and awk, so it adds no measurable time to the quality job.
- The normal Cargo test profiles execute the behavior, schema, CLI, and
  downstream extension integration contracts.

## Benchmark compilation

The Criterion targets `packet_pipeline`, `reassembly`, and `workflow_scan` are
included in the all-target clippy and cargo-hack compilations. These commands
compile-check and lint the benchmark targets without executing their harnesses.
CI does not impose a benchmark performance threshold.

## Coverage

Linux coverage installs cargo-llvm-cov `0.8.7` and enforces at least 75 percent
line coverage:

```console
cargo llvm-cov --locked --all-features --workspace \
  --lcov --output-path lcov.info --fail-under-lines 75
```

The `linux-lcov` artifact contains `lcov.info` and is retained for three days.

## Dependency and cargo-deny policy

The dependency-policy job installs cargo-deny `0.20.2`, verifies that the fuzz
lockfile is current, then checks both dependency graphs:

```console
cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1
cargo deny check
cargo deny --manifest-path fuzz/Cargo.toml check
```

`deny.toml` evaluates all features for the four release target triples. It
denies yanked, unmaintained, and unsound advisories; wildcard dependencies;
unapproved licenses; and unknown registries or Git sources. Duplicate versions
are warnings. The documented `RUSTSEC-2024-0436` exception is the only advisory
ignore. Independent date gates require its internal remediation before
2026-09-16 UTC and reject the exception on and after 2026-10-12 UTC.

## Fuzz checks

Pull requests and manual CI dispatches run 1,000 deterministic iterations for
each committed target with seed `12648430`, a five-second per-input timeout, a
2 GiB RSS limit, the target-specific maximum input length, corpus, and
dictionary. The targets are:

- `capture_reader`;
- `decode_roundtrip`;
- `packet_inputs`;
- `dns_wire`;
- `reassembly_state`.

The nightly workflow runs each target for ten minutes with the same timeout,
memory limit, maximum input length, corpus, and dictionary. Evolving corpora
are cached. A failing campaign uploads
`fuzz-crash-<target>` for seven days.

## Privileged Linux native E2E

The reusable and manually dispatchable Linux workflow runs the repository entry
point:

```console
scripts/test-native-e2e
```

The known `ubuntu-24.04` runner must provide passwordless non-interactive sudo
and authority to create named network namespaces and veth devices, change
namespace forwarding sysctls, and use the `/run/netns` mount. The entry point
performs an actual throwaway namespace/veth probe before building. Missing
commands, unavailable kernel facilities, and insufficient privileges are hard
failures, never skips or synthetic successes.

The test topology has no default route and uses only literal RFC 1918 and ULA
addresses, so fixture traffic has no DNS or public Internet dependency. See
[Linux native E2E testing](native-e2e.md) for the topology and lifecycle.

When the harness step fails,
`linux-native-e2e-diagnostics-<run-id>-<attempt>` is retained for seven days.
It includes `workflow.log`; harness failures additionally include topology
descriptions and before/after-cleanup diagnostics, fixture stdout and stderr,
PacketcraftR invocation records, cleanup errors, the exception trace, and the
complete command audit.

No self-hosted runner label is assumed. If repository or organization policy
removes the required capabilities from `ubuntu-24.04`, an administrator must
provide an equivalently privileged Linux runner and deliberately update the
reviewed `runs-on` label. Until then the strict prerequisite probe will fail.

## Release archive contract

The release preflight requires the `v*` tag to equal the root package version
and requires exactly one non-empty, dated changelog section for that version.
It classifies versions containing `-` as prereleases.

The build matrix creates eight archives: all-feature and pcap-free variants for
each of the four release targets. Every archive contains the executable,
`LICENSE`, `README.md`, and `CHANGELOG.md`. Each extracted executable must
report the exact tagged version. Linux additionally verifies with `ldd` that
the all-feature binary links libpcap and the pcap-free binary does not.
Intermediate release metadata and binary-archive artifacts are retained for
one day.

Before publishing, the workflow requires exactly the eight expected archive
names, creates `SHA256SUMS`, and verifies every checksum. Only after preflight
and every matrix build succeeds does the write-scoped job create the GitHub
release. The package remains `publish = false`; no crates.io publication is
performed.

## Local reproduction

Run the downstream extension contracts with:

```console
cargo test --locked --test external_protocol
cargo test --locked --test external_provider
cargo test --locked --test external_output
```

Probe or run the privileged native harness with:

```console
sudo -v
scripts/test-native-e2e --check-prerequisites
scripts/test-native-e2e
```

To preserve the same failure files CI uploads, provide an absolute directory:

```console
PCR_NATIVE_E2E_ARTIFACT_DIR=/tmp/packetcraftr-native-e2e \
  scripts/test-native-e2e --force-failure route-ipv4
```
