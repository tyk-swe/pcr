# PacketcraftR

PacketcraftR is a Rust library and CLI for packet construction, bounded dissection,
capture-file processing, offline analysis, and authorized network diagnostics.

Latest release: **0.5.0-beta.3**. This guide describes `main`, including unreleased
breaking changes. Read the [changelog](CHANGELOG.md) and migration notes for
[beta.3](docs/migration-beta.3.md) or [beta.3 → main](docs/migration-unreleased.md).
The crates are unpublished; [pin a reviewed revision](docs/consumer-compatibility.md#rust-api-adoption).

> Test only systems and networks you own or are explicitly authorized to test.
> Opt-in flags are technical controls, not permission.

Commands are grouped by workflow: `packet`, `files`, `analyze`, `network`, and
`reference`. All 31 commands retain supported flat aliases. Use `-h` for common
options and `--help` for full help. Text results are compact; `-v`/`--verbose`
expands retained evidence and technical details. JSON, NDJSON, and byte output are unchanged by verbosity.

## Quick start

These commands work in every profile and send no traffic:

```console
packetcraftr reference protocols
packetcraftr --output hex packet build --packet 'raw(text=hello)'
packetcraftr --output hex packet build --packet 'ipv4()/icmpv4(identifier=1)' \
  | packetcraftr packet dissect --link-type ipv4 --hex - --tree
packetcraftr --output ndjson files read examples/captures/tls-handshake.pcapng --max-frames 100
packetcraftr analyze stats examples/captures/http-stream.pcap --table overview
packetcraftr --output csv analyze stats examples/captures/http-stream.pcap --table endpoints
packetcraftr analyze tls examples/captures/tls-handshake.pcapng
packetcraftr analyze http2 examples/captures/http2-multiplexed.pcapng
```

Global options such as `--output` may appear before the group, between the group and command, or after the command. Use `packetcraftr <group> <command> --help` for options
and examples, `reference protocols [PROTOCOL]` for packet fields, and `reference topics` for expressions,
filters, formats, and exit codes.

| Task | Guide |
| --- | --- |
| Build fixtures or test forwarding | [Task recipes](docs/tasks.md#1-build-a-fixture-and-test-one-property), [verification](docs/verification-contract.md) |
| Investigate or transform captures | [Capture recipes](docs/tasks.md#2-investigate-a-capture-without-losing-evidence), [resources and evidence](docs/analysis-resources.md) |
| Run live diagnostics | [Isolated lab recipe](docs/tasks.md#3-run-an-authorized-diagnostic-in-an-isolated-lab), [native validation](docs/native-validation.md) |
| Interpret scans and services | [Scanner evidence](docs/scanner-evidence.md), [TCP diagnostic scans](docs/tcp-diagnostics.md), [service identification](docs/service-identification.md), [OS identification](docs/os-identification.md) |
| Automate processing | [Resource presets](docs/resource-presets.md), [consumer compatibility](docs/consumer-compatibility.md) |

## Install

[Release archives](https://github.com/tyk-swe/pcr/releases) cover Linux x86-64/Arm64,
macOS x86-64/Arm64, and Windows x86-64 MSVC. Verify `SHA256SUMS`, then put
`packetcraftr` or `packetcraftr.exe` on `PATH`. Archives include completions, man
pages, schemas, examples, and `BUILD-METADATA.json` with compiler, commit, target,
feature variant, and executable digest. Verify the Sigstore attestation with:

```console
gh attestation verify packetcraftr-v<version>-<target>-<variant>.<ext> --owner tyk-swe
```

`all-features` archives include routing, raw Layer 3, and Layer 2 capture/injection;
they need libpcap on Linux/macOS or Npcap 1.88 on Windows. `pcap-free` archives
include routing and raw Layer 3 without libpcap/Npcap. Tested binary baselines are
Ubuntu 24.04 (glibc 2.39), macOS 14 Arm64, macOS 15 x86-64, and Windows Server 2022.
Full-native Ubuntu needs `libpcap0.8t64`; Windows Layer 2 needs a working Npcap
loader. Build from source for other environments.

### Build from source

Install the toolchain in `rust-toolchain.toml` (also declared in `Cargo.toml`).
All profiles need a C compiler for rustls/ring; no system TLS library is needed.
Linux Layer 2 builds also need `libpcap-dev`.

Run `cargo build --locked --release -p packetcraftr-cli` with the chosen arguments:

| Profile | Cargo arguments | Capabilities |
| --- | --- | --- |
| Portable | `--no-default-features` | Offline tools, ordinary-socket `network dns --tcp`, `network scan --connect`, and `network identify` |
| Default | none | Portable plus passive interfaces and routes |
| Layer 2 only | `--no-default-features --features native-layer2` | Default plus Layer 2 capture/injection |
| Pcap-free | `--no-default-features --features native-layer3` | Default plus raw Layer 3 send/replay |
| Full native | `--all-features` | All providers, including capture-backed exchanges/probes |

Check `./target/release/packetcraftr --version`. Capture-backed operations require
Layer 2 support; runtime backends and privileges still determine availability.
See [Contributing](CONTRIBUTING.md) for development checks.

## Shell completions and man pages

Archives ship Bash, Elvish, Fish, PowerShell, and Zsh completions under
`completions/` and one man page per command under `man/`. Regenerate them with
`packetcraftr reference documentation --directory DIR`, then install them in your shell's
completion directory and `man1` directory.

## Contracts

Current producers use [packet/v2](schemas/packetcraftr.packet.v2.schema.json) and
[output/v18](schemas/packetcraftr.output.v18.schema.json). Output v6–v17 schemas
remain frozen for historical evidence; beta.3 used packet/v1 and output/v2.
[Consumer compatibility](docs/consumer-compatibility.md) defines versioning,
error semantics, and stream completion. Always inspect the terminal `complete`
or `error`; interrupted output can be incomplete. Binary output to an interactive
terminal requires `--force-binary-stdout`.

[Rewrite rules](schemas/packetcraftr.rewrite.v2.schema.json),
[UDP profiles](schemas/packetcraftr.udp-profiles.v1.schema.json),
[service probes](schemas/packetcraftr.service-probes.v1.schema.json), and
[service exclusions](schemas/packetcraftr.service-exclusions.v1.schema.json) have
independent versions. See [document fixtures](examples/documents) and the
[scanner data policy](docs/scanner-data-policy.md).

## Library

| Crate | Responsibility |
| --- | --- |
| `packetcraftr-core` | Packets, codecs/reflection, bounded documents, capture files, filters, offline analysis |
| `packetcraftr-netio` | Provider contracts, native capture/transmit, interfaces/routes, socket resources |
| `packetcraftr` | Policy-gated `Client` workflows, preparation, budgets, evidence |
| `packetcraftr-cli` | Arguments, provider composition, rendering, machine output |

Compose a `Client` with the capabilities needed in a `ProviderSet`, or use
`SystemProviders`. Core is independent of native I/O. Live workflows authorize
before active discovery and check final endpoints and bytes under finite budgets.

```console
cargo run --locked -p packetcraftr-core --example build_decode_filter
cargo run --locked -p packetcraftr-core --example capture_analysis
cargo run --locked -p packetcraftr --example client_composition --no-default-features
cargo doc --locked --workspace --all-features --no-deps --open
```

See [Contributing](CONTRIBUTING.md) and report vulnerabilities through
[Security](SECURITY.md). PacketcraftR uses [AGPL-3.0-only](LICENSE);
[third-party notices](THIRD_PARTY_NOTICES.md) accompany binary distributions.
