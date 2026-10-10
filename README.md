# PacketcraftR

PacketcraftR is a Rust library and CLI for protocol development,
interoperability testing, and authorized network diagnostics: exact packet
construction, bounded dissection, capture-file I/O, offline analysis, and
policy-gated live networking.

Latest release: **0.5.0-beta.3**. This README describes `main`, which carries
unreleased breaking changes. See the [changelog](CHANGELOG.md) and migration
notes for [beta.3](docs/migration-beta.3.md) or
[beta.3 → main](docs/migration-unreleased.md). The crates are not yet published;
pin a reviewed revision for [library dependencies](docs/consumer-compatibility.md#rust-api-adoption).

> **Authorized use:** Test only systems and networks you own or are explicitly
> authorized to test. Opt-in flags are technical controls, not permission.

## Quick start

These offline commands work in every build profile and send no traffic:

```console
packetcraftr protocols
packetcraftr --output hex build --packet 'raw(text=hello)'
packetcraftr --output hex build --packet 'ipv4()/icmpv4(identifier=1)' \
  | packetcraftr dissect --link-type ipv4 --hex - --tree
packetcraftr --output ndjson read examples/captures/tls-handshake.pcapng --max-frames 100
packetcraftr tls examples/captures/tls-handshake.pcapng
packetcraftr http2 examples/captures/http2-multiplexed.pcapng
```

Put global options such as `--output` before the command. Use
`packetcraftr <COMMAND> --help` for options and runnable examples,
`packetcraftr protocols [PROTOCOL]` for supported packet fields, and
`packetcraftr topics` for expressions, filters, formats, and exit codes.

| Task | Start here |
| --- | --- |
| Build a fixture or verify forwarding | [Task recipes](docs/tasks.md#1-build-a-fixture-and-test-one-property), [verification contract](docs/verification-contract.md) |
| Investigate or transform a capture | [Capture recipes](docs/tasks.md#2-investigate-a-capture-without-losing-evidence), [analysis resources and evidence](docs/analysis-resources.md) |
| Run an authorized live diagnostic | [Isolated lab recipe](docs/tasks.md#3-run-an-authorized-diagnostic-in-an-isolated-lab), [native validation](docs/native-validation.md) |
| Interpret scan or service results | [Scanner evidence](docs/scanner-evidence.md), [service identification](docs/service-identification.md) |
| Automate bounded processing | [Resource presets](docs/resource-presets.md), [consumer compatibility](docs/consumer-compatibility.md) |
| Review scanner coverage and open work | [Roadmap](docs/roadmap/README.md), [Nmap gap matrix](docs/roadmap/nmap-gap-matrix.md) |

| Area | Commands |
| --- | --- |
| Packets and captures | `build`, `dissect`, `protocols`, `read` |
| Capture transformation | `fragment`, `merge`, `export`, `rewrite` |
| Offline analysis | `expert`, `follow`, `stats`, `tls`, `dns-read`, `http`, `http2`, `verify-forwarding`, `fuzz` |
| Native inspection and planning | `interfaces`, `routes`, `plan` |
| Live workflows | `send`, `exchange`, `capture`, `replay`, `scan`, `identify`, `traceroute`, `dns`, `fuzz --live` |
| References and shell integration | `topics`, `documentation` |

## Install

[GitHub releases](https://github.com/tyk-swe/pcr/releases) provide Linux
x86-64 and Arm64, macOS x86-64 and Arm64, and Windows x86-64 MSVC archives.
Verify the matching archive with `SHA256SUMS`, then put `packetcraftr` or
`packetcraftr.exe` on `PATH`.

- `all-features` archives include routing, raw Layer 3, and Layer 2
  capture/injection. They require libpcap on Linux and macOS or Npcap 1.88 on
  Windows.
- `pcap-free` archives include routing and raw Layer 3 without libpcap/Npcap.

Release archives include GitHub Artifact Attestations signed with Sigstore:

```console
gh attestation verify packetcraftr-v<version>-<target>-<variant>.<ext> --owner tyk-swe
```

Release artifacts use these runtime baselines: Ubuntu 24.04 (glibc 2.39) on
x86-64 and Arm64, macOS 14 on arm64, macOS 15 on x86_64, and Windows Server 2022
on x86_64. Older systems are not a tested binary baseline; build from source for
another environment. Full-native Linux needs the shared libpcap runtime (Ubuntu
`libpcap0.8t64`); Windows capture/Layer 2 needs a working Npcap installation
exporting the symbols required by the loader. `BUILD-METADATA.json` in each
archive records compiler, commit, target, feature variant, and the executable
digest.

### Build from source

Install the toolchain in `rust-toolchain.toml`; the same supported version is
declared in `Cargo.toml`. Builds with Layer 2 support on Linux also need libpcap
development files such as `libpcap-dev`. Choose a profile, then build with
`cargo build --locked --release -p packetcraftr-cli` plus its Cargo arguments:

| Profile | Cargo arguments | Capability |
| --- | --- | --- |
| Portable | `--no-default-features` | Offline construction and analysis, ordinary-socket `dns --tcp`, `scan --connect`, and `identify`; native packet and route providers report unavailable |
| Default | none | Portable capabilities plus passive interface enumeration and route lookup |
| Layer 2 only | `--no-default-features --features native-layer2` | Default capabilities and Layer 2 capture/injection |
| Pcap-free | `--no-default-features --features native-layer3` | Default capabilities and raw Layer 3 `send`/`replay`, without libpcap |
| Full native | `--all-features` | Every provider, including capture, Layer 2, and capture-ready exchanges |

Capture, `exchange`, and capture-backed probes need a profile with Layer 2
capture. Verify a build with `./target/release/packetcraftr --version`, and see
[Contributing](CONTRIBUTING.md) for the ordinary Cargo loop.

## Shell completions and man pages

Release archives ship generated shell completions under `completions/` (Bash,
Elvish, Fish, PowerShell, and Zsh) and man pages under `man/` (one per command).
The binary itself regenerates both trees from the finalized command
definitions:

```console
packetcraftr documentation --directory DIR
```

This writes `DIR/completions/` and `DIR/man/`, which can be copied into the
shell completion and `man1` directories of the platform.

## Contracts

Current producers use [packet/v2](schemas/packetcraftr.packet.v2.schema.json)
and [output/v12](schemas/packetcraftr.output.v12.schema.json). Frozen output
v6–v11 schemas remain available for previously published evidence; beta.3 used
packet/v1 and output/v2. Do not silently reinterpret an older contract.

[Consumer compatibility](docs/consumer-compatibility.md) defines versioning,
field tolerance, error semantics, and complete NDJSON streams. Always inspect
the terminal `complete` or `error`; a killed process or broken output can leave
an incomplete stream. Binary output refuses interactive stdout unless
`--force-binary-stdout` is supplied.

Other documents have independent versions: [rewrite rules](schemas/packetcraftr.rewrite.v2.schema.json),
[UDP profiles](schemas/packetcraftr.udp-profiles.v1.schema.json),
[service probes](schemas/packetcraftr.service-probes.v1.schema.json), and
[service exclusions](schemas/packetcraftr.service-exclusions.v1.schema.json).
See [examples](examples/documents) and the
[scanner data policy](docs/scanner-data-policy.md) for fixtures and provenance.

## Library

Depend on the crate that owns the capability you need:

| Crate | Responsibility |
| --- | --- |
| `packetcraftr-core` | Packets, codecs/reflection, bounded documents, capture files, filters, offline analysis |
| `packetcraftr-netio` | Provider contracts, interfaces/routes, native capture/transmit and socket resources |
| `packetcraftr` | Policy-gated `Client` workflows, preparation, budgets, evidence |
| `packetcraftr-cli` | Arguments, provider composition, rendering, versioned machine output |

Core is independent of native I/O. Compose a `Client` with a `ProviderSet`
containing only the capabilities your workflow needs, or use `SystemProviders`.
Live workflows authorize operations before active discovery and check final
endpoints and bytes before transmission under finite resource budgets.

Runnable examples use documentation addresses and in-memory fixtures:

```console
cargo run -p packetcraftr-core --example build_decode_filter
cargo run -p packetcraftr-core --example capture_analysis
cargo run -p packetcraftr --example client_composition --no-default-features
cargo doc --locked --workspace --all-features --no-deps --open
```

## Contributing, security, and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and validation. Report
vulnerabilities privately via [SECURITY.md](SECURITY.md).

PacketcraftR is licensed under the [GNU AGPL v3.0 only](LICENSE).
Dependency attributions are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
