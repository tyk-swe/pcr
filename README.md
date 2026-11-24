# PacketcraftR

PacketcraftR builds and dissects packets, reads PCAP and PCAPNG captures, and runs bounded offline and policy-gated live network workflows for authorized diagnostics and protocol testing. The workspace contains the runtime-neutral `packetcraftr-core` library, the provider boundary `packetcraftr-netio`, the workflow library `packetcraftr`, and the `packetcraftr-cli` binary.

## Offline quick start

From the repository root, use the Rust toolchain pinned in `rust-toolchain.toml` and a native C compiler to build the CLI and print the bytes for `hello` in hex. Both quick-start commands run without elevated privileges.

```sh
cargo run --quiet --locked -p packetcraftr-cli --no-default-features -- --output hex packet build --packet 'raw(text=hello)'
```

```text
68656c6c6f
```

Dissect the bundled DNS response capture with the same offline build.

```sh
cargo run --quiet --locked -p packetcraftr-cli --no-default-features -- files read examples/captures/dns-response.pcap --dissect
```

## Build from source

Run these Cargo commands from the repository root with the toolchain in `rust-toolchain.toml` (`edition = "2024"`, minimum supported Rust `1.98.1` in `Cargo.toml`). Keep `--locked` to use the checked-in dependency versions in [`Cargo.lock`](Cargo.lock), and add `--offline` when those dependencies are already cached.

| Build | Command | Capabilities and prerequisites |
| --- | --- | --- |
| Offline | `cargo build --locked -p packetcraftr-cli --no-default-features` | Packet construction, decoding, capture files, and bounded offline analysis with no native network providers |
| Default | `cargo build --locked -p packetcraftr-cli` | Enables `native-route` for interface enumeration and route lookup |
| Layer 3 (`pcap-free`) | `cargo build --locked -p packetcraftr-cli --no-default-features --features native-layer3` | Enables `native-route` and raw IP sockets without libpcap or Npcap |
| Layer 2 and 3 (`all-features`) | `cargo build --locked -p packetcraftr-cli --all-features` | Enables `native-route`, raw IP sockets, and live Layer 2 capture and injection |

Linux and macOS Layer 2 builds require libpcap development headers and libraries at build time (such as `libpcap-dev` on Debian and Ubuntu) and libpcap at runtime. Windows Layer 2 builds load Npcap dynamically at runtime, and the release workflow targets Npcap 1.88. Live raw sockets and capture also require the permissions granted by the operating system.

By default, Cargo uses the development profile and writes `target/debug/packetcraftr` (or `target/debug/packetcraftr.exe` on Windows). Add `--release` for optimized binaries in `target/release/`, which keep integer overflow checks enabled.

## Use a release archive

Each GitHub release ships `pcap-free` and `all-features` archives across Linux (`x86_64` and `aarch64`), macOS (`x86_64` and `aarch64`), and Windows (`x86_64`). Choose `pcap-free` for offline work, interface discovery, native routes, and raw Layer 3 support without a libpcap or Npcap runtime dependency. Choose `all-features` when you also need live Layer 2 capture and injection, which requires libpcap at runtime on Linux and macOS or Npcap 1.88 at runtime on Windows.

Verify downloaded archives against the published `SHA256SUMS` file and GitHub build provenance attestations (`gh attestation verify`). Unpack the archive and open a shell in the directory containing the executable, generated `completions/` and `man/` trees, `BUILD-METADATA.json`, `schemas/`, `docs/`, and `examples/`.

## Offline examples

Run these examples from the repository root or the unpacked release directory so the relative example paths resolve. Use the path to the binary if it is not on your `PATH`, such as `./target/debug/packetcraftr` for a source build or `./packetcraftr` in an unpacked release.

### Build and inspect packets

```sh
packetcraftr --output hex packet build --packet-file examples/documents/packet-dns-response.json
packetcraftr --output json files read examples/captures/protocol-mqtt.pcap --field frame.number
```

### Analyze captures

```sh
packetcraftr analyze dns examples/captures/dns-response.pcap
packetcraftr analyze http examples/captures/http-stream.pcap
packetcraftr analyze quic examples/captures/quic-demo-v1.pcap --keylog examples/captures/quic-demo.keys
packetcraftr analyze http3 examples/captures/http3-demo.pcapng --keylog examples/captures/http3-demo.keys
```

See [QUIC transport analysis](docs/quic-analysis.md) for offline and live decryption, TLS key logs, stream export, and bounded diagnostics. See [HTTP/3 exchange reconstruction](docs/http3-analysis.md) for offline request and response reconstruction with QPACK state and stream offsets.

### Find fixtures and schemas

The protocol fixture manifest at [`examples/captures/protocols.manifest.json`](examples/captures/protocols.manifest.json) links synthetic captures to their packet documents and optional decode bindings. Public JSON contracts live under [`schemas/`](schemas/), with matching input and output examples under [`examples/documents/`](examples/documents/).

All current CLI JSON and NDJSON envelopes emit the `packetcraftr.output/v22` schema identifier defined in [`schemas/packetcraftr.output.v22.schema.json`](schemas/packetcraftr.output.v22.schema.json). Output contract identifiers are immutable and never reused.

## Generated references

Run `packetcraftr --help` to list command groups, or pass `--help` after any command for all options, defaults, prerequisites, and supported output formats. Pass `-h` for a shorter summary.

```sh
packetcraftr reference protocols
packetcraftr reference topics
packetcraftr reference topics expressions
packetcraftr reference topics scope
packetcraftr reference documentation --directory ./cli-docs
```

Running `packetcraftr reference topics` without a name lists all built-in reference topics (`expressions`, `filters`, `formats`, `scope`, and `exit-codes`). Pass any of those topic names to print its reference text offline.

The `packetcraftr reference documentation --directory ./cli-docs` command generates shell completions for Bash, Elvish, Fish, PowerShell, and Zsh in `cli-docs/completions/` and manual pages for the grouped command tree in `cli-docs/man/`. It supports text output only, completes all rendering and staged writes before starting publication, and replaces existing regular files atomically per file while preserving existing file permissions. Symlink, directory, and special-file destinations are rejected, and a publication failure reports any files already published.

PacketcraftR is licensed under [AGPL-3.0-only](LICENSE). Third-party attribution is listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
