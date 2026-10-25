# PacketcraftR

PacketcraftR builds and dissects packets, reads PCAP/PCAPNG captures, and runs
bounded offline analysis. Native networking features add route lookup, raw
packet transmission, capture, and injection. The workspace contains the
runtime-neutral `packetcraftr-core`, provider boundary `packetcraftr-netio`,
workflow library `packetcraftr`, and `packetcraftr-cli` binary.

## Build

Use the Rust toolchain pinned in `rust-toolchain.toml` and a native C compiler.
Run these commands from the repository root. Keep `--locked` to use the checked-in
dependency versions; add `--offline` when those dependencies are already cached.

| Build | Command | Capabilities and prerequisites |
| --- | --- | --- |
| Offline | `cargo build --locked -p packetcraftr-cli --no-default-features` | Packet construction, decoding, capture files, offline analysis; no native packet providers |
| Default | `cargo build --locked -p packetcraftr-cli` | Adds native interface and route lookup |
| Layer 3 | `cargo build --locked -p packetcraftr-cli --no-default-features --features native-layer3` | Adds raw IP sockets; no libpcap/Npcap requirement |
| Layer 2 and 3 | `cargo build --locked -p packetcraftr-cli --all-features` | Adds live Layer 2 capture and injection |

Linux and macOS Layer 2 builds need libpcap development headers/libraries and
libpcap at runtime (for example `libpcap-dev` on Debian/Ubuntu). Windows Layer 2
uses Npcap; the release workflow targets Npcap 1.88. Live raw sockets and capture
need the permissions granted by the operating system. Offline examples below do
not require elevated privileges.

The commands above use Cargo's development profile and write
`target/debug/packetcraftr` (`.exe` on Windows). Add `--release` for optimized
binaries in `target/release/`; release builds retain overflow checks. Release
archives distinguish `all-features` from `pcap-free` (native routes and Layer 3).

## Try it offline

After building, put `target/debug` on your PATH or replace `packetcraftr` below
with the binary's path:

```sh
packetcraftr --help
packetcraftr packet build --packet 'raw(text=hello)'
packetcraftr --output hex packet build --packet-file examples/documents/packet-dns-response.json
packetcraftr files read examples/captures/dns-response.pcap --dissect
packetcraftr analyze dns examples/captures/dns-response.pcap
packetcraftr analyze http examples/captures/http-stream.pcap
packetcraftr --output json files read examples/captures/protocol-mqtt.pcap --dissect
```

Use `--help` on a command for all options, defaults, prerequisites, and output
formats. `-h` shows a shorter guide. The protocol fixture manifest at
[`examples/captures/protocols.manifest.json`](examples/captures/protocols.manifest.json)
links synthetic captures to their packet documents and optional decode bindings.
Public JSON contracts are under [`schemas/`](schemas/), with examples under
[`examples/documents/`](examples/documents/).

## Generated references

```sh
packetcraftr reference protocols
packetcraftr reference topics expressions
packetcraftr reference topics filters
packetcraftr reference documentation --directory ./cli-docs
```

The last command generates Bash, Elvish, Fish, PowerShell, and Zsh completions in
`cli-docs/completions/` and manuals for the command tree in `cli-docs/man/`.
Regeneration replaces existing regular files atomically per file, preserving
existing file permissions. All rendering and staged writes complete before
publication starts. A later publication failure reports the files already
published; files are not replaced as a single transaction. Symlink, directory,
and special-file destinations are rejected. Documentation generation supports
text output only.

PacketcraftR is licensed under [AGPL-3.0-only](LICENSE). Third-party attribution
is listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
