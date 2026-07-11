# Installation

PacketcraftR is built from its Rust workspace and requires Rust 1.96.

## Portable installation

The portable profile supports packet construction, dissection, packet
documents, offline PCAP/PCAPNG, and application-provided networking adapters.
It has no native packet-capture dependency.

```console
git clone https://github.com/tyk-swe/pcr.git
cd pcr
rustup toolchain install 1.96.0 --profile minimal
cargo install --locked --path . --no-default-features
packetcraftr --help
```

Use a reviewed commit and keep `Cargo.lock` unchanged when reproducibility
matters.

## Native features

Native providers are opt-in and independently selectable:

| Feature | Provides |
| --- | --- |
| `native-route` | Passive interface, route, source, next-hop, and MTU discovery |
| `native-layer2` | Layer 2 capture and injection through libpcap or Npcap |
| `native-layer3` | Raw IP transmission where the operating system supports the requested bytes |

Build all native providers for the current target with:

```console
cargo build --locked --features native-route,native-layer2,native-layer3
```

### Linux

Install the libpcap development package before enabling `native-layer2`:

```console
sudo apt-get update
sudo apt-get install libpcap-dev
```

Raw sockets and capture commonly require narrowly granted `CAP_NET_RAW`,
`CAP_NET_ADMIN`, or root inside an isolated environment.

### macOS

The operating system supplies libpcap/BPF. Layer 2 access depends on BPF device
policy, and exact raw IPv4 normally requires elevated privileges. Complete raw
IPv6 headers are unsupported by the native Layer 3 adapter; use an explicit
Layer 2 path when appropriate.

### Windows

`native-route` uses IP Helper and does not require Npcap. `native-layer2`
dynamically loads the 64-bit Npcap runtime from the system path; PacketcraftR
does not bundle Npcap or link its SDK import library. Npcap-backed live traffic
is experimental and should be used only in an isolated authorized lab.

The [platform matrix](platform-support.md) documents exact feature combinations,
operating-system limits, privileges, and typed failure behavior.
