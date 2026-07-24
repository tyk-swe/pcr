# PacketcraftR

PacketcraftR is a Rust library and command-line tool for constructing exact
packet bytes, dissecting packet stacks, reading and replaying capture files,
inspecting native routes and interfaces, and running bounded live-network
workflows. Its live operations are policy-gated so that destination scope,
hostname resolution, malformed traffic, and operation budgets are explicit.

PacketcraftR is currently a pre-1.0 beta (`0.4.0-beta.2`). Interfaces and
serialized v1 contracts can still change incompatibly between beta releases.
Review the [changelog](CHANGELOG.md) before upgrading.

Use PacketcraftR only on systems and networks you own or are explicitly
authorized to test. Packet construction, capture, and transmission can expose
sensitive traffic or disrupt a network when used incorrectly.

## Supported use cases

- Build strict or deliberately permissive packet stacks from expressions,
  versioned JSON, or YAML and emit text, JSON, hexadecimal, or exact raw bytes.
- Dissect bounded raw frames and preserve unknown or malformed bytes with
  diagnostics.
- Read and transcode classic PCAP and PCAPNG files without live-network access.
- Generate deterministic, field-aware fuzz cases offline; live fuzzing is a
  separate opt-in.
- Enumerate interfaces and passively inspect route decisions.
- Send or replay packets through Layer 2 or raw Layer 3 backends.
- Capture traffic and run capture-ready exchange, scan, traceroute, and DNS
  workflows with finite packet, byte, duration, and evidence limits.

The command and output vocabulary is defined by the current CLI and the
[`packetcraftr.output/v1` schema](schemas/packetcraftr.output.v1.schema.json).
Packet documents use the
[`packetcraftr.packet/v1` schema](schemas/packetcraftr.packet.v1.schema.json).
Published packet and output examples are in
[`examples/documents`](examples/documents).

## Built-in protocol coverage

The default registry provides exact construction and bounded dissection for
these protocol families:

- capture and link framing: BSD NULL and LOOP, Linux cooked capture v1 and v2,
  Ethernet II, IEEE 802.1Q and 802.1ad VLANs, and ARP;
- network and control: IPv4, IPv6, ICMPv4, ICMPv6, IGMP, GRE, and the IPv6
  Hop-by-Hop, Destination Options, Fragment, and Segment Routing headers;
- transport and payload: TCP, UDP, SCTP common headers with validated opaque
  chunks, plus raw, padding, and malformed-byte preservation layers.

IPv4 and IPv6 can be nested inside either IP version through their standard
protocol/next-header bindings, and GRE can carry typed IPv4 or IPv6 payloads.
Unknown numeric link types and unknown discriminators remain bounded and are
preserved as raw bytes. Built-in protocol support is header-focused: SCTP
chunks are not decoded into typed chunk models, DNS messages remain owned by
the DNS workflow, and other application payloads are represented as raw bytes.

## Output formats and terminal colour

Global `--color <WHEN>` accepts `auto`, `always`, or `never` and affects only
human-facing text, help, and diagnostics. `auto` is the default and emits
colour only when the destination supports it; `always` forces human styling,
and `never` disables it.

Machine and binary formats never contain terminal styling, even with
`--color always`. This guarantee covers JSON, NDJSON, hexadecimal, raw, PCAP,
and PCAPNG output. A raw packet may naturally contain an escape byte as packet
data; PacketcraftR does not add terminal control sequences around it.

## Installation

### Release archives

GitHub releases provide these targets:

- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

Each target is published as an `all-features` and a `pcap-free` variant. Choose
`all-features` for Layer 2 capture/injection and capture-based workflows.
Choose `pcap-free` when native routing and raw Layer 3 transmission are enough
and a libpcap/Npcap dependency is undesirable.

Download the archive and `SHA256SUMS` from the
[GitHub release](https://github.com/tyk-swe/pcr/releases), verify the archive,
then extract it. Every binary archive contains:

- `packetcraftr` or `packetcraftr.exe`
- `LICENSE`
- `README.md`
- `CHANGELOG.md`

Run `packetcraftr --version` and `packetcraftr --help` after placing the
executable on your `PATH`.

The `all-features` Linux and macOS archives need libpcap at runtime. The
`all-features` Windows archive needs Npcap 1.88 at runtime. The `pcap-free`
archives need neither.

### Build from source

The repository pins Rust 1.97 in `rust-toolchain.toml`; Rust 1.96 is the
minimum supported version. Build from a checkout with the committed lockfile:

```console
cargo build --locked --release
./target/release/packetcraftr --help
```

Select a different feature set with one of the commands in the next section.
The resulting executable is always `target/release/packetcraftr` on Unix-like
systems or `target\release\packetcraftr.exe` on Windows.

## Cargo features and tested profiles

`Cargo.toml` defines exactly four features: `live`, `native-route`,
`native-layer2`, and `native-layer3`. `native-layer2` and `native-layer3`
enable `live`; the default feature set contains only `live`.

The profile names below are repository, CI, or release labels, not additional
Cargo feature names. In particular, there is no `portable` or `pcap-free`
feature.

| Profile label | Cargo invocation | Enabled features | Available native behavior |
| --- | --- | --- | --- |
| Portable | `--no-default-features` | None | Offline build, dissection, capture-file reading/transcoding, and offline fuzzing. Native interface, route, capture, and send providers are unavailable. |
| Default | no feature arguments | `live` | Portable behavior plus interface enumeration. It does not enable native route selection, capture, Layer 2 injection, or raw Layer 3 transmission. |
| Pcap-free release variant | `--no-default-features --features live,native-route,native-layer3` | `live`, `native-route`, `native-layer3` | Interface enumeration, passive native routes, and raw Layer 3 send/replay on Linux, macOS, and Windows. No Layer 2 capture/injection; capture-based workflows are unavailable. |
| Complete / all-features | `--all-features` | All four features | Native routes, raw Layer 3 transmission, and Layer 2 capture/injection on supported Linux, macOS, and Windows targets. |

Build each profile with:

```console
cargo build --locked --release --no-default-features
cargo build --locked --release
cargo build --locked --release \
  --no-default-features --features live,native-route,native-layer3
cargo build --locked --release --all-features
```

## Build and runtime prerequisites

All source builds require a Rust toolchain, Cargo, and the platform linker
needed by the selected Rust target. Native dependencies vary by feature set:

| Platform | All-features prerequisites | Pcap-free prerequisites |
| --- | --- | --- |
| Linux | libpcap development files at build time and libpcap at runtime. Debian/Ubuntu CI installs `libpcap-dev`. | No libpcap dependency. Native routes use route netlink; raw Layer 3 uses raw sockets. |
| macOS | The system/build environment must provide libpcap. Capture and Layer 2 injection also need access to macOS BPF devices. | No libpcap dependency. Native routes use the routing socket; raw Layer 3 uses raw sockets. |
| Windows x86-64 MSVC | A working Rust MSVC linker for source builds. At runtime PacketcraftR securely loads Npcap 1.88 from the system Npcap directory; install it for all users. | A working Rust MSVC linker for source builds. No Npcap dependency. |

The release workflow builds Linux x86-64, macOS x86-64 and Arm64, and Windows
x86-64 MSVC. CI also compile-checks FreeBSD interface-enumeration and feature
combinations, but PacketcraftR has no FreeBSD native route, Layer 2, or raw
Layer 3 backend and publishes no FreeBSD binary archive.

## Offline quick start

The following commands do not open an interface, perform route lookup, resolve
a hostname, capture live traffic, or transmit packets. They work with the
portable build.

Build exact bytes from an inline expression:

```console
packetcraftr --output hex build --packet 'raw(text=hello)'
```

Dissect a frame using an open numeric DLT/link type:

```console
packetcraftr --output json dissect --hex deadbeef --link-type 147
```

Generate four deterministic fuzz cases offline. `fuzz` is offline unless
`--live` is explicitly present:

```console
packetcraftr fuzz \
  --packet 'raw(hex="00")' \
  --seed 9 --cases 4 --strategy bit-flip --field 0.bytes
```

Read a local capture with explicit limits:

```console
packetcraftr --output ndjson read capture.pcapng \
  --max-frames 100 --max-bytes 10485760 --max-frame-bytes 1048576
```

From a source checkout, a published packet document can be built directly:

```console
packetcraftr --output json build \
  --packet-file examples/documents/packet-ipv4-udp.json
```

## Safety gates for live operations

Read and satisfy these gates before running the live examples below.

### Destination authorization

By default, live policy denies globally routable addresses and multicast
addresses. Private, loopback, link-local, unspecified, and documentation
addresses are not classified as public by the current policy. When a public
destination is genuinely required and authorized, pass
`--allow-public-destinations` to that live command. This opt-in does not grant
legal authorization, operating-system privileges, or additional packet/byte
budget.

PacketcraftR checks every route-bearing destination declared by a packet.
Replay checks each decoded frame. A policy rejection is reported as
`policy.public_destination` before interface discovery, route lookup, capture,
or transmission.

### Hostname resolution

Live hostnames are not resolved unless the command includes
`--allow-hostname-resolution`. Resolution is separately bounded by
`--max-resolved-addresses`, and every returned address must independently pass
the public-destination policy. If a hostname can resolve publicly, both
`--allow-hostname-resolution` and `--allow-public-destinations` are required.

### Permissive and malformed live traffic

Offline permissive construction does not authorize transmission. The current
live paths use independent call-site and policy opt-ins:

| Operation | Required opt-ins when permissive or malformed bytes will be live |
| --- | --- |
| `send` or `exchange` with `--mode permissive` | `--allow-permissive-live` and `--allow-permissive-packets` |
| `replay` of a frame whose dissection preserves malformed bytes | `--allow-malformed-live` and `--allow-permissive-packets` |
| `fuzz --live` when a case is permissive or malformed | `--allow-malformed-live` and `--allow-permissive-packets`; use `--mode permissive` when malformed dependent fields are intentional |

These flags do not bypass destination checks, route consistency, MTU checks,
capture readiness, interface identity validation, or the configured operation
limits. Capture-backed active workflows establish capture readiness before
sending; startup failure aborts the operation.

### Native privileges

Grant only the minimum permission needed for the selected backend:

- **Linux:** libpcap Layer 2 capture/injection and raw Layer 3 sockets normally
  require root or the relevant `CAP_NET_RAW` capability. Configure capability
  or capture permissions for the exact installed executable; replacing the
  executable can remove file capabilities.
- **macOS:** libpcap capture/injection requires access to `/dev/bpf*`; raw
  sockets normally require root. Use an administrator-approved BPF permission
  setup instead of making capture devices broadly writable.
- **Windows:** raw sockets require administrator rights. Npcap capture or
  injection may require an elevated process when Npcap was installed with
  administrator-only access.

Interface enumeration and passive route lookup normally do not require these
packet I/O privileges.

## Live-network quick start

Use an isolated lab network and replace `eth0` and `192.168.56.10` with a
current interface and an authorized private destination.

First inspect interfaces and routes. `interfaces` works in the default,
pcap-free, and all-features builds. `routes` and `plan` require
`native-route`, so use pcap-free or all-features:

```console
packetcraftr interfaces
packetcraftr routes
packetcraftr plan \
  --packet 'ipv4(dst=192.168.56.10)/icmpv4(type=8,code=0)' \
  --interface eth0 --link-mode layer3
```

`plan` is passive and sends no packet. After granting the required raw-socket
permission, the pcap-free or all-features build can transmit the same strict
packet through Layer 3:

```console
packetcraftr send \
  --packet 'ipv4(dst=192.168.56.10)/icmpv4(type=8,code=0)' \
  --interface eth0 --link-mode layer3
```

Layer 2 capture and every capture-based active workflow require the
all-features build plus libpcap/Npcap and capture privileges:

```console
packetcraftr capture \
  --packet 'ipv4(dst=192.168.56.10)/icmpv4(type=8,code=0)' \
  --interface eth0 --timeout-ms 1000

packetcraftr exchange \
  --packet 'ipv4(dst=192.168.56.10)/icmpv4(type=8,code=0)' \
  --interface eth0 --link-mode layer3 --timeout-ms 1000

packetcraftr scan 192.168.56.10 \
  --transport tcp --ports 22,80,443 --interface eth0
```

Other representative commands are:

```console
packetcraftr traceroute 192.168.56.10 \
  --strategy icmp --interface eth0

packetcraftr dns 192.168.56.53 example.test \
  --type a --interface eth0

packetcraftr replay capture.pcapng \
  --interface eth0 --timing immediate
```

Inspect capture contents before replaying them. The pcap-free build can replay
supported raw IPv4/IPv6 captures with `--link-mode layer3`; Ethernet replay
requires all-features and Layer 2.

Run `packetcraftr <COMMAND> --help` for the command's exact formats, limits,
and examples. Global `--output` supports command-specific combinations of
`text`, `json`, `ndjson`, `hex`, `raw`, `pcap`, and `pcapng`.

## Platform notes

### Linux

All-features links libpcap for promiscuous capture and Layer 2 injection.
Pcap-free intentionally omits that link. Native route lookup uses the current
Linux network namespace and route netlink. Containers and network namespaces
must expose the selected interface, route, and required capability inside the
same namespace as PacketcraftR.

### macOS

Layer 2 capture/injection uses libpcap over the selected BPF-capable interface.
The exact raw Layer 3 backend supports complete-header IPv4 transmission.
Darwin raw IPv6 sockets do not support PacketcraftR's exact complete-header
path, so raw IPv6 Layer 3 transmission is rejected; use an authorized Layer 2
path instead.

### Windows

Interface and route discovery use IP Helper. The all-features Layer 2 backend
supports `x86_64-pc-windows-msvc` and loads the pinned Npcap 1.88 runtime from
`%SystemRoot%\System32\Npcap\wpcap.dll`. Windows client editions can reject raw
UDP whose source address is not assigned to a local interface; PacketcraftR
rejects that unsupported case before sending.

## Troubleshooting

For machine-readable diagnostics, add `--output json` before a command.
Classified errors include a stable code, kind, message, and remediation.

### Missing libpcap

- A Linux all-features source build that cannot find `pcap` needs the libpcap
  development files; Debian/Ubuntu uses `libpcap-dev`.
- An all-features binary that fails at startup or capture time needs a
  compatible libpcap runtime visible to the dynamic loader.
- If Layer 2 and capture-based commands are unnecessary, build or download the
  pcap-free variant. Do not expect `capture`, `exchange`, `scan`, `traceroute`,
  `dns`, or `fuzz --live` to work without `native-layer2`.

### Missing Npcap

An all-features Windows error naming `Npcap 1.88 runtime` or
`capability.missing_dependency` means the expected DLL or required SDK symbol
could not be loaded. Install Npcap 1.88 for all users, restart PacketcraftR,
and confirm `wpcap.dll` is under the system Npcap directory. Use the pcap-free
archive only when Layer 2 capture/injection is not needed.

### Insufficient privileges

`capability.privilege` means the backend reached an operating-system permission
boundary. Grant the minimum Linux raw/capture capability, macOS BPF/raw-socket
permission, or Windows administrator/Npcap permission described above. Do not
disable PacketcraftR's policy flags to solve an operating-system privilege
error; they govern different boundaries.

### Interface selection

Run `packetcraftr interfaces` and pass the current name or non-zero numeric
index to `--interface`. PacketcraftR treats decimal selectors as indexes,
requires an exact name/index identity, and revalidates it immediately before
native I/O. An interface rename, VPN reconnect, or hot-plug can therefore
produce `io.interface_not_found`, `io.route_selection`, or `io.device`; list
interfaces again rather than reusing stale identity data.

### Route lookup failures

`capability.route` means the build lacks `native-route`; use pcap-free or
all-features. For `io.route_not_found`, first run the same packet through
`plan`, inspect the OS route table, and check `--interface`, `--source`, and
address-family compatibility. PacketcraftR does not silently switch link mode
or choose another interface after a constrained route fails.

### Capture startup failures

`io.capture`, `io.capture_readiness`, or `capability.missing_dependency`
usually indicates an unavailable/down interface, missing libpcap/Npcap,
insufficient capture permission, or an unsupported capture device. Confirm the
all-features build, dependency, selected interface, and capture privileges.
Active exchanges do not send if capture cannot become ready.

### Pcap-free limitations

Pcap-free has native routes and raw Layer 3 transmission but no
`native-layer2`. It cannot capture, inject Ethernet frames, resolve Layer 2
neighbors through the native capture path, or run workflows that require
capture-ready response evidence. Select `--link-mode layer3` only for a
supported raw IP packet or capture.

### Public-destination policy rejection

`policy.public_destination` is intentional. Prefer an authorized private lab
destination. If the public target is necessary and within the approved test
scope, add `--allow-public-destinations` to that command. If the target began
as a hostname, also add `--allow-hostname-resolution`; every resolved address
is still checked.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, checks, and
review requirements. Report suspected vulnerabilities privately as described
in [SECURITY.md](SECURITY.md), especially malformed-input, privilege-boundary,
policy-bypass, unsafe-native-code, resource-exhaustion, or unintended-network
access issues.

PacketcraftR is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE).
