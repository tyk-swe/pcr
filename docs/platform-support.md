# Platform and capability matrix

This document distinguishes the current alpha checkpoint from the stable v0.2 target. "Builds" does not mean a live networking workflow has been release-qualified.

Status snapshot: 2026-07-10 (`0.2.0-alpha.1`).

## Status legend

- **Alpha:** implementation exists but its API and qualification are incomplete.
- **Planned:** required before stable v0.2, but not complete in this checkpoint.
- **CI:** compiled or tested in unprivileged continuous integration.
- **Runner:** requires a dedicated privileged/native-dependency test runner.

## Current alpha checkpoint

| Capability | Linux | macOS | Windows | Notes |
| --- | --- | --- | --- | --- |
| Portable packet/layer/field model | Alpha, CI | Alpha, CI | Alpha, CI | Runtime-neutral; no native capture dependency |
| Generic registry, build, and dissection APIs | Alpha, CI | Alpha, CI | Alpha, CI | Built-in protocol slice remains incomplete |
| Offline classic PCAP/PCAPNG | Alpha, CI | Alpha, CI | Alpha, CI | Pure Rust, streaming, bounded, multi-interface PCAPNG |
| Packet-expression/document CLI | Alpha, CI | Alpha, CI | Alpha, CI | `packetcraftr.packet/v1`; `build` and `dissect` are wired |
| Route/source planning | Native alpha, CI | Native alpha, CI | Native alpha, CI | `native-route` uses netlink, routing sockets/native interfaces, or IP Helper; planning remains passive |
| Live Layer 2 capture/injection | Native alpha, CI/Runner | Native alpha, CI/Runner | Native alpha, CI/Runner | `native-layer2` uses libpcap or runtime-loaded Npcap; hosted CI covers ABI/lifecycle, while privileged qualification requires dedicated runners |
| Gateway-aware ARP/NDP | Native alpha, CI/Runner | Native alpha, CI/Runner | Native alpha, CI/Runner | Portable resolver logic is deterministically tested with injected providers; privileged routed/VLAN qualification remains a release gate |
| Raw Layer 3 transmission | Native alpha, CI/Runner | Native alpha, CI/Runner | Native alpha, CI/Runner | `native-layer3` uses target raw sockets; hosted CI covers validation and injected send seams, while privileged qualification requires dedicated runners |
| Coordinated exchange | Native alpha | Native alpha | Native alpha | Injectable and native capture share the readiness barrier, bounded retention, loss reporting, and joined shutdown contract |
| Defragmentation and TCP reassembly | Alpha, CI | Alpha, CI | Alpha, CI | Portable stages bounded by flow, byte, fragment, pending-TCP-segment, and expiry limits |
| Scan, traceroute, DNS, and fuzz tools | Planned | Planned | Planned | v0.1 paths were removed; replacements will use shared APIs |

Consult the exact release notes and `packetcraftr --help` for the checkout in use; a planned row is not a stable v0.2 guarantee.

## Build and feature contracts

| Cargo profile | Linux | macOS | Windows | Native dependency contract |
| --- | --- | --- | --- | --- |
| `--no-default-features` | Portable | Portable | Portable | No `libloading`, `pnet`, `pcap`, `rtnetlink`, `socket2`, or `windows` adapter package |
| Default features | Portable core plus isolated alpha interface enumeration | Portable core plus isolated alpha interface enumeration | Portable | Current `live` enables only the temporary Unix enumeration adapter |
| `--all-features` | Native routes/interfaces and libpcap L2 | Native routes/interfaces and libpcap L2 | Native routes/interfaces and dynamic Npcap L2 | Hosted tests do not require capture privileges; Windows resolves the DLL only when live I/O is opened |

`--features native-route` may also be selected without the default `live` feature. It returns platform-neutral `RouteDecision`, `InterfaceInfo`, `RouteSelectionReason`, and `NativeRouteError` values. Route lookup can constrain an exact interface and an interface-owned preferred source, rejects family/assignment/mismatch failures, reports the next hop and effective MTU, and never invokes ARP/NDP, capture, or transmission.

`--features native-layer2` selects `SystemLayer2Io` and `SystemCaptureProvider`. Capture activation completes before the session reports ready; the owned worker preserves native timestamps, open numeric link types, interface metadata, complete snap-length-bounded bytes, native loss counters, and bounded frame/byte queue accounting. Stop interrupts the native read and joins its worker. Missing dependencies, permissions, devices, and unsupported targets return typed errors; the adapter never changes the selected link mode.

`SystemNeighborResolver` composes the system interface, Layer 2, and capture providers. Its rich route-planner path uses the interface-owned source IP and MAC, selected next hop, MTU, link type, and exact VLAN stack. ARP and NDP use finite attempts and timeouts, protocol validation, bounded captured evidence, joined shutdown, and a bounded finite-lifetime cache. Selecting both `native-route` and `native-layer2` supplies the complete native planning and resolution path; either provider family remains independently injectable.

`--features native-layer3` selects `SystemLayer3Io` on Linux, macOS, and Windows. It accepts only complete IPv4/IPv6 datagrams whose destination, family, and size match the materialized route, binds the route-selected interface/source independently of a crafted packet source, enables full-header raw transmission, and checks complete writes. Linux and Windows may fill selected zero or derived IPv4 fields; macOS additionally consumes total length and fragment fields in host order. The adapter validates values that the kernel would rewrite and uses a private macOS submission copy, so a success can report the original exact wire bytes. Spoofed raw UDP that Windows can silently discard is rejected before send; other platform restrictions remain typed socket errors.

Every profile exposes the platform-neutral provider traits. An application can implement interface, route, neighbor, typed Layer 2/Layer 3 transmission, and capture providers without importing a native wrapper. `Layer2Frame` and `Layer3Frame` reject a materialized route for the other mode, and `DispatchPacketIo` cannot cross those provider boundaries.

The component and native ownership rules are fixed by [ADR 0004](adr/0004-component-and-native-adapter-boundaries.md). Portable components forbid unsafe code. Direct native dependencies, FFI, and any reviewed unsafe implementation are confined to the private `io::platform` subtree and checked by CI.

## Stable v0.2 target

| Capability | Linux x86_64 GNU | macOS arm64/x86_64 | Windows x86_64 MSVC |
| --- | --- | --- | --- |
| Packet construction/dissection | Required | Required | Required |
| Streaming PCAP/PCAPNG read/write | Required | Required | Required |
| Interface enumeration | Required | Required | Required |
| Native route/source selection | Netlink | Routing sockets/native interface APIs | `GetBestRoute2`/adapter APIs |
| Layer 2 capture/injection | libpcap | libpcap/BPF | Npcap |
| Layer 3 transmission where supported | Required | Required | Required |
| Gateway-aware ARP/NDP | Required | Required | Required |
| Coordinated send/capture/exchange | Required | Required | Required |
| Scan and traceroute tools | Required | Required | Required |
| Actionable privilege/dependency errors | Required | Required | Required |

Explicitly complete packets must produce identical protocol bytes on every platform. Platform adapters may differ only in route discovery, link materialization, capture/injection, timestamp facilities, and error reporting.

## Native dependencies and privileges

### Linux

- Portable and offline use: no libpcap requirement.
- `native-layer2` requires libpcap development/runtime packages (`libpcap-dev` on Debian/Ubuntu) and uses the optional `pcap` 2.4 wrapper.
- `native-layer3` uses `socket2` 0.6 raw sockets and requires `CAP_NET_RAW` or equivalent privilege. It binds the selected device and interface-owned source before sending.
- Live operations commonly need root or narrowly granted `CAP_NET_RAW`; capture configuration can also need `CAP_NET_ADMIN` depending on the operation.
- `native-route` route and interface discovery uses route netlink and is exercised in unprivileged CI.
- The selected safe route wrapper is `rtnetlink` 0.21; Layer 2 I/O uses `pcap` 2.4. Both are optional and target-specific.
- CI currently qualifies this provider on Ubuntu 24.04. `rtnetlink` and its netlink dependencies are MIT-licensed; the repository records a narrow policy exception for the non-vulnerable, unmaintained `paste` transitive macro advisory until that dependency path is removed upstream.

### macOS

- Portable and offline use: no external packet-capture package.
- `native-layer2` uses the system libpcap/BPF facilities and can require elevated privileges or an administrator-managed device policy.
- `native-layer3` uses raw IPv4/IPv6 sockets, macOS interface-index binding, and a private host-order IPv4 submission copy; root-equivalent raw-socket privilege is normally required.
- `native-route` route selection uses routing sockets and `getifaddrs`; it is exercised on hosted macOS CI for IPv4/IPv6 loopback selection and interface enumeration.
- Routing-socket setup is isolated behind `socket2` 0.6 plus the private native ABI adapter; libpcap/BPF integration uses `pcap` 2.4.
- CI currently qualifies passive discovery on macOS 14 arm64; both `socket2` and `libc` are MIT OR Apache-2.0 licensed.

### Windows

- Default and `--no-default-features` builds are portable profiles. Neither resolves `libloading`, `pnet`, or `windows`, links `Packet.lib`, nor requires an Npcap installation or SDK.
- The default feature set does not imply a Windows native adapter. `native-route` alone enables Windows route/interface discovery without Npcap; `--all-features` still loads Npcap only when Layer 2 I/O is opened.
- `native-layer2` supports x86_64 MSVC with the Npcap 1.88 runtime and the pinned SDK 1.16 ABI. PacketcraftR does not bundle Npcap or its SDK and does not link an import library.
- `native-layer3` uses Winsock raw IPv4/IPv6 sockets. Windows client restrictions can prohibit raw TCP and discard raw UDP with a non-local source; PacketcraftR rejects the silent UDP case, while native TCP permission failures remain typed socket errors.
- The adapter obtains the Windows directory from the operating system, loads `System32\\Npcap\\wpcap.dll` with restricted dependent-DLL search flags, validates every required symbol, and initializes UTF-8 mode once. A missing/incompatible runtime is a typed dependency error and never changes link mode.
- `native-route` route/source selection uses `GetBestRoute2` and adapter enumeration uses `GetAdaptersAddresses`; both IPv4 and IPv6 paths are exercised on hosted Windows CI.
- IP Helper calls use narrowly enabled `windows` 0.62 bindings. Npcap uses its C ABI through optional, ISC-licensed `libloading` 0.8 so ordinary Windows builds and hosted native tests have no `wpcap.lib`/`Packet.lib` link boundary.
- CI currently qualifies passive discovery plus Npcap ABI/error/lifecycle behavior on Windows Server 2022 x86_64 MSVC. Actual capture/injection with Npcap 1.88 remains mandatory on a dedicated privileged runner before release candidate.

## Link-mode contract

`LinkMode::Auto`, `Layer2`, and `Layer3` select behavior explicitly:

| Packet/request | Result |
| --- | --- |
| Explicit Ethernet or VLAN with `Auto` | Layer 2 |
| IP-root packet with `Auto` | Layer 3 where supported; otherwise an explicitly reported Layer 2 materialization |
| IP-root packet with `Layer2` | A reported Ethernet envelope is synthesized after route/neighbor resolution |
| Ethernet packet with `Layer3` | Typed error |
| Neighbor resolution failure | Error; never a link-mode fallback |

For an off-link destination, neighbor resolution targets the selected route gateway. An explicit spoofed source remains in the crafted packet, while ARP/NDP uses an interface-owned source. For IPv6 SRH, route selection targets the first visited segment and transport checksums use the final destination.

Active neighbor discovery preserves the planned VLAN stack and interface identity. A response from another interface or VLAN, an invalid ARP/NDP message, an NDP advertisement with a bad checksum or hop limit, or an uncorrelated pre-request frame remains evidence but cannot satisfy the lookup. Exhaustion returns a typed error with attempts, bounded frames, truncation state, and capture statistics; it never falls back to another route or link mode.

## Continuous-integration coverage

Pull requests run formatting and default/no-default/all-feature lint, test, and documentation profiles on Linux. Default, no-default, and all-feature profiles compile and test on macOS. Windows runs portable default/no-default jobs and a native all-feature job; every Windows profile rejects static `pcap`, `pnet`, and `Packet.lib` linkage, while portable profiles also reject `libloading`, `socket2`, and the `windows` adapter package. The native profile requires both the Npcap runtime loader and raw-socket wrapper. A separate architecture check resolves no-default dependency trees for Linux, macOS, and Windows targets and rejects native adapter packages, native references outside the platform subtree, or unsafe/FFI outside its single owner. These unprivileged hosted jobs qualify passive route/interface behavior and injected capture/send lifecycle logic, not live packet I/O.

Stable release qualification additionally requires:

- privileged Linux network-namespace topologies for Ethernet, VLAN, routed IPv4/IPv6, gateway resolution, low MTUs, exchange, scans, and traceroute;
- dedicated macOS arm64/x86_64 live-I/O runners; and
- a Windows x86_64 MSVC runner with the documented Npcap version.

A missing dedicated runner is a release blocker for the corresponding advertised live capability, not a reason to downgrade silently to portable-only behavior.
