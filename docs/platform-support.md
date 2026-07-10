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
| Live Layer 2 capture/injection | Planned | Planned | Planned | New native adapters will use libpcap/Npcap; no fallback is present |
| Raw Layer 3 transmission | Planned | Planned | Planned | Cross-platform adapters are a later alpha milestone |
| Coordinated exchange | Portable alpha | Portable alpha | Portable alpha | Injectable endpoint has a readiness barrier, bounded retention, and core matchers; native I/O remains planned |
| Defragmentation and TCP reassembly | Alpha, CI | Alpha, CI | Alpha, CI | Portable stages bounded by flow, byte, fragment, pending-TCP-segment, and expiry limits |
| Scan, traceroute, DNS, and fuzz tools | Planned | Planned | Planned | v0.1 paths were removed; replacements will use shared APIs |

Consult the exact release notes and `packetcraftr --help` for the checkout in use; a planned row is not a stable v0.2 guarantee.

## Build and feature contracts

| Cargo profile | Linux | macOS | Windows | Native dependency contract |
| --- | --- | --- | --- | --- |
| `--no-default-features` | Portable | Portable | Portable | No `pnet`, `pcap`, `rtnetlink`, `socket2`, or `windows` adapter package |
| Default features | Portable core plus isolated alpha interface enumeration | Portable core plus isolated alpha interface enumeration | Portable | Current `live` enables only the temporary Unix enumeration adapter |
| `--all-features` | Passive native routes/interfaces | Passive native routes/interfaces | Passive native routes/interfaces | Activates the target-specific dependencies owned by `native-route`; no capture SDK/runtime |

`--features native-route` may also be selected without the default `live` feature. It returns platform-neutral `RouteDecision`, `InterfaceInfo`, `RouteSelectionReason`, and `NativeRouteError` values. Route lookup can constrain an exact interface and an interface-owned preferred source, rejects family/assignment/mismatch failures, reports the next hop and effective MTU, and never invokes ARP/NDP, capture, or transmission.

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
- Future native capture/injection adapters will require libpcap development/runtime packages (`libpcap-dev` on Debian/Ubuntu); the current alpha does not link libpcap.
- Live operations commonly need root or narrowly granted `CAP_NET_RAW`; capture configuration can also need `CAP_NET_ADMIN` depending on the operation.
- `native-route` route and interface discovery uses route netlink and is exercised in unprivileged CI.
- The selected safe route wrapper is `rtnetlink` 0.21; libpcap integration will use the `pcap` crate. Both are optional and target-specific.
- CI currently qualifies this provider on Ubuntu 24.04. `rtnetlink` and its netlink dependencies are MIT-licensed; the repository records a narrow policy exception for the non-vulnerable, unmaintained `paste` transitive macro advisory until that dependency path is removed upstream.

### macOS

- Portable and offline use: no external packet-capture package.
- Future live capture/injection uses the system libpcap/BPF facilities and can require elevated privileges or an administrator-managed device policy.
- `native-route` route selection uses routing sockets and `getifaddrs`; it is exercised on hosted macOS CI for IPv4/IPv6 loopback selection and interface enumeration.
- Routing-socket setup is isolated behind `socket2` 0.6 plus the private native ABI adapter; libpcap/BPF integration will use the `pcap` crate.
- CI currently qualifies passive discovery on macOS 14 arm64; both `socket2` and `libc` are MIT OR Apache-2.0 licensed.

### Windows

- Default and `--no-default-features` builds are portable profiles. Neither resolves `pnet` or `windows`, links `Packet.lib`, nor requires an Npcap installation or SDK.
- The default feature set does not imply a Windows native adapter. `native-route` or `--all-features` explicitly enables Windows route/interface discovery without Npcap.
- Future Layer 2 capture/injection requires a supported Npcap installation. Building native integration can require the matching Npcap SDK.
- A future capture/injection profile must pin and provision its supported Npcap SDK/runtime contract. Missing or incompatible native dependencies must remain capability errors and must never silently change link mode.
- `native-route` route/source selection uses `GetBestRoute2` and adapter enumeration uses `GetAdaptersAddresses`; both IPv4 and IPv6 paths are exercised on hosted Windows CI.
- IP Helper/Winsock calls use narrowly enabled `windows` 0.62 bindings; future Npcap integration uses the `pcap` crate behind a separate explicit native capability.
- CI currently qualifies passive discovery on Windows Server 2022 x86_64 MSVC; `windows` is MIT OR Apache-2.0 licensed and uses the operating system's built-in IP Helper runtime.

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

## Continuous-integration coverage

Pull requests run formatting and default/no-default/all-feature lint, test, and documentation profiles on Linux. Default, no-default, and all-feature profiles compile and test on macOS. Windows runs portable default/no-default jobs and a native-route all-feature job; every Windows profile rejects `pnet` (and therefore the `Packet.lib` link boundary), while portable profiles also reject the `windows` adapter package. A separate architecture check resolves no-default dependency trees for Linux, macOS, and Windows targets and rejects native adapter packages, native references outside the platform subtree, or unsafe/FFI outside its single owner. These unprivileged hosted jobs qualify passive route/interface behavior, not live packet I/O.

Stable release qualification additionally requires:

- privileged Linux network-namespace topologies for Ethernet, VLAN, routed IPv4/IPv6, gateway resolution, low MTUs, exchange, scans, and traceroute;
- dedicated macOS arm64/x86_64 live-I/O runners; and
- a Windows x86_64 MSVC runner with the documented Npcap version.

A missing dedicated runner is a release blocker for the corresponding advertised live capability, not a reason to downgrade silently to portable-only behavior.
