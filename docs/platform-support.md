# Platform and capability matrix

This document distinguishes the current alpha checkpoint from the stable v0.2 target. "Builds" does not mean a live networking workflow has been release-qualified.

Status snapshot: 2026-07-11 (`0.2.0-alpha.1`).

## Status legend

- **Alpha:** implementation exists but its API and qualification are incomplete.
- **Planned:** required before stable v0.2, but not complete in this checkpoint.
- **CI:** compiled or tested in unprivileged continuous integration.
- **Runner:** requires a dedicated privileged/native-dependency test runner.

## Current alpha checkpoint

| Capability | Linux | macOS | Windows | Notes |
| --- | --- | --- | --- | --- |
| Portable packet/layer/field model | Alpha, CI | Alpha, CI | Alpha, CI | Runtime-neutral; no native capture dependency |
| Generic registry, build, and dissection APIs | Beta candidate, CI | Beta candidate, CI | Beta candidate, CI | The [stable built-in protocol matrix](protocol-support.md) is complete and corpus-backed; the Rust façade is baseline-diffed in CI |
| Offline classic PCAP/PCAPNG | Alpha, CI | Alpha, CI | Alpha, CI | Pure Rust bounded read/write; metadata-preserving multi-interface copy through `read` and the public API |
| Packet-expression/document CLI | Alpha, CI | Alpha, CI | Alpha, CI | One exclusive recipe grammar is shared by `build`, `plan`, `send`, `capture`, and `exchange` |
| Route/source planning and inventory CLI | Native alpha, CI | Native alpha, CI | Native alpha, CI | `plan` and interface-bound `routes` use `native-route`; both remain passive |
| Live Layer 2 capture/injection CLI | Native alpha, CI/Runner | Native alpha, CI/Runner | Native alpha, CI/Runner | `send`/`capture` use libpcap or runtime-loaded Npcap; hosted CI covers policy, ABI, and lifecycle seams, while privileged qualification requires dedicated runners |
| Gateway-aware ARP/NDP | Native alpha, CI/Runner | Native alpha, CI/Runner | Native alpha, CI/Runner | Portable resolver logic is deterministically tested with injected providers; privileged routed/VLAN qualification remains a release gate |
| Raw Layer 3 transmission CLI | Native alpha, CI/Runner | Native alpha, CI/Runner | Native alpha, CI/Runner | `send --link-mode layer3` uses target raw sockets; hosted CI covers validation and injected send seams, while privileged qualification requires dedicated runners |
| Coordinated exchange CLI | Native alpha, CI/Runner | Native alpha, CI/Runner | Native alpha, CI/Runner | `exchange` awaits capture readiness before send and shares bounded retention, loss reporting, and joined shutdown contracts |
| Exact bounded replay CLI | Native alpha, CI/Runner | Native alpha, CI/Runner | Native alpha, CI/Runner | Portable policy/timing/transmitter seams are deterministic in hosted CI; privileged Ethernet/raw-IP replay remains a dedicated-runner gate |
| Defragmentation and TCP reassembly | Alpha, CI | Alpha, CI | Alpha, CI | Portable stages bounded by flow, byte, fragment, pending-TCP-segment, and expiry limits |
| Structured scan workflow | Native alpha, CI/Runner | Native alpha, CI/Runner | Native alpha, CI/Runner | Portable planner, matcher/classifier, policy, timing, and injected lifecycle tests run in hosted CI; privileged qualification remains a dedicated-runner gate |
| Structured traceroute workflow | Native alpha, CI/Runner | Native alpha, CI/Runner | Native alpha, CI/Runner | Portable hop planner, IPv4/IPv6 quoted-error classifier, policy, timing, and injected exchange seams run in hosted CI; privileged qualification remains a dedicated-runner gate |
| Structured DNS workflow | Native alpha, CI/Runner | Native alpha, CI/Runner | Native alpha, CI/Runner | Portable codec, relevance, policy/rebinding, timing, and injected exchange tests run in hosted CI; privileged UDP qualification remains a dedicated-runner gate |
| Bounded field-aware fuzz workflow | Alpha, CI/Runner | Alpha, CI/Runner | Alpha, CI/Runner | Offline deterministic mutation/build/dissection is portable and hosted-CI tested; optional live cases use the shared route, policy, exchange, and selected native send path |

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

`--features native-layer3` selects `SystemLayer3Io` on Linux, macOS, and Windows. It accepts only complete IPv4/IPv6 datagrams whose destination, family, and size match the materialized route, constrains the route-selected interface independently of a crafted packet source, enables full-header raw transmission, and checks complete writes. Linux uses device binding, macOS uses interface-index binding, and Winsock uses its family-appropriate unicast or multicast interface option. Linux and Windows may fill selected zero or derived IPv4 fields; macOS additionally consumes total length and fragment fields in host order. The adapter validates values that the kernel would rewrite and uses a private macOS submission copy, so a success can report the original exact wire bytes. Spoofed raw UDP that Windows can silently discard is rejected before send; other platform restrictions remain typed socket errors.

The native CLI feature requirements are explicit:

| Workflow | Required native feature path |
| --- | --- |
| `plan`, `routes` | `native-route` |
| Layer 3 `send` | `native-route` + `native-layer3` |
| Layer 2 `send` | `native-route` + `native-layer2`; unresolved neighbors use the same Layer 2 capture provider |
| `capture` | `native-route` + `native-layer2` |
| `exchange` | `native-route` + `native-layer2` for capture, plus the selected Layer 2 or Layer 3 send path |
| `scan` | Same route, capture, and selected send paths as `exchange` |
| `traceroute` | Same route, capture, and selected send paths as `exchange` |
| `dns` | Same route, capture, and selected UDP send paths as `exchange` |
| Offline `fuzz` | None; portable on every profile |
| Live `fuzz` | Same route, capture, and selected send paths as `exchange` |
| Ethernet `replay` | `native-route` + `native-layer2` |
| Raw IPv4/IPv6 `replay` | `native-route` + `native-layer3` |

An unavailable feature, native runtime, device, or privilege is returned as a
typed capability failure; no command silently changes link mode or substitutes
another provider. `plan` and `routes` may inspect only passive route/interface
state. `capture` has a finite overall window. `exchange` arms and awaits its
owned capture session before the first send, and both commands stop and join
capture on success or failure. `replay` fixes its provider from the capture
root, authorizes complete bytes before interface/route I/O, and requires exact
backend wire evidence for every successful frame.

Every profile exposes the platform-neutral provider traits. An application can implement interface, route, neighbor, typed Layer 2/Layer 3 transmission, and capture providers without importing a native wrapper. `Layer2Frame` and `Layer3Frame` reject a materialized route for the other mode, and `DispatchPacketIo` cannot cross those provider boundaries.

Every live boundary also implements the shared error classification contract.
Unsupported adapters, missing dependencies, and privileges map to exit class
4; route, device, capture, timeout, send, partial-send, and cleanup failures map
to class 5; policy denials map to class 6; and inconsistent provider reports map
to class 70. Route providers can classify their own error type without exposing
a native wrapper. Neighbor and exchange failures retain typed operation and
cleanup errors when both occur. Classifications include remediation and never
authorize a silent link-mode or provider fallback.

| Rust failure family | Stable machine code | Exit |
| --- | --- | ---: |
| Unsupported route/link/live adapter | `capability.route`, `capability.link_mode`, `capability.unsupported` | 4 |
| Missing native dependency | `capability.missing_dependency` | 4 |
| Missing privilege | `capability.privilege` | 4 |
| Traffic-policy denial | `policy.*` | 6 |
| Route/device/runtime send or capture | `io.route*`, `io.device`, `io.send`, `io.capture*` | 5 |
| Neighbor or resolver timeout/failure | `io.neighbor*`, `io.hostname_resolution` | 5 |
| Incomplete send | `io.partial_send` | 5 |
| Invalid CLI resource limit | `cli.capture_limit`, `cli.capture_timeout`, `cli.exchange_limit`, `cli.neighbor_limit`, `cli.dns_limit`, `cli.fuzz_limit` | 2 |
| Packet/live-frame validation | `packet.*` | 3 |
| Inconsistent provider report/state | `internal.*` | 70 |

Hostname resolution is platform-neutral and independently injectable. The
validated declared hostname must pass traffic policy before the resolver is
called. Results are distinct-address bounded, and every address is checked
against current policy before any route provider receives one. Re-resolution
repeats both checks, preventing a changed DNS answer from bypassing policy.

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
| Scan, traceroute, DNS, and bounded fuzz tools | Required | Required | Required |
| Actionable privilege/dependency errors | Required | Required | Required |

Explicitly complete packets must produce identical protocol bytes on every platform. Platform adapters may differ only in route discovery, link materialization, capture/injection, timestamp facilities, and error reporting.

## Native dependencies and privileges

### Linux

- Portable and offline use: no libpcap requirement.
- `native-layer2` requires libpcap development/runtime packages (`libpcap-dev` on Debian/Ubuntu) and uses the optional `pcap` 2.4 wrapper.
- `native-layer3` uses `socket2` 0.6 raw sockets and requires `CAP_NET_RAW` or equivalent privilege. It binds the selected Linux device before sending while preserving a separately crafted source.
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

Pull requests run formatting and default/no-default/all-feature lint, test, and documentation profiles on Linux. Default, no-default, and all-feature profiles compile and test on macOS. Windows runs portable default/no-default jobs and a native all-feature job; every Windows profile rejects static `pcap`, `pnet`, and `Packet.lib` linkage, while portable profiles also reject `libloading`, `socket2`, and the `windows` adapter package. The native profile requires both the Npcap runtime loader and raw-socket wrapper. A separate architecture check resolves no-default dependency trees for Linux, macOS, and Windows targets and rejects native adapter packages, native references outside the platform subtree, or unsafe/FFI outside its single owner. The cross-platform test profiles read the same SHA-256-pinned authoritative frame/capture/document corpus only after provenance validation; CI enforces fixture sidecars over the complete pull-request or push range. These unprivileged hosted jobs qualify passive route/interface behavior and injected capture/send lifecycle logic, not live packet I/O.

Stable release qualification additionally requires:

- privileged Linux network-namespace topologies for Ethernet, VLAN, routed IPv4/IPv6, gateway resolution, low MTUs, exchange, scans, and traceroute;
- dedicated macOS arm64/x86_64 live-I/O runners; and
- a Windows x86_64 MSVC runner with the documented Npcap version.

A missing dedicated runner is a release blocker for the corresponding advertised live capability, not a reason to downgrade silently to portable-only behavior.
