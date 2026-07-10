# Platform and capability matrix

This document distinguishes the current alpha checkpoint from the stable v0.2 target. "Builds" does not mean a live networking workflow has been release-qualified.

Status snapshot: 2026-07-09 (`0.2.0-alpha.1`).

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
| Route/source planning | Portable alpha | Portable alpha | Portable alpha | Injectable planner is implemented; native OS providers are later alpha work |
| Live Layer 2 capture/injection | Planned | Planned | Planned | New native adapters will use libpcap/Npcap; no fallback is present |
| Raw Layer 3 transmission | Planned | Planned | Planned | Cross-platform adapters are a later alpha milestone |
| Coordinated exchange | Portable alpha | Portable alpha | Portable alpha | Injectable endpoint has a readiness barrier, bounded retention, and core matchers; native I/O remains planned |
| Defragmentation and TCP reassembly | Alpha, CI | Alpha, CI | Alpha, CI | Portable stages bounded by flow, byte, fragment, pending-TCP-segment, and expiry limits |
| Scan, traceroute, DNS, and fuzz tools | Planned | Planned | Planned | v0.1 paths were removed; replacements will use shared APIs |

Consult the exact release notes and `packetcraftr --help` for the checkout in use; a planned row is not a stable v0.2 guarantee.

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
- Route and interface discovery uses netlink in the v0.2 target.

### macOS

- Portable and offline use: no external packet-capture package.
- Future live capture/injection uses the system libpcap/BPF facilities and can require elevated privileges or an administrator-managed device policy.
- Route selection uses routing sockets and native interface APIs in the v0.2 target.

### Windows

- Default and `--no-default-features` builds are portable profiles. Neither resolves `pnet`, links `Packet.lib`, nor requires an Npcap installation or SDK.
- The default feature set does not imply a Windows native adapter. Until that adapter is implemented, commands such as `interfaces` return an actionable capability error instead of falling through to another link mode or failing at link time.
- Future Layer 2 capture/injection requires a supported Npcap installation. Building native integration can require the matching Npcap SDK.
- A future explicit native-adapter profile must pin and provision its supported Npcap SDK/runtime contract. Missing or incompatible native dependencies must remain capability errors and must never silently change link mode.
- Route/source selection uses Windows IP Helper APIs such as `GetBestRoute2` in the v0.2 target.

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

Pull requests run formatting and default/no-default/all-feature lint, test, and documentation profiles on Linux. Default and no-default profiles compile and test on macOS. Windows runs separately named portable default and portable no-default jobs, and CI rejects either dependency graph if it contains `pnet` (and therefore the `Packet.lib` link boundary). These unprivileged hosted jobs do not qualify live I/O.

Stable release qualification additionally requires:

- privileged Linux network-namespace topologies for Ethernet, VLAN, routed IPv4/IPv6, gateway resolution, low MTUs, exchange, scans, and traceroute;
- dedicated macOS arm64/x86_64 live-I/O runners; and
- a Windows x86_64 MSVC runner with the documented Npcap version.

A missing dedicated runner is a release blocker for the corresponding advertised live capability, not a reason to downgrade silently to portable-only behavior.
