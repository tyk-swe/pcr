# Platform and capability support

PacketcraftR separates portable packet processing from native networking.
Hosted continuous integration exercises portable behavior and native adapter
boundaries without assuming packet privileges. Real Windows traffic through
Npcap remains experimental; no hosted result should be interpreted as a live
Npcap pass.

## Capability matrix

| Capability | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Packet construction, dissection, schemas, and output | Supported | Supported | Supported |
| Offline PCAP/PCAPNG read and write | Supported | Supported | Supported |
| Passive interface, route, source, next-hop, and MTU discovery | Supported | Supported | Supported |
| Layer 2 capture and injection | libpcap | libpcap/BPF | Npcap; experimental live path |
| Raw Layer 3 transmission | Complete IPv4/IPv6 | Exact IPv4; complete-header IPv6 unsupported | Winsock restrictions apply; broader live use is experimental |
| Gateway-aware ARP/NDP | Supported | Supported | Npcap-dependent; experimental |
| Exchange, replay, scan, traceroute, DNS, and live fuzzing | Supported native path | Supported native path | Npcap-dependent paths are experimental |
| Offline deterministic fuzzing and injected providers | Supported | Supported | Supported |

Portable protocol bytes, document parsing, schemas, output envelopes, and
error classification are target-independent. Platform variance is limited to
interfaces, routes, native capabilities, timestamps, privileges, and operating
system diagnostics.

## Build profiles

| Cargo profile | Linux | macOS | Windows |
| --- | --- | --- | --- |
| `--no-default-features` | Portable | Portable | Portable |
| Default features | Portable core plus basic interface enumeration | Portable core plus basic interface enumeration | Portable |
| `--features native-route` | Netlink | Routing sockets and `getifaddrs` | IP Helper |
| `--features native-layer2` | libpcap | libpcap/BPF | Dynamically loaded Npcap |
| `--features native-layer3` | Raw sockets | Raw IPv4 | Winsock raw sockets |

The portable profile does not resolve `libloading`, `pnet`, `pcap`,
`rtnetlink`, `socket2`, or `windows` adapter packages. Native dependencies are
optional, target-specific, and confined to the private `packetcraftr-io`
platform adapter.

`native-route` is passive: it never performs ARP/NDP, capture, or transmission.
It returns platform-neutral route, interface, source, next-hop, MTU, and
selection-reason values.

`native-layer2` provides owned bounded capture and complete-frame injection.
Capture readiness precedes traffic, stop interrupts and joins the worker, and
records preserve native timestamps, link types, interface metadata, lengths,
bytes, and available loss counters.

`native-layer3` accepts only complete datagrams consistent with the selected
route, family, destination, and MTU. Linux supports complete IPv4 and IPv6.
macOS supports exact IPv4 through a private host-order submission copy but
cannot accept a caller-supplied complete IPv6 header. Windows raw sockets are
subject to Winsock restrictions; PacketcraftR rejects raw UDP with a non-local
source when the platform can silently discard it.

## Workflow requirements

| Workflow | Required native features |
| --- | --- |
| `plan`, `routes` | `native-route` |
| Layer 3 `send` | `native-route,native-layer3` |
| Layer 2 `send` | `native-route,native-layer2` |
| `capture` | `native-route,native-layer2` |
| `exchange`, `scan`, `traceroute`, `dns` | Route and capture features plus the selected send path |
| Offline `fuzz` | None |
| Live `fuzz` | Same path as `exchange` |
| Ethernet `replay` | `native-route,native-layer2` |
| Raw IP `replay` | `native-route,native-layer3` |

An unavailable feature, runtime, device, or privilege is a typed capability
failure. PacketcraftR never changes link mode or substitutes a provider to
make an operation appear successful.

## Native dependencies and privileges

### Linux

- `native-layer2` requires libpcap development and runtime packages, commonly
  `libpcap-dev` on Debian and Ubuntu.
- `native-route` uses route netlink and needs no packet privilege.
- Layer 2 traffic and raw sockets commonly require `CAP_NET_RAW`; capture or
  device configuration may also require `CAP_NET_ADMIN`.
- Prefer a disposable network namespace or dedicated lab. Do not grant packet
  capabilities to a shared writable binary.

### macOS

- The operating system supplies libpcap/BPF.
- BPF access depends on administrator-managed device policy.
- Exact raw IPv4 normally requires elevation. Complete-header raw IPv6 is
  rejected before socket I/O; PacketcraftR does not silently fall back to
  Layer 2.

### Windows

- Default and portable builds do not require Npcap, its SDK, or `Packet.lib`.
- `native-route` uses `GetBestRoute2` and `GetAdaptersAddresses` without Npcap.
- `native-layer2` supports x86_64 MSVC with the Npcap 1.88 runtime and SDK 1.16
  ABI. It loads `System32\\Npcap\\wpcap.dll` from a restricted system path.
- Missing architecture, symbols, dependent DLLs, or privileges produce typed
  errors. The adapter does not search alternate DLL paths or switch providers.
- Actual Npcap capture, injection, neighbor discovery, and dependent workflows
  remain experimental.

## Errors and troubleshooting

| Failure | Machine code family | Exit |
| --- | --- | ---: |
| Unsupported capability or link mode | `capability.*` | 4 |
| Missing dependency or privilege | `capability.*` | 4 |
| Route, device, send, capture, timeout, or cleanup | `io.*` | 5 |
| Traffic-policy denial | `policy.*` | 6 |
| Packet or live-frame validation | `packet.*` | 3 |
| Invalid CLI limits or arguments | `cli.*` | 2 |
| Inconsistent provider report | `internal.*` | 70 |

Start by separating portable and native builds:

```console
cargo build --locked --no-default-features
cargo build --locked --features native-route
cargo build --locked --features native-route,native-layer2,native-layer3
packetcraftr --output json interfaces
packetcraftr --output json routes
```

On Linux, confirm libpcap with `ldconfig -p | grep libpcap`. On macOS, inspect
the administrator-managed `/dev/bpf*` devices. On Windows, inspect Npcap with:

```powershell
Get-Service npcap -ErrorAction SilentlyContinue
Test-Path "$env:WINDIR\System32\Npcap\wpcap.dll"
```

Use the structured error's `remediation` field before changing privileges or
installing a native dependency.

## Link-mode behavior

| Packet and request | Result |
| --- | --- |
| Ethernet or VLAN with `Auto` | Layer 2 |
| IP root with `Auto` | Layer 3 where exact transmission is supported; otherwise an explicit Layer 2 plan |
| IP root with `Layer2` | Ethernet is materialized after route and neighbor resolution |
| Ethernet with `Layer3` | Typed error |
| Neighbor resolution failure | Typed error; never a fallback |

For an off-link destination, neighbor discovery targets the selected gateway.
A crafted source remains distinct from the interface-owned source used for
ARP/NDP. Responses from another interface or VLAN and invalid or uncorrelated
ARP/NDP records remain bounded evidence but cannot satisfy the lookup.

## Continuous integration

Pull requests run formatting, linting, tests, doctests, rustdoc, schema and
fixture validation, architecture policy, and public API/CLI contract checks.
Default, portable, and all-feature profiles are checked across Linux, macOS,
and Windows. These hosted jobs validate compilation, passive discovery, exact
portable bytes, and injected native lifecycles; they do not open packet devices
or grant live-network privileges.
