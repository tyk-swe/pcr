# ADR 0004: Component graph and native adapter ownership

- Status: Accepted
- Date: 2026-07-10

## Context

The v0.2 alpha proves packet, protocol, route, capture, session, and client contracts in one crate before the planned component-crate extraction. Without explicit dependency directions, provider traits drift into the façade, native wrapper types leak into callers, and a later split creates cycles or forces downstream import changes. Native dependencies and FFI also need one auditable owner: portable packet work must remain buildable without a host SDK, packet-capture runtime, privileged runner, or unsafe code.

Linux, macOS, and Windows require different route, capture, and raw-socket facilities. The public contracts must express their common semantics while preserving target-specific capability errors. An unavailable Layer 2 or Layer 3 implementation must not silently redirect bytes to another provider.

## Decision

### Component dependency graph

The module boundaries are the extraction boundaries. Arrows below mean "may depend on":

```text
packetcraftr-protocols ───────> packetcraftr-core
packetcraftr-io ──────────────> packetcraftr-core
packetcraftr-session ─────────> packetcraftr-core, packetcraftr-protocols, packetcraftr-io
packetcraftr-tools ───────────> packetcraftr-core, packetcraftr-protocols,
                                packetcraftr-io, packetcraftr-session
packetcraftr façade/client ───> all component crates

packetcraftr-io::platform ────> packetcraftr-io public provider contracts
```

Dependencies may only point rightward/downward in this list; components never depend on the root façade or CLI. The boundaries own:

| Component | Ownership |
| --- | --- |
| `core` | ordered packet model, fields, registry contracts, build/dissect, documents, capture records, and diagnostics |
| `protocols` | built-in codecs, typed protocol layers, bindings, and response matchers |
| `io` | offline capture I/O, interface/route/neighbor values, capture sessions, typed L2/L3 transmission seams, and platform adapters |
| `session` | bounded exchange state, fragmentation, flow tracking, and reassembly |
| `tools` | reusable scan, traceroute, DNS, replay, and fuzz workflows |
| root façade | stable reexports, high-level policy/client composition, output contracts, and CLI wiring |

`io` owns `InterfaceProvider`, `RouteProvider`, `NeighborResolver`, `Layer2Io`, `Layer3Io`, `PacketIo`, `CaptureProvider`, and `ExchangeIo`. These traits use only standard-library and PacketcraftR-owned types. Native handles, wrapper errors, socket addresses, and capture-library packet types cannot cross the public boundary.

`Layer2Frame` and `Layer3Frame` have checked constructors and private fields. `TransmissionFrame` selects one of them from a materialized `LinkMode`; `DispatchPacketIo` sends each variant only to the corresponding provider. An unresolved `Auto` mode or mismatched constructor is a typed error. The high-level client submits the exact already-built bytes and never asks a backend to infer or synthesize a different envelope.

Provider contracts are exported from `packetcraftr::io` and the root. The historical `packetcraftr::client::*` provider paths remain compatibility reexports during the alpha. This lets XOD-43 extract modules into synchronized crates without changing ordinary root imports.

### Unsafe and FFI policy

The workspace lint is `unsafe_code = "deny"`. Portable modules (`core`, `protocols`, `session`, `tools`, the client, and CLI) strengthen that to `#![forbid(unsafe_code)]`. The crate-private `src/io/platform` subtree is the only location allowed to lower the lint and the only location allowed to contain:

- an `unsafe` block, function, implementation, or trait;
- an `extern "C"`/`extern "system"` boundary; or
- a direct reference to a native networking wrapper.

Every future unsafe operation must be minimal, carry a local `SAFETY:` invariant, convert native inputs to owned `io` values before returning, and receive platform-adapter review. No platform module is publicly exported. `scripts/check-architecture.sh` enforces directory ownership, portable `forbid` attributes, the private module declaration, native source references, and portable dependency trees in CI.

### Native wrapper policy

Target adapters use the following wrapper families:

| Target/facility | Selected boundary | Constraint |
| --- | --- | --- |
| Linux routes/interfaces | [`rtnetlink`](https://docs.rs/rtnetlink/latest/rtnetlink/) over kernel route netlink | Target-specific and feature-gated; disable unused default features; translate messages inside `io::platform::linux` |
| Linux L2 capture/injection | [`pcap`](https://docs.rs/crate/pcap/latest/source/README.md) over system libpcap | Target-specific native feature; no libpcap in portable profiles |
| Linux raw L3 | `socket2`/standard sockets | Keep raw-socket setup and privilege mapping inside the Linux adapter |
| macOS routes/raw L3 | `socket2` plus the native routing-socket ABI | Parse routing messages inside `io::platform::macos`; no native structures escape |
| macOS L2 capture/injection | `pcap` over system libpcap/BPF | Target-specific native feature; BPF descriptors remain private |
| Windows routes/interfaces/raw L3 | [`windows`](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/NetworkManagement/IpHelper/index.html) IP Helper and Winsock bindings | Request only required Win32 feature namespaces; map status codes immediately |
| Windows L2 capture/injection | `pcap` over a pinned Npcap SDK/runtime contract | Explicit Windows-native feature; portable default never links `Packet.lib` |

Native packages are optional, target-specific, use `default-features = false` where supported, and are locked in `Cargo.lock`. Adding or updating one requires its platform ticket to record the tested wrapper version, native SDK/runtime version, license, minimum host version, and privileged qualification evidence. The temporary Unix `pnet` interface enumeration remains isolated in `io::platform` for default builds until later capture adapters replace it; `native-route` selects the platform-neutral route/interface contracts instead.

### Features, builds, and publication

`--no-default-features` is the portable contract on every target: packet construction/dissection, documents, offline capture, injected providers, and external provider implementations compile without native adapter packages. During the alpha, the default `live` feature enables the isolated Unix enumeration adapter while Windows default remains portable. The explicit `native-route` feature enables passive target-native route, source, MTU, and interface selection; it does not imply neighbor discovery, capture, or transmission. `--all-features` therefore exercises native route providers on each stable target while preserving the portable no-default boundary.

CI covers Linux default/no-default/all-feature tests, lints, and docs; macOS default/no-default/all-feature compile and tests; Windows portable default/no-default plus native-route all-feature compile and tests; and target-resolved no-default dependency-tree checks for all three operating-system families. Privileged live qualification is separate and remains mandatory before advertising capture or transmission capability.

All extracted crates take one version from `[workspace.package]` and release together. Their publish order is `packetcraftr-core`, `packetcraftr-protocols`, `packetcraftr-io`, `packetcraftr-session`, `packetcraftr-tools`, then `packetcraftr`. Workspace metadata records that order and the native/unsafe owner. Component crates use exact synchronized internal dependency versions for a stable release; root reexports remain the ordinary public surface. This graph has no cycle.

## Consequences

- Route/interface adapters share dedicated private Linux, macOS, and Windows modules; later platform tickets extend those same ownership boundaries with L2, L3, capture, and exchange implementations.
- External providers can compile on any target without importing an OS wrapper type.
- A provider cannot accidentally receive the other link mode through `DispatchPacketIo`.
- Portable builds remain useful for offline work, tests, and custom injected providers.
- Native error translation is repetitive across targets, but platform-specific semantics remain visible as typed capability, privilege, send, and capture failures.
- The eventual crate extraction can follow the recorded DAG and publication order without adding a compatibility cycle through the façade.

## Alternatives considered

### Put native adapters in the root client

Rejected because the façade would own target dependencies and component crates would need to depend back on it.

### Expose native wrapper handles in provider traits

Rejected because every caller and test would become target- and wrapper-version-specific, making portable implementations and independent wrapper upgrades impossible.

### Use one untyped byte-slice send method in every adapter

Rejected because raw sockets and link-layer injection have different byte contracts. A mode flag beside an untyped slice can be ignored; checked frame types make dispatch structural.

### Forbid unsafe code across the entire crate

Rejected because small OS ABI gaps may require reviewed FFI. One private, CI-enforced adapter subtree is a narrower and auditable exception.
