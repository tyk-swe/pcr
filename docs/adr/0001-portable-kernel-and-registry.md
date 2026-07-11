# ADR 0001: Portable kernel, immutable registry, and stable façade

- Status: Accepted
- Date: 2026-07-09
- Amended: 2026-07-11 (physical component extraction)

## Context

The v0.1 implementation couples a fixed protocol sequence, operating-system I/O, listener state, routing settings, and CLI orchestration. Adding a protocol requires central match arms, and applications cannot build or inspect arbitrary repeated layers without using private types. Native dependencies also prevent packet construction and offline processing from being a reliably portable base.

v0.2 needs arbitrary stacking, reflective editing, compile-time Rust protocol extensions, exact byte preservation, and portable offline use. The implementation will eventually be split into component crates, but forcing downstream applications to change imports during that extraction would create avoidable churn.

## Decision

Create a runtime-neutral packet kernel with no OS access, async runtime, pcap dependency, or unsafe code. Its primary contracts are:

- `Packet` owns exactly one ordered sequence of object-safe `Layer` values.
- Layers provide a stable protocol identifier, reflective schema and fields, cloning, and downcasting.
- Raw, padding, truncated, unknown, and intentionally malformed bytes have explicit representations.
- Builders and dissectors report exact bytes, structured packets, byte layouts, and diagnostics.
- Parsers and builders take explicit limits and checked lengths.

Protocol behavior is composed through an explicit `RegistryBuilder` that produces an immutable `ProtocolRegistry`. The registry owns codecs, link-type roots, discriminator bindings, automatic-field bindings, and response matchers. Registration priority is deterministic and conflicts fail construction. There is no global mutable registry and no runtime native plugin loader.

Develop these boundaries as modules first. After the first alpha, extract synchronized component crates behind unchanged root reexports:

```text
packetcraftr-core       packet model, registry, encoding, dissection
packetcraftr-protocols  built-in typed protocols and matchers
packetcraftr-io         captures, routes, neighbors, platform adapters
packetcraftr-session    exchange, flows, fragmentation, reassembly
packetcraftr-tools      templates, DNS, scans, traceroute, fuzzing
packetcraftr            stable façade, high-level Client, CLI
```

Applications import normal APIs from `packetcraftr`. Component crates are implementation boundaries, not a requirement for ordinary users.

The 2026-07-11 beta extraction physically separated `packetcraftr-core`,
`packetcraftr-protocols`, `packetcraftr-io`, and `packetcraftr-session` behind
those unchanged root paths. The reusable tool workflows, high-level client,
output contracts, and CLI remain façade-owned because they compose one another;
extracting them now would introduce a reverse dependency or duplicate the
policy layer. A later tools extraction is permitted only if it preserves the
acyclic graph and the same root imports. All packages are synchronized,
`publish = false`, and assembled together for GitHub Releases rather than a
public registry.

Public library failures use typed, non-exhaustive errors. `anyhow` is permitted only where the CLI composes independently typed operations.

## Consequences

- Packet construction, dissection, and offline capture can work without libpcap or Tokio.
- External protocol crates can participate without modifying a central protocol enum or match statement.
- Callers explicitly own a registry, which makes configuration reproducible and tests isolated.
- Registry creation has more setup than a global singleton; high-level constructors can provide a built-in default registry.
- Object-safe layers involve dynamic dispatch and allocation. This is accepted for an extensible laboratory framework; layouts and registry lookup remain benchmark targets.
- The module-to-crate extraction must preserve root paths and synchronized versions.
- Portable crates can use `#![forbid(unsafe_code)]`; platform-specific unsafe code is isolated and documented in adapter modules.

## Alternatives considered

### Retain a central protocol enum

Rejected because every external protocol would require a PacketcraftR source change and central match-arm growth.

### Use global registration

Rejected because process-global mutation makes behavior order-dependent, complicates tests, and cannot clearly report binding conflicts.

### Load native dynamic plugins

Rejected because ABI stability, unsafe loading, platform packaging, and trust policy are outside v0.2 scope. Compile-time Rust extension is sufficient.

### Extract all crates before exposing an API

Rejected because it delays validation of the public model. Root façade reexports allow boundaries to be proven as modules and extracted later without downstream import churn.
