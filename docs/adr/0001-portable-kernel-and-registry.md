# ADR 0001: Portable kernel, immutable registry, and stable façade

- Status: Accepted
- Date: 2026-07-09
- Amended: 2026-07-11 (physical component extraction)

## Context

The original implementation coupled a fixed protocol sequence, operating-system I/O, listener state, routing settings, and CLI orchestration. Adding a protocol required central match arms, and applications could not build or inspect arbitrary repeated layers without using private types. Native dependencies also prevented packet construction and offline processing from being a reliably portable base.

PacketcraftR needs arbitrary stacking, reflective editing, compile-time Rust protocol extensions, exact byte preservation, and portable offline use. Component crates must preserve the root façade so internal ownership does not force downstream import changes.

## Decision

Create a runtime-neutral packet kernel with no OS access, async runtime, pcap dependency, or unsafe code. Its primary contracts are:

- `Packet` owns exactly one ordered sequence of object-safe `Layer` values.
- Layers provide a stable protocol identifier, reflective schema and fields, cloning, and downcasting.
- Raw, padding, truncated, unknown, and intentionally malformed bytes have explicit representations.
- Builders and dissectors report exact bytes, structured packets, byte layouts, and diagnostics.
- Parsers and builders take explicit limits and checked lengths.

Protocol behavior is composed through an explicit `RegistryBuilder` that produces an immutable `ProtocolRegistry`. The registry owns codecs, link-type roots, discriminator bindings, automatic-field bindings, and response matchers. Registration priority is deterministic and conflicts fail construction. There is no global mutable registry and no runtime native plugin loader.

Represent these boundaries with synchronized component crates behind unchanged root reexports:

```text
packetcraftr-core       packet model, registry, encoding, dissection
packetcraftr-protocols  built-in typed protocols and matchers
packetcraftr-io         captures, routes, neighbors, platform adapters
packetcraftr-session    exchange, flows, fragmentation, reassembly
packetcraftr            façade, high-level client, tools, output, and CLI
```

Applications import normal APIs from `packetcraftr`. Component crates are implementation boundaries, not a requirement for ordinary users.

`packetcraftr-core`, `packetcraftr-protocols`, `packetcraftr-io`, and
`packetcraftr-session` sit behind those root paths. Reusable tool workflows,
the high-level client, output contracts, and CLI remain façade-owned because
they compose one another; extracting them would introduce a reverse dependency
or duplicate the policy layer. A later extraction is permitted only if it
preserves the acyclic graph and the same root imports. All packages are
synchronized and have `publish = false`.

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

Rejected because ABI stability, unsafe loading, platform packaging, and trust policy are outside the project scope. Compile-time Rust extension is sufficient.

### Extract all crates before exposing an API

Rejected because it delays validation of the public model. Root façade reexports allow boundaries to be proven as modules and extracted later without downstream import churn.
