# PacketcraftR Multi-Crate Architecture and Wasm Plugin System Plan

## Status

- Project baseline: `packetcraftr 0.4.0-beta.2`
- Migration policy: breaking internal and public API changes are allowed while the project is in beta.
- Compatibility policy: do not preserve obsolete architecture through forwarding modules, deprecated aliases, compatibility adapters, or duplicate execution paths.
- Implementation strategy: seven ordered, independently reviewable phases.
- Current phase: Phases 1 and 2 complete; Phase 3 not started.

Mark a phase complete only after its implementation, tests, documentation, and validation gates are complete. Add a short completion note beneath the phase describing important decisions and any deliberate deviations from this plan.

## Goals

The completed architecture must provide:

1. A maintainable multi-crate workspace with explicit dependency and security boundaries.
2. Strongly typed native protocol support without exposing Rust ABI details to plugins.
3. Cross-language third-party plugins based on the WebAssembly Component Model and versioned WIT worlds.
4. Protocol, matcher, analyzer, transform, capture-format, renderer, workflow, and policy-guard extension points.
5. A capability-based host in which plugins have no ambient authority.
6. Immutable, provenance-aware extension catalogs that can be activated and replaced transactionally.
7. Exact-digest package installation, capability grants, lockfiles, rollback, health tracking, and quarantine.
8. Strict resource accounting for memory, execution, guest resources, host calls, bytes, logs, and result sizes.
9. Host-controlled networking in which raw sockets, capture handles, routing, target authorization, and transmission remain outside guest control.
10. A clean Rust SDK and conformance harness for plugin authors.

## Non-goals

The first complete plugin-system release will not support:

- Rust dynamic libraries or in-process native third-party shared objects.
- Wasm implementations of operating-system interface, route, capture, raw socket, or transmission providers.
- Ambient WASI filesystem, socket, DNS, HTTP, environment, stdin, stdout, or stderr access.
- Runtime plugin-to-plugin service discovery or recursive plugin calls.
- Guest-controlled registration priorities.
- Automatic inheritance of grants across package digest changes.
- Native-async WIT as part of the version-1 ABI.
- A single universal plugin world.
- Process-isolated Wasm workers in the initial implementation. The ABI and effect model must remain compatible with adding worker mode later.

## Non-negotiable security and architecture rules

1. The host is the sole owner of privileged I/O.
2. Plugins receive bounded owned values or read-only host resources.
3. Plugins return declarations, values, patches, findings, render documents, or effect requests.
4. No Rust references, trait objects, `Any`, native handles, or host pointers cross the Wasm ABI.
5. WIT is the ABI source of truth. JSON is allowed for configuration and canonical output, but not as the primary packet-operation ABI.
6. All guest inputs and outputs have explicit count, depth, length, and aggregate byte limits.
7. Every guest result is validated independently of whether Wasm execution succeeded.
8. The base traffic policy can never be weakened by a plugin.
9. Guard plugins may only deny or reduce authority and budgets.
10. Guest code never executes while host network effects are being performed.
11. Host code never re-enters a guest while that guest call is active.
12. Every active operation pins an immutable catalog snapshot.
13. Package version labels are informational during execution; exact content digests are authoritative.
14. Requested capabilities are not grants.
15. Grants are bound to an exact package digest.
16. Built-in namespaces and bindings cannot be replaced implicitly.
17. Registration conflicts require deterministic host-side rejection or explicit administrator selection.
18. Wasmtime types must remain confined to the plugin runtime and plugin host boundaries.
19. No global live Wasmtime `Store` or shared mutable guest instance is permitted.
20. First-party workspace code must retain the repository’s unsafe-code policy.

## Target repository structure

The root remains the `packetcraftr` package and workspace root. Its library is a thin public façade and its binary is a thin launcher, preserving the `packetcraftr` binary name without making domain crates depend on the façade.

    Cargo.toml
    Cargo.lock
    plan.md
    src/
      lib.rs
      main.rs
    crates/
      packetcraftr-model/
      packetcraftr-capture/
      packetcraftr-packet/
      packetcraftr-protocols/
      packetcraftr-session/
      packetcraftr-net/
      packetcraftr-net-native/
      packetcraftr-policy/
      packetcraftr-client/
      packetcraftr-workflow/
      packetcraftr-workflow-client/
      packetcraftr-output/
      packetcraftr-plugin-wit/
      packetcraftr-plugin-package/
      packetcraftr-plugin-runtime/
      packetcraftr-plugin-host/
      packetcraftr-plugin-distribution/
      packetcraftr-cli/
    sdk/
      rust/
        packetcraftr-plugin-sdk/
      test/
        packetcraftr-plugin-test/
    examples/
      plugins/
    tests/
    benches/
    fuzz/
    docs/
    schemas/
    scripts/

## Crate responsibilities

### `packetcraftr-model`

Foundational, owned, platform-neutral models:

- Shared classified error vocabulary.
- `Frame`, `FrameError`, `LinkType`, and `Direction`.
- Stable protocol, field, package, component, extension, digest, and invocation identities.
- Common bounded identifiers and metadata.
- No Wasmtime, async runtime, native platform code, registry, or packet engine.

### `packetcraftr-capture`

Offline capture formats and bounded streaming:

- Classic PCAP.
- PCAPNG.
- Reader, writer, transcoding, limits, and format metadata.
- Re-export shared frame models where that preserves an intentional public domain API.
- No native live capture.

### `packetcraftr-packet`

Packet kernel and protocol-extension contracts:

- `Packet`, `Layer`, `DynamicLayer`, schemas, fields, layouts, diagnostics, documents, expressions, templates, building, and dissection.
- Immutable protocol catalogs.
- Native codec and matcher contracts.
- Protocol provider/session abstraction used by both native and Wasm implementations.
- No built-in protocol implementations.
- No Wasmtime.
- No native networking.

### `packetcraftr-protocols`

All first-party protocol implementations:

- Built-in typed layers.
- Native codecs.
- Matchers.
- Capture roots.
- Bindings.
- Built-in protocol support manifest.
- One crate initially; do not create one crate per protocol.

### `packetcraftr-session`

Bounded stateful packet processing:

- IP fragment reassembly.
- TCP reassembly.
- Session and flow limits.
- Timeout and memory accounting.

### `packetcraftr-net`

Platform-neutral networking contracts and planning:

- Interfaces.
- Routes.
- Neighbor-resolution contracts.
- Capture provider/session traits.
- Layer-2 and layer-3 transmission contracts.
- Evidence and statistics.
- No operating-system implementation modules.

### `packetcraftr-net-native`

Operating-system implementations:

- Linux, macOS, and Windows providers.
- Native interface enumeration.
- Route providers.
- Live capture.
- Layer-2 and layer-3 transmission.
- Native dependency feature wiring.
- The only normal domain crate allowed to contain platform FFI implementation details.

### `packetcraftr-policy`

The non-bypassable authorization boundary:

- Traffic policy.
- Target and hostname models.
- Target resolution authorization.
- Public/private address authorization.
- Permissive packet authorization.
- Packet, byte, duration, destination, and effect budgets.
- Budget reservation and accounting.
- Guard-result intersection.

### `packetcraftr-client`

Audited active-network orchestration:

- Packet materialization.
- Route selection.
- Send.
- Capture-ready exchange.
- Response matching.
- Cleanup.
- Evidence and statistics.
- Depends on policy rather than owning policy.

### `packetcraftr-workflow`

Pure workflow engines and execution contracts:

- Replay.
- Scan.
- Traceroute.
- DNS.
- Fuzz.
- Deterministic clocks and state machines.
- No concrete client adapters.

### `packetcraftr-workflow-client`

Adapters that execute workflow contracts through `packetcraftr-client`.

### `packetcraftr-output`

High-level render-neutral models:

- Versioned envelopes.
- Command output models.
- Canonical serialized representations.
- Redaction.
- Structured terminal document model.
- Mappings from packet, capture, client, workflow, and plugin results.

### `packetcraftr-plugin-wit`

Versioned WIT packages and worlds. It must not depend on Wasmtime.

### `packetcraftr-plugin-package`

Portable package representation:

- Bounded bundle parsing.
- Manifest validation.
- Component and package digest verification.
- Content-addressed storage models.
- Lockfile and grant-file models.
- Trust-policy inputs.
- No runtime engine and no privileged operations.

### `packetcraftr-plugin-runtime`

The only crate that directly owns Wasmtime integration:

- Engine configuration.
- Generated host bindings.
- Component compilation.
- Linker profiles.
- `InstancePre`.
- Store creation and destruction.
- Fuel, epoch, memory, table, instance, resource, host-call, byte, log, and result accounting.
- Trap and runtime error classification.

### `packetcraftr-plugin-host`

Domain integration and active snapshot management:

- WIT/domain conversion.
- Protocol provider adapters.
- Analyzer pipelines.
- Transactional transforms.
- Capture-format adapters.
- Renderer adapters.
- Workflow effect broker.
- Guard integration.
- Activation staging.
- Health and quarantine.
- Audit and observability.
- Immutable active plugin snapshots.

### `packetcraftr-plugin-distribution`

Optional distribution support:

- OCI pull and push by exact digest.
- Package metadata and attachment handling.
- No dependency from core packet or runtime crates.
- No network access during normal plugin execution.

### `packetcraftr-cli`

CLI arguments, commands, rendering integration, runtime composition, and plugin administration.

### Root `packetcraftr`

Intentional façade:

- Re-exports stable domain surfaces.
- Maps public Cargo features to member crates.
- Retains the `packetcraftr` executable through a thin launcher.
- Contains no domain implementation.

## Dependency direction

The intended dependency direction is:

    packetcraftr-model
      ├── packetcraftr-capture
      ├── packetcraftr-packet
      │     ├── packetcraftr-protocols
      │     └── packetcraftr-session
      ├── packetcraftr-net
      │     └── packetcraftr-net-native
      ├── packetcraftr-policy
      ├── packetcraftr-client
      ├── packetcraftr-workflow
      │     └── packetcraftr-workflow-client
      └── packetcraftr-output

    packetcraftr-plugin-wit
    packetcraftr-plugin-package
      └── packetcraftr-plugin-runtime

    packetcraftr-plugin-runtime
      + packetcraftr-packet
      + packetcraftr-policy
      + packetcraftr-client
      + packetcraftr-workflow
      + packetcraftr-capture
      + packetcraftr-output
      └── packetcraftr-plugin-host

    packetcraftr-plugin-package
      └── packetcraftr-plugin-distribution

    domain crates
      + packetcraftr-plugin-host
      + packetcraftr-net-native
      └── packetcraftr-cli

    packetcraftr-cli
      + public domain crates
      └── root packetcraftr façade and launcher

No domain crate may depend on the root façade or CLI crate.

## Protocol execution model

The packet crate must not expose Wasm concepts. It defines a runtime-neutral provider boundary:

- A `ProtocolProvider` creates a short-lived `ProtocolSession`.
- A catalog maps each protocol to a provider and provider-local protocol key.
- A `ProtocolCatalogOperation` lazily creates at most one session per provider.
- Native sessions call trusted Rust codecs and matchers.
- Wasm sessions own one Store and component instance for the packet operation.
- Building, decoding, reflective construction, and response matching execute through the operation rather than obtaining raw codec objects from the catalog.
- Codec contexts contain resolved facts, not the full catalog.
- Child and reverse discriminator resolution remain host-controlled.

This provides one Wasm instance per component per packet operation without sharing mutable guest state across operations.

## Schema and dynamic-layer model

- `ProtocolId` is a stable namespaced identifier.
- Every schema has a deterministic schema version or hash.
- Every field has an explicit stable `FieldId`.
- Field names and aliases remain human-facing lookup keys.
- Schemas own their strings, aliases, field arrays, and constraints.
- Built-in schemas may live in `OnceLock` values but are not restricted to compile-time slices.
- `DynamicLayer` stores an `Arc<LayerSchema>` and host-validated field values indexed by schema slot.
- Native typed layers retain typed access.
- Wasm-defined layers remain schema-typed and reflectively accessible.
- The internal Rust `FieldValue` may remain recursive.
- The WIT representation must use a bounded, non-recursive flat value arena.

## Catalog and conflict model

Every registration records provenance:

- Built-in.
- Trusted native module.
- Wasm package, component, extension, and exact digest.

Catalog rules:

- `packetcraftr.*` is reserved for first-party identifiers.
- Third-party extension identifiers must be under their package namespace.
- Protocol aliases are unique after normalization.
- Capture roots are unique unless an explicit host selection chooses a provider.
- An exact parent/discriminator decode binding has one selected child.
- Reverse encoding has exactly one canonical discriminator for a selected parent/child pair.
- Additional aliases may be decode-only.
- Numeric plugin-controlled priorities do not exist.
- Built-ins win by default.
- Any replacement of a built-in requires explicit administrator selection and an appropriate grant.
- Catalog construction is deterministic and produces a content hash.
- Active catalogs are immutable.

## Identity model

Keep these identities distinct:

    Package
      └── Component
            └── Extension
                  └── Runtime invocation or session

Every diagnostic, metric, audit event, error, health record, and registration should be attributable to:

- Package ID.
- Package version.
- Package digest.
- Component ID.
- Component digest.
- WIT world and version.
- Extension ID.
- Activation generation.
- Operation or session ID.

## WIT worlds

All version-1 worlds are synchronous and independently versioned.

### `protocol-plugin@1`

- Metadata and descriptors.
- Schema registration.
- Reflective construction.
- Encode.
- Decode.
- Response matching.
- Pure by default.

### `analyzer-plugin@1`

- Stateless or bounded-session analysis.
- Frame, packet, and flow inputs.
- Structured findings.
- No active network effects.

### `transform-plugin@1`

- Transactional packet patch plans.
- Deterministic seeded mutation.
- No mutable packet resource.

### `capture-format-plugin@1`

- Pull-based frame reading.
- Push-based frame writing.
- Only user-selected source and sink resources.
- Transactional output commit.

### `renderer-plugin@1`

- Canonical redacted input.
- Structured terminal document output.
- Bounded file-rendering output.
- No arbitrary terminal escape authority.

### `workflow-plugin@1`

- Host-driven event/effect state machine.
- No raw network imports.
- One bounded workflow session per Store.
- Optional bounded checkpoint and restore.

### `guard-plugin@1`

- Deny or restrict effect batches.
- Cannot increase authority or budgets.
- Trap, timeout, invalid output, or unavailable mandatory guard fails closed.

## ABI value model

The WIT ABI uses a flat arena:

    ValueTree
      root: u32
      nodes: list<ValueNode>

    ValueNode
      Bool
      Unsigned
      Signed
      Text
      InlineBytes
      Ipv4
      Ipv6
      Mac
      List(list<u32>)

The host validates:

- Root and child indices.
- Reachability.
- Cycle absence.
- Maximum depth.
- Maximum node count.
- Maximum children per list.
- Maximum total text bytes.
- Maximum total inline bytes.
- Schema compatibility.
- Duplicate fields.
- Tree semantics rather than amplification through shared subgraphs.

Large packet and file bytes use immutable host resources with bounded reads instead of repeated full copies.

## Runtime model

- One configured Wasmtime engine per runtime configuration.
- Compiled components and `InstancePre` values may be cached by exact component digest.
- A Store is never global.
- Stores are scoped to semantic operations or sessions.
- Separate Stores provide concurrency.
- No Store is concurrently shared.
- No ambient WASI linker is installed.
- Runtime profiles expose only their required host imports.
- All blocking or active work occurs after the guest call returns.
- Fuel is the deterministic execution budget.
- Epoch interruption is the wall-time backstop.
- Host imports enforce their own cancellation and accounting.
- Publisher-supplied serialized native Wasmtime artifacts are never trusted.
- Portable components are compiled by PacketcraftR.

## Capability model

Effective authority is the intersection of:

    world capability ceiling
    ∩ package capability request
    ∩ administrator grant for the exact digest
    ∩ current operation policy

Capability categories include:

- Structured log.
- Deterministic seed.
- Host-managed state.
- Selected source read.
- Selected sink write.
- Resolve target effect.
- Build packet effect.
- Send effect.
- Exchange effect.
- Analyzer invocation.
- Transform invocation.
- Output emission.

Raw sockets, native capture handles, arbitrary paths, environment variables, and unrestricted network clients are never capabilities.

## Package model

A `.pcr-plugin` package contains:

    plugin.toml
    components/*.wasm
    schemas/*
    licenses/*
    sbom.spdx.json
    provenance.intoto.json
    signatures/*

The manifest declares:

- Package identity and version.
- Host compatibility range.
- Components and exact component digests.
- Exact WIT world.
- Declared extension IDs.
- Requested capabilities.
- Configuration schema.
- Optional state schema version.
- Optional SDK and build metadata.

The package parser must reject:

- Path traversal.
- Absolute paths.
- Duplicate entries.
- Symlinks.
- Undeclared executable components.
- Digest mismatches.
- Excessive archive size.
- Excessive decompressed size.
- Excessive entry count.
- Compression bombs.
- Unsupported manifest versions.
- World or extension declarations that do not match component descriptors.

## Lifecycle model

    Discovered
      -> Parsed
      -> Verified
      -> Compiled
      -> Described
      -> Configured
      -> Self-tested
      -> Staged
      -> Active
      -> Draining
      -> Removed or Quarantined

Activation is transactional:

1. Parse and bound the package.
2. Verify content digests and trust policy.
3. Resolve exact grants.
4. Type-check supported WIT worlds.
5. Compile components.
6. Instantiate under activation limits.
7. Validate metadata, configuration, descriptors, and self-tests.
8. Validate schemas and registrations.
9. Resolve conflicts.
10. Run any state migration before publication.
11. Build a complete new active snapshot.
12. Atomically publish it.

An operation keeps its original snapshot until completion. Stateful sessions remain pinned to their original component digest unless explicit compatible checkpoint/restore succeeds.

## Failure model

Keep these domains separate:

- Plugin domain error.
- Runtime failure.
- ABI or contract violation.
- Host policy denial.
- Host I/O failure.

Contract violations include malformed descriptors, invalid schemas, invalid field values, out-of-range layouts, undeclared registrations, invalid patch plans, excessive output, invalid effects, and leaked guest resources.

Repeated traps, deadlines, resource exhaustion, or contract violations contribute to a circuit breaker for the exact component digest. Quarantine blocks new invocations without deleting evidence or silently trusting a replacement version.

## Ordered implementation phases

### [x] Phase 1 — Multi-crate workspace and dependency boundaries

Deliver:

- Root workspace plus thin façade and binary launcher.
- Domain crates through `packetcraftr-cli`.
- Frame and common error models extracted into `packetcraftr-model`.
- Native platform implementations isolated in `packetcraftr-net-native`.
- Policy extracted from client.
- Client workflow adapters moved to `packetcraftr-workflow-client`.
- Existing behavior, CLI output, schemas, fixtures, and public examples preserved where compatible with the target architecture.
- CI, scripts, fuzz package, tests, benches, docs, and repository guidelines updated for the workspace.

Acceptance:

- No domain implementation remains in root `src/`.
- No member crate depends on root `packetcraftr`.
- No dependency cycle.
- Portable, default, and all-feature test profiles pass.
- Existing golden and schema tests pass.

Completion notes:

The workspace root keeps the `packetcraftr` package, the `packetcraftr` binary
name, Rust 2024, the 1.96 MSRV, AGPL-3.0-only, repository metadata, the
`unsafe_code = "deny"` policy, and `overflow-checks = true` in the release
profile. Package metadata, dependency versions, and lints are now declared once
in `[workspace.package]`, `[workspace.dependencies]`, and `[workspace.lints]`;
members declare only what is specific to them. Root `src/lib.rs` is a façade of
re-exports and small explicit modules, and `src/main.rs` only calls
`packetcraftr_cli::run_entrypoint`.

Final crate graph (arrows point at dependencies):

    packetcraftr-model      (no first-party dependencies)
    packetcraftr-capture    -> model
    packetcraftr-packet     -> model
    packetcraftr-protocols  -> model, packet
    packetcraftr-session    (no first-party dependencies)
    packetcraftr-net        -> model, packet          [dev: protocols]
    packetcraftr-net-native -> model, net
    packetcraftr-policy     -> model, packet
    packetcraftr-client     -> model, packet, policy, protocols, net
    packetcraftr-workflow   -> model, capture, packet, protocols, policy, net
    packetcraftr-workflow-client
                            -> model, capture, packet, protocols, policy, net,
                               net-native, client, workflow
    packetcraftr-output     -> model, capture, packet, protocols, net, client,
                               workflow
    packetcraftr-cli        -> every public domain crate above
    packetcraftr (root)     -> every domain crate; cli behind the `cli` feature

Important decisions:

- `Frame`, `FrameError`, `LinkType`, `Direction`, and `ProtocolId` moved to
  `packetcraftr-model`. Frame construction and validation now return
  `FrameError`; `capture::Error` gained a transparent `Frame` variant that
  preserves the previous messages and classification exactly.
- `packetcraftr-net` keeps only contracts. Every `System*` provider moved to
  `packetcraftr-net-native`, which stays the sole holder of target-specific
  dependencies, `platform/` FFI, and `#![allow(unsafe_code)]` files. The
  unsafe-code policy is unchanged.
- Operation counters (`Stats`) moved to `packetcraftr-net`, so client and
  workflow both re-export one definition instead of workflow importing client.
- `push_diagnostic_once` moved to `packetcraftr-packet::diagnostic`, removing
  the last client-to-workflow dependency.
- Policy-only authorizers (`workflow::PolicyAuthorizer`, `fuzz::PolicyAuthorizer`,
  `replay::SystemAuthorizer`) deliberately stay in `packetcraftr-workflow`: after
  the policy extraction they carry no client dependency, and keeping them beside
  the engines they gate preserves the engine unit tests without a dev-dependency
  cycle. `packetcraftr-workflow-client` holds exactly the adapters that need a
  live `Client` or a native provider.
- `FieldKind`, `FieldValue`, and `replay::Timing` dropped `#[non_exhaustive]`.
  They are closed vocabularies that codecs, mutators, renderers, and output
  mappings translate exhaustively; across a crate boundary the attribute would
  have forced silent lossy fallbacks instead of a compile error.
- `Layer::declared_layout_fields` and `BuiltinProtocol::{has_exact_round_trip,
  from_name_or_alias}` are no longer `#[cfg(test)]`, because the built-in support
  manifest that asserts against them now lives in a different crate.

Intentional public API breaks:

- `packetcraftr::client::policy` and `packetcraftr::client::target` are now
  `packetcraftr::policy` and `packetcraftr::policy::target`.
- `packetcraftr::capture::Error` no longer has `CapturedLengthTooLarge`,
  `CapturedLengthMismatch`, or `OriginalLengthTooSmall`; they are
  `Error::Frame(FrameError::…)` with unchanged `Display` output.
- `packetcraftr::net::route::SystemError` is `packetcraftr_net_native`'s
  `NativeRouteError`; the façade path is unchanged.
- `packetcraftr::workflow::Stats` and `packetcraftr::client::Stats` are the same
  `packetcraftr_net::Stats`, and `Stats::checked_add` is public.
- `packetcraftr::workflow::scan::classify_response`,
  `traceroute::classify_response`, and the new `dns::correlates` are the
  supported seams for out-of-crate executors, alongside the now-public
  `Client::exchange_for_workflow`.

### [x] Phase 2 — Extensible packet core and immutable protocol catalog

Deliver:

- Owned schemas and explicit stable field IDs.
- Field constraints and deterministic schema identity.
- `DynamicLayer`.
- Runtime-neutral protocol provider/session abstraction.
- Native codec and matcher adapter.
- Catalog operation with one lazy session per provider.
- Codec contexts no longer receive a registry.
- Immutable, provenance-aware protocol catalog.
- Deterministic conflict handling without numeric priorities.
- Built-in protocols migrated to the new contracts.

Acceptance:

- Built-in packet bytes, decode behavior, layouts, diagnostics, and match results remain equivalent.
- Typed native layer access still works.
- Dynamic-layer validation is exhaustive.
- Catalog construction is deterministic.
- Explicit tests prove built-ins cannot be shadowed implicitly.
- The packet crate has no Wasmtime dependency.

Completion notes:

- Completed 2026-07-26. Schemas are immutable owned values with explicit stable
  field IDs, constraints, and canonical hashes; host-owned `DynamicLayer`
  values occupy validated schema slots.
- Each `ProtocolCatalogOperation` pins one immutable snapshot and lazily creates
  at most one short-lived mutable session per provider. Sessions are never
  shared across operations; the trusted native adapter follows this lifecycle,
  while the packet crate remains independent of any Wasm runtime.
- Decode bindings select exactly one child for a parent/discriminator pair.
  Canonical bidirectional bindings alone create reverse encode mappings;
  decode-only aliases never do, and fallbacks are explicit. Built-ins win by
  default, protected identities require an exact-origin host selection to be
  replaced, conflicts contain no numeric priority, and equivalent canonical
  registration sets produce the same provenance-aware catalog hash regardless
  of insertion order.

### [ ] Phase 3 — WIT, package, runtime, SDK, and common host foundation

Deliver:

- Versioned WIT packages for every version-1 world.
- Non-recursive value arena and host-resource contracts.
- Bounded package parser and verified-package typestate.
- Wasmtime runtime profiles with no ambient WASI.
- Fuel, epoch, memory, table, instance, resource, host-call, byte, log, and result limits.
- Runtime error classification.
- Common metadata, configuration, and self-test lifecycle.
- Rust guest SDK.
- Host conformance-test crate.
- Optional root `wasm-plugins` feature.

Acceptance:

- Metadata-only components can be verified, compiled, instantiated, configured, self-tested, and dropped.
- Runtime tests require no external network.
- Default workspace tests do not require `cargo-component`.
- Malicious fixture components prove limits and forbidden imports.
- Wasmtime types do not leak into domain crates.

Completion notes:

- Not completed.

### [ ] Phase 4 — Wasm protocol and analyzer plugins

Deliver:

- Protocol descriptor conversion and validation.
- `WasmProtocolProvider` and per-operation session.
- Blob and packet-view resources.
- Construct, encode, decode, and response-match adapters.
- Strict validation of every guest result.
- Stateless and bounded-session analyzers.
- Structured finding model and analyzer pipeline.
- Example protocol and analyzer plugins.
- Differential and adversarial tests.

Acceptance:

- A Wasm protocol can construct, build, decode, and match packets through the normal packet engine.
- Multiple protocols from one component reuse one Store within a packet operation.
- Stores are not reused across packet operations.
- Invalid guest offsets, layouts, fields, registrations, or values are rejected.
- Analyzer failure policy is explicit and tested.
- No active network capability is exposed.

Completion notes:

- Not completed.

### [ ] Phase 5 — Transform, capture-format, and renderer plugins

Deliver:

- Transactional patch-plan model and transform adapter.
- Seeded deterministic mutators.
- Capture source, sink, reader, and writer resources.
- Transactional capture export.
- Structured renderer document model.
- Host escaping and redaction boundaries.
- Extension command descriptors for later CLI invocation.
- Examples and adversarial tests.

Acceptance:

- Failed transforms leave packets unchanged.
- Patch selectors cannot apply to stale or unexpected packet revisions.
- Capture plugins cannot access arbitrary files.
- Partial output is never committed after writer failure.
- Renderer plugins cannot inject terminal control sequences.
- Canonical machine output is redacted before guest access.

Completion notes:

- Not completed.

### [ ] Phase 6 — Workflow effects and restrictive policy guards

Deliver:

- Synchronous workflow event/effect ABI.
- Workflow session lifecycle.
- Host effect broker.
- Target resolution, build, send, exchange, sleep, analyze, transform, and output effects.
- Conservative batch cost calculation and budget reservation.
- Non-bypassable policy integration.
- Restrictive guard pipeline.
- Cancellation, cleanup, idempotency, sequencing, audit records, and optional checkpoints.
- Deterministic tests using controlled providers.

Acceptance:

- Guest execution never overlaps host network effects.
- Target authorization precedes DNS.
- Every resolved address is authorized before route planning.
- Capture readiness precedes send through the existing client exchange path.
- Guards cannot expand authority or budgets.
- Mandatory guard failure closes the operation.
- Cancellation drops the session and cleans up host effects.
- No raw capture or socket import exists.

Completion notes:

- Not completed.

### [ ] Phase 7 — Trust, installation, activation, distribution, CLI, and production hardening

Deliver:

- Content-addressed package store.
- Exact-digest lockfile.
- Exact-digest capability grants.
- Trusted publisher keys and detached package signature verification using established cryptographic libraries.
- Explicit unsigned-development mode.
- Optional OCI distribution crate.
- Host-managed namespaced plugin state with quotas and transactional migration.
- Transactional active snapshot publication.
- Hot reload, drain, update, rollback, disable, and removal.
- Health tracking, circuit breaker, and quarantine.
- Structured tracing, metrics, audit output, and diagnostics.
- Complete plugin administration and invocation CLI.
- Output schemas, docs, examples, security guidance, CI, and conformance coverage.

Acceptance:

- Installing a package does not grant capabilities.
- Updating to a different digest does not inherit grants silently.
- Failed activation leaves the previous snapshot active.
- In-flight operations remain pinned to the previous snapshot.
- Rollback selects an exact verified digest.
- Quarantine blocks new invocations for the failing digest.
- CLI machine formats have stable schemas and tests.
- Full workspace CI, documentation, dependency, fuzz-smoke, and coverage gates pass.

Completion notes:

- Not completed.

## Required validation matrix

Each phase must run the relevant subset, and Phase 7 must run the complete set:

- `cargo fmt --all -- --check`
- `scripts/check-source-conventions`
- `cargo test --locked --workspace --no-default-features`
- `cargo test --locked --workspace`
- `cargo test --locked --workspace --all-features`
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
- `RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps`
- `cargo deny check`
- `cargo deny --manifest-path fuzz/Cargo.toml check`
- `cargo llvm-cov --locked --workspace --all-features --lcov --output-path lcov.info --fail-under-lines 75`
- Every committed fuzz target must compile and pass its smoke test.
- Native privileged tests remain opt-in through `scripts/test-native-e2e`.

If the local environment lacks a documented native prerequisite, run every portable gate, run compile checks for the affected feature where possible, and report the exact unavailable prerequisite. Do not silently skip failures.

## Definition of done

The project is complete when:

- All seven phases are checked off.
- Root implementation code has been replaced by the intended façade and launcher.
- All extension worlds have stable version-1 WIT definitions.
- Third-party components can be packaged, verified, installed, granted, activated, invoked, updated, rolled back, and quarantined.
- Protocol plugins use the normal packet builder and dissector.
- Workflow plugins use only host-mediated effects.
- The host remains authoritative for policy, budgets, I/O, validation, and audit.
- No compatibility scaffolding preserves the old monolithic architecture.
- No unfinished stubs, placeholder implementations, ignored security checks, or undocumented architectural exceptions remain.

## Deferred follow-up

After production experience establishes a need, consider:

- Optional process-isolated plugin workers.
- Runtime-only data-plane deployments using host-produced precompiled artifacts.
- Native-async version-2 WIT worlds.
- Batch protocol decode APIs supported by profiling evidence.
- Additional guest-language SDKs.
- Administratively composed shared component libraries.
- Separately sandboxed native provider workers.
