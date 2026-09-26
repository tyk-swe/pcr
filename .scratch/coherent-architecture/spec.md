# Coherent architecture: one vocabulary, correct ownership

Status: ready-for-agent

## Problem Statement

A maintainer or agent moving around the workspace keeps finding that one
concept has several names, that one name means several things, and that
logic sits in a crate that doesn't own its domain. A read-only audit of all
four crates found the following.

**Across the workspace**
- Module files mix 80 `mod.rs` files with 36 `foo.rs` + `foo/` pairs, sometimes
  inside one directory.
- Error types follow no convention. Names mix `Error` and `XError`.
  `codec::Error` holds only strings, so protocol errors are flattened through
  97 `invalid(name, String)` calls. Sources are dropped, stringified, or
  repeated in messages. Libraries emit `Kind::Cli` classifications.
- Public surfaces mix nested `pub mod` paths with flat re-exports. Sibling
  crates depend on `#[doc(hidden)]` items and macros. Aliases give one type two
  names.
- "Budget" and "Limit" are used interchangeably. There are 15+ limits types;
  only 8 validate, and DHCP silently clamps the caller's limits.

**packetcraftr-core**
- Capture formats live under `analysis::pcap` but import nothing from
  analysis, and live replay and the CLI use them. Link-type knowledge exists
  in four places.
- Module dependencies have cycles across layers (`packet`⇄`protocol`,
  `registry`→`matcher`→`packet`→`protocol`→`registry`). The generic decode and
  build engines hard-code built-in protocols.
- Live-policy vocabulary sits in the lowest crate: live opt-in,
  transmission-denial reasons, probe/attempt coordinates, and deadline helpers
  that no core code calls.
- Protocols have no common file shape, wire-API error type, or grouping.
  `transform` hand-parses bytes that codecs already understand.
- Built-in protocols are identified by schema strings and inspected both by
  string field names and by downcasts. Field paths are re-parsed on every call.
- `Layer` hand-rolls `clone_box`/`as_any`/`as_any_mut`.

**packetcraftr-netio**
- It holds non-native logic: route planning, active neighbor resolution, and
  capture fan-in.
- It hand-writes Ethernet, VLAN, ARP, and NDP bytes.
- `platform/` mixes OS, library, capability, and platform-neutral code.
- Provider contracts differ in naming, error model, `Send + Sync` bounds, and
  deadline handling. Transmit has three traits and two compositions. Route
  lookup hard-codes backend timeouts.
- There are three threading and admission models, and several poll-with-sleep
  loops.

**packetcraftr**
- There are two main entry models plus variants. `send` and `exchange` are
  `Client` methods that use `Policy` directly. `dns`, `scan`, `traceroute`, and
  `fuzz` are free functions that take an authorizer and an executor wrapping a
  `Client`, so policy and registry are supplied twice.
- File and type names mean different things per workflow (`request`, `plan`,
  `execution`, `Execution`, `Transport`, `Completion`).
- `probe` is both the scan/traceroute kernel and the crate-wide executor and
  sink seam.
- Each workflow has its own event-callback bound, error type, and return shape.
- Optional capabilities are default trait methods that fail at runtime.
- Policy returns two error types that wrap each other.

**packetcraftr-cli**
- Per-command facts are spread across at least seven parallel tables, and
  there are two command enums.
- Provider composition happens in five places.
- `rendering.rs` sometimes formats and sometimes drives a command, and six
  newer commands follow a second style that skips terminal sanitization.
- About 40 output fields serialize library types directly, using five
  different conversion styles.
- Domain logic lives in the CLI: rewrite rules and documents, replay routing,
  selectors, and recipe sniffing.
- The lib exposes only `output`, which forces duplicated test support.

## Solution

Apply one vocabulary, recorded in `CONTEXT.md`, and one ownership rule per
crate. The decisions below were settled in a design session. The four
boundary decisions have ADRs (`docs/adr/0001`–`0004`).

- **core** holds runtime-neutral packet knowledge, including matchers and
  packet semantics that only live workflows use today (ADR 0002). Its modules
  form acyclic layers: model → protocols → engines → analysis/fuzz. Capture
  formats become `core::capture_file`. Core owns fuzz campaigns.
- **netio** holds only provider contracts, system providers, and native
  backends (ADR 0001). Every capability is `<capability>::Provider` plus
  `<capability>::SystemProvider`, with one deadline and cancellation
  convention and one worker pool for blocking native calls.
- **packetcraftr** runs every workflow through the `Client`. Each workflow
  uses the fixed roles request → plan → engine → executor → evidence → report,
  plus error. Route planning and neighbor resolution move here.
- **CLI** owns arguments, composition (only in `system/`), rendering, and every
  published output field (ADR 0003).

## Constraints

- **Frozen:** the machine contracts (`packetcraftr.output/v6`,
  `packetcraftr.packet/v2`, `rewrite` and `udp-profiles` document formats), CLI
  flags, error classification codes, and exit codes.
- **Allowed:** breaking Rust API changes, recorded under `[Unreleased]` and in
  `docs/migration-unreleased.md`. Deprecated aliases are not added, because
  they would be equivalent public paths.
- Human-readable error text may change.
- Behavior fixes found along the way land in the same slice and get their own
  changelog entry.
- The four crates stay, and their dependency direction is
  `core < netio < packetcraftr < cli`.
- Each issue is independently mergeable and passes
  `cargo fmt --all -- --check`, `cargo clippy --locked --workspace
  --all-targets --all-features -- -D warnings`, and `cargo test --locked
  --workspace --all-features`.

## User Stories

1. As a maintainer opening any workflow module, I want the same role files
   with the same meanings, so that I know where request validation, planning,
   execution, evidence, and reporting live without reading the code.
2. As a maintainer, I want one public name to mean one thing across the
   workspace, so that `Execution`, `Exchange`, `Budget`, or `Stats` never needs
   disambiguating.
3. As a library consumer, I want to run any workflow as a `Client` method with
   injected providers, so that I supply policy and registry once.
4. As a library consumer, I want every workflow to publish events through one
   sink contract and return its report, so that one integration pattern covers
   all of them.
5. As a security reviewer, I want one admission path for every workflow, so
   that authorization before active discovery is enforced in one place.
6. As a security reviewer, I want netio to contain only contracts and native
   bindings, so that the unsafe crate stays small and every decision that
   leads to traffic is visible to live policy.
7. As a netio maintainer adding a backend, I want `platform/` organized as
   capability → backend with only native code in it, so that I know where the
   binding goes and what dispatch selects.
8. As a library consumer injecting providers, I want every capability to have
   the same contract shape and deadline convention, so that fakes look alike
   and no call can block past my deadline.
9. As an operator, I want every native call that can block to honor the
   caller's deadline and run under one bounded worker pool, so that resource
   use is finite and predictable.
10. As a core maintainer, I want core modules to form acyclic layers and the
    engines to read protocol properties from the registry, so that a custom
    protocol behaves like a built-in one.
11. As a consumer of capture files, I want one `capture_file` module that
    owns pcap/pcapng and link types, so that I don't import analysis to read a
    file.
12. As a protocol maintainer, I want every protocol to follow one file shape,
    live in its layer group, and return its own typed error, so that adding a
    protocol is a copy of an existing one.
13. As a maintainer debugging a failure, I want every error to keep its typed
    source and never repeat the source text, so that error chains are complete
    and readable.
14. As a maintainer, I want limits validated when set and budgets named as
    running allowances, so that a limit is never silently lowered.
15. As a maintainer, I want core's public API to be flat re-exports with no
    hidden items used across crates, so that every path I see is a supported
    one.
16. As a transform maintainer, I want faithful codecs used where possible and
    one shared header walker otherwise, so that byte-level edits have one
    implementation and a documented reason.
17. As a CLI maintainer adding a command, I want to declare its facts in one
    place and follow one directory shape, so that I can't forget dispatch,
    contract, preset, or resource wiring.
18. As a CLI maintainer, I want `system/` to be the only place providers are
    built, so that native composition is auditable.
19. As a consumer of machine output, I want output/v6 to be unaffected by
    library serde changes, so that the contract only changes when the CLI
    changes it.
20. As a CLI user, I want every command's human output to go through terminal
    sanitization and show no Debug formatting, so that captured bytes can't
    inject terminal escapes.
21. As a CLI maintainer, I want domain logic (rules, documents, selectors,
    routing) owned by core or packetcraftr, so that library consumers get the
    same behavior as the CLI.
22. As a test author, I want integration tests to reach the CLI's internals
    through its lib and one test support module, so that fixtures aren't
    duplicated.
23. As a maintainer, I want optional capabilities to be separate traits, so
    that a missing capability fails at compile time instead of at runtime.
24. As a downstream consumer, I want every breaking Rust change listed in the
    changelog and migration note, so that I can upgrade a pinned revision on
    purpose.

## Implementation Decisions

### Workspace conventions

- **Module files:** use self-named `foo.rs` + `foo/` everywhere. Enforce with
  `clippy::mod_module_files` in `[workspace.lints.clippy]`.
- **Facade rule:** crates expose domain modules as `pub mod`. Inside a module,
  submodules are private and items are re-exported flat (`tls::Tls`,
  `dns::Request`). Nested `pub mod` only for a real sub-domain; `scan::connect`
  stays one because it uses the TCP provider rather than exchanges. No aliases
  that give a type a second name. Nothing `#[doc(hidden)]` may be used by
  another crate: either it becomes real API or it moves to the crate that uses
  it.
- **Errors:**
  - Each owning module has one `Error`, used module-qualified with no `XError`
    suffix.
  - Sources are attached with `#[source]`/`#[from]`, are never repeated in the
    message, and are never turned into strings.
  - A crate uses one way of storing type-erased sources (for example `Arc` when
    the error must be `Clone`).
  - Every public error implements `Classified`.
  - `codec::Error` gains a real source (and drops `Eq`).
  - Classification kinds are neutral: `Kind::Cli` becomes `Kind::Usage`. The
    CLI maps each kind to its exit code, and codes such as `cli.capture_filter`
    keep their exact frozen strings.
- **Limits and budgets:** a limit is a configured ceiling, validated at
  construction and never silently clamped. A budget is the running allowance
  charged against a limit. Types are renamed to match. Every limits type gets
  `validate()`. DHCP's silent clamp becomes a validation error. No shared
  budget primitive is introduced, because the accounting models differ.
- **Names:**
  - `Stats` is the one word; netio `Statistics` and `connect::Statistics` are
    renamed (serde keeps the JSON field names).
  - The permissive-packet opt-in is `allow_permissive_live` everywhere.
  - Exchange means capture-armed only; the DNS-over-TCP socket round trip is a
    query.
  - Rate fields keep their unit-bearing names (`probes_per_second`,
    `cases_per_second`, `queries_per_second`, `rate`).
- **Tests:**
  - Direct schema assertions move from `*_contracts.rs` to
    `*_conformance.rs`. The shared parse helper's schema guard stays.
  - In-crate tests are inline `mod tests`, or `<module>/tests.rs` once large.
    No `*_tests.rs` or descriptively named test files.
  - Helpers live only in `test_support` modules.
  - Moved code keeps its tests beside it.

### packetcraftr-core

- **Scope (ADR 0002):**
  - Matchers and packet semantics stay in core.
  - These move to packetcraftr: `build::Options::requires_live_opt_in`,
    transmission-denial wording, `Coordinate::ProbeSequence`/`Attempt`, the
    live-only `Deadline` helpers (`remaining_before`, `into_boundary_error`,
    `for_wait`, `bounded_timeout`, `POLL_INTERVAL`), and
    `deadline_error_conversions!`.
  - Packet semantics errors describe the packet, not a policy denial.
- **`capture_file`:** `analysis::pcap` becomes top-level `capture_file`. It
  owns link types and the single link-type ↔ root-protocol mapping, which
  replaces the copies in `frame.rs`, `protocol/capture`, `fuzz/decode.rs`, and
  `transform/rewrite.rs`.
- **Layers:**
  - The order is model (`field`, `layer`, `layout`, `packet`, `frame`,
    `codec`, `registry`) → protocols (built-ins, semantics, matchers) →
    engines (`decode`, `build`, `transform`, `filter`, `expression`) →
    `analysis`/`fuzz`.
  - Cycles inside the model layer are acceptable; cycles across layers are
    removed.
  - Raw/Padding/Malformed are model layers in full: codecs move out of
    `protocol/raw.rs`.
  - Whether a link protocol allows trailing padding becomes a registered
    protocol property, replacing the engine's fixed list.
- **Protocols:**
  - Each protocol is `<proto>.rs` (model, `reflective_layer!`, codec) and
    grows into `<proto>/` with codec/reflection/model submodules only when
    large.
  - Wire APIs return the protocol's own `Error`.
  - Grouping by layer: `gre` → tunnel, `icmp` → network, IPv6 extension
    headers under `network/ipv6`.
  - TLS internals become private with flat re-exports. DNS name decoding keeps
    one public API.
  - Field visibility stays as it is per protocol.
- **Identity:**
  - `layer::Id` stays open for registry extensions.
  - Built-in identity comes from the layer's type, not schema-string matching.
    Built-in layers are always inspected by typed downcast, never by string
    field names.
  - Field paths are a parsed `FieldPath` type in every API; strings are parsed
    only at document and CLI edges.
- **`Layer`:** trait upcasting to `Any` replaces the hand-rolled
  `as_any`/`as_any_mut`. `clone_box` stays only if object-safe cloning still
  needs it.
- **Transforms (ADR 0004):** use codecs where the round trip is byte-faithful.
  Otherwise use one shared link/VLAN/IP header walker, which packetcraftr's
  neighbor code also uses for anything its codecs can't parse faithfully.
- **Fuzz:** core owns campaigns, cases, and offline outcomes, including
  offline runs with events.

### packetcraftr-netio

- **Scope (ADR 0001):**
  - `route::plan` and its intent helpers move to `packetcraftr::route`, and
    the route cache joins them from `exchange`.
  - `neighbor` (resolver, cache, wire, options, evidence, error) moves to
    `packetcraftr::neighbor`, where ARP/NDP are built and parsed with core
    codecs. The duplicate multicast-MAC helper disappears.
  - `capture::Group` stays as a composite capture session that implements
    `Session`, and single sessions and groups apply the same filter limit.
- **Contracts:**
  - Every capability is `<capability>::Provider` with a
    `<capability>::SystemProvider`, and every provider trait has
    `Send + Sync` supertraits. The capabilities are route, interface, capture,
    transmit, and tcp.
  - One `transmit::Provider` sends any frame. `transmit::SystemProvider`
    dispatches Layer 2 or Layer 3 to its backend, and returns a classified
    capability error when that layer isn't compiled in.
  - `ModeSender` and `PacketIo` are removed; the `Client` holds transmit and
    capture providers separately.
  - `transmit::Frame` is renamed so it no longer collides with
    `core::frame::Frame`.
- **Deadlines:** every call that can block takes the same deadline and
  cancellation input. Route lookup takes the caller's deadline, replacing the
  backends' hard-coded 2–3 second timeouts.
- **Threading:**
  - Every native call that can block past a deadline (capture, netlink,
    AF_ROUTE, IP Helper, TCP connect) runs on one admitted worker pool with the
    reaper. Sends stay on the caller's thread.
  - One named capacity constant replaces the three unrelated 16s.
  - Poll-with-sleep loops become channel or condvar waits wherever the backend
    offers a waitable handle. Where it doesn't, a comment says why the poll
    stays.
- **`platform/`:**
  - Holds only code that calls native APIs, organized as capability →
    backend.
  - Platform-neutral code moves to its capability module: route
    normalization, interface validation, the capture filter, live-capture
    queue and time, workers, the reaper, and TCP connect.
  - `dispatch` only selects backends; validation moves to its capability.
  - Interface enumeration gets its own error type instead of route's.
- **Errors:** one "unsupported" representation, no dropped sources (npcap,
  neighbor options), and no `cli.*` kinds, per the workspace convention.

### packetcraftr

- **Client entry model:**
  - The `Client` holds the policy, protocol registry, clock, runtime, and
    providers. Every workflow is `client.<workflow>(request, sink)`, and there
    is one admission path.
  - `Executor`, `Authorizer`, and the replay transmitter/authorizer become
    internal seams; tests inject fake providers.
  - `scripts/check-external-consumer.py` and the crate docs follow the new
    model.
- **Roles:** each workflow module has `request`, `plan`, `engine`,
  `executor`, `evidence`, `report`, and `error` with the meanings in
  `CONTEXT.md`. The `execution`, `model`, `classification`, `probe`, `run`,
  `runner`, and `transmitter` files dissolve into those roles. Extra files are
  only for workflow-specific domain concepts (DNS wire, scan profile, exchange
  correlation).
- **`probe` split:** a private root `execution` module holds the executor
  contract, evidence validation, the event sink, and the pacing context.
  `probe` keeps only the scan/traceroute kernel. Scan and traceroute each get
  their own `Error`.
- **Events:** every workflow publishes `Event` values through one sink bound
  that runs on the runtime, and returns its `Report`. `send`, `replay`, and
  `capture` converge; capture keeps `Control` only if early stop cannot be
  expressed otherwise.
- **Capabilities:** pipelined execution, DNS-over-TCP, and final-wire
  authorization become separate traits instead of default methods that fail.
- **Placement:** `packetcraftr::route` (route plan and route cache) and
  `packetcraftr::neighbor` (resolution, cache, ARP/NDP).
- **Policy:** policy has one `Error`, and `UnsupportedOperation` moves there.
- **Fuzz:** the live `fuzz::Request` wraps a core campaign request. Its
  `Report` reuses core's `Case` and adds live evidence by composition. No
  duplicate definitions remain.

### packetcraftr-cli

- **Lib and binary:** the lib holds the whole application and `main.rs` calls
  `packetcraftr_cli::main()`. Only `output` and the entry point are public.
  Clap enums move to arguments and convert with `From` into output types.
  There is one `test_support`.
- **Composition:** `system/` is the only place that constructs system
  providers and builds the `Client`. `commands/execution.rs`,
  `commands/preparation.rs`, and the copies in fuzz and replay go through it.
- **Commands:**
  - Each command implements one command trait that declares its kind,
    formats, publication duration, cancellation support, preset membership,
    and resource stages. Dispatch, the contract, presets, and resources read
    from it.
  - There is one command enum. `resources.rs` and `presets.rs` read typed
    arguments instead of argument-id strings.
- **Shape:**
  - Every command is `commands/<cmd>.rs` + `commands/<cmd>/{arguments,
    rendering}`. The command root drives execution. `rendering.rs` only
    formats text from the command's output type. `output/<cmd>` is named after
    the command.
  - Single-user `command_options` groups move into their command. Repeated
    fields (`max_duration_ms`, `timeout_ms`, `compression`) become shared
    groups with one validation.
  - The six second-style commands gain help text, sanitized output, and no
    Debug formatting.
- **Output (ADR 0003):**
  - Output types embed only versioned library documents
    (`packetcraftr.packet`). Everything else is a CLI-owned type with an
    identical JSON shape.
  - Conversions are `From`/`TryFrom` only, and commands never build output
    struct literals.
- **Domain logic down:**
  - These move to core: rewrite rule application, the `rewrite` and
    `udp-profiles` documents, recipe sniffing, `--payload-file` field
    injection, the TLS/expert/frame selectors, and the root-protocol →
    link-type mapping.
  - Replay interface routing (`SOURCE=IF`, `EXPR=>IF`) moves to
    `packetcraftr::replay`.
  - Capture file rotation stays in the CLI.
- **Exit codes:** cancellation uses the exit-code constant everywhere.

### Order

The phases land in this order:
1. Phase 0: mechanical workspace sweeps.
2. Phase 1: core.
3. Phase 2: netio.
4. Phase 3: packetcraftr.
5. Phase 4: CLI.

Within each crate, mechanical changes land first, then ownership moves, then
shape changes. Upper crates are refactored once, against the final lower APIs.
Every slice updates the call sites in upper crates so that the workspace keeps
building. `AGENTS.md`, `CONTRIBUTING.md`, and crate docs are updated in the
slice that makes them stale.

## Testing Decisions

- The existing public-behavior contract tests, conformance tests (especially
  output/v6 and packet/v2), matrix tests, and CLI process tests are the
  regression net. An assertion changes only when the slice sanctions a
  behavior fix, and the changelog names it.
- Pure moves and renames change only import paths in tests.
- New seams get tests at their own interface. Examples:
  - the transmit `SystemProvider` returns the capability error for a layer
    that isn't built;
  - route lookup honors the caller's deadline with a fake backend;
  - the worker pool refuses work past capacity;
  - one `Client` method per workflow runs against the test-support fake
    providers.
- The ARP/NDP rewrite over core codecs is proven by byte-for-byte comparison
  with the current hand-written frames before the old code is deleted. It
  also has parse tests on captured replies, including VLAN-tagged ones and
  replies with IPv6 extension headers.
- Mirrored output types are proven by the v6 conformance suite serializing
  real payloads. No hand-written JSON fixtures replace it.
- Tests that only exercised deleted plumbing are removed once interface tests
  cover the behavior. No duplicate verification.
- `native_isolated.rs` runs on the Linux namespace launcher for the netio
  threading and deadline slices.

## Out of Scope

- New crates or changes to the dependency direction.
- Changes to machine-contract families, CLI flags, error codes, or exit codes.
- A shared budget primitive.
- Changes to rate field names.
