# Untangle decision log

This log records one whole-codebase untangle pass. It lists every place the
code answered the question "should these pieces change together" wrong, the
root fix chosen for each group, and what happened. It also records the
findings that were checked and deliberately left alone, so a later pass does
not re-derive them from scratch.

Statuses. **done** means fixed in this pass. **kept** means checked and
deliberately left, with the reason. **deferred** means real, worth fixing,
and too large or too risky to land safely inside this pass, with the shape
of the fix recorded.

Baseline before any edit. `cargo test --locked --workspace` passed, and
`scripts/check_layers.py`, `scripts/check_coupling.py`, and
`scripts/check_file_lengths.py` passed. The counted coupling patterns sit at
their ceilings. Everything below is what those counters cannot see.

## Periphery (scripts, schemas, examples, fuzz, CI)

- Parse and compare the layer tables instead of hand-copying them.
  - `scripts/check_layers.py` hand-copied its tables from the four crate
    roots and never read them, despite ADR 0001 saying it enforces the
    documented tables.
  - `crates/packetcraftr-core/src/lib.rs` omitted `clock` from its layer 1
    row even though the module exists and the script layers it.
  - `crates/packetcraftr-netio/src/lib.rs` omitted `entropy` from its
    layer 1 row the same way.
  - `scripts/check_layers.py` layered an `entropy` module for
    `packetcraftr` that does not exist in that crate.
  - Status. done. The checker now parses each crate root table and fails on
    drift in either direction, and the three drifted entries are fixed.

- Guard the input documents the way the output contract is guarded.
  - The seven input schemas under `schemas/` restate parser limits and are
    never checked against the example documents or embedded data.
  - Three example documents are byte-identical copies of embedded data in
    `crates/packetcraftr/data/` with nothing asserting they stay equal.
  - `examples/consumers/forwarding.py` hard-codes the output schema
    identity, and `scripts/check_output_schema.py` never reads it.
  - The frozen historical schema matches its ADR 0003 hash today, but
    nothing fails if it is edited.
  - Status. done. `scripts/check_documents.py` validates every JSON and YAML
    document that claims an input schema, fails on unclaimed schemas and
    twin drift, ties the forwarding consumer to `OUTPUT_SCHEMA`, and pins
    the frozen schema by a hash it also ties to ADR 0003. The YAML example
    `packet-raw.yaml` is also built end to end by a core test.
    The missing port catalog schema now exists.

- Remove dead weight from `scripts/check_coupling.py`.
  - `BASELINE` numbers were only printed, never asserted.
  - `message_protocol_rows` counted lines in a deleted file, so it could
    never fail.
  - Status. done. The ceilings stay. They are the ratchet from the
    decoupling plan, not structure worship.

- One name per fact in `scripts/release_assets.py`.
  - `GENERATED_ASSETS` was defined twice, once as the generator input and
    once as the manifest value.
  - Status. done. The generator input is now `BUILT_ASSETS`. The committed
    manifest itself stays, because `scripts/tests/test_release_assets.py`
    already fails when it goes stale.

- Kept, the fuzz seed mirrors in `scripts/fuzz_seeds.py`, the line-numbered
  mutant exclusions in `.github/workflows/ci.yml`, and the checked-in
  release manifest. Each has an enforcing test or gate today, and the
  checked review is recorded here instead of churning working guards.

## packetcraftr-core

- Make the protocol catalog say what it means.
  - `is_message_protocol` was defined as "has a coverage sentence", so
    editing documentation changed registration.
  - Catalog rows for DNS, HTTP, TLS, both DHCPs, TFTP, NTP, and Syslog
    claimed no ports while `builtin/bindings.rs` hand-bound their real
    ports, and TLS kept a third list.
  - `supports_transport` carried hand lists that restated those bindings.
  - `stream_decode` inferred stream framing from port assignment, two
    different facts.
  - Status. done. Rows now carry an explicit `message` flag and the real
    ports, one generic loop binds every catalog port, and
    `stream_decode` reads the message flag. The tunnel bindings in
    `register_tunnels` stay hand-written beside their child bindings, and
    the full per-protocol descriptor redesign was deferred and is
    resolved in the follow-up pass below.

- Delete the TLS-only registry wrapper.
  - `registry_with_tls_ports` in `protocol/builtin/assembly.rs` was a
    one-line delegate with no caller in tree outside its own doctest.
  - Status. done, together with its `bind_tls_ports` helper. This is a
    breaking removal for embedders, accepted because the workspace is
    unpublished and the capability survives. Callers add bindings through
    `registry_with` and `Builder::bind` directly, as its doctest already
    showed, and read the port list from
    `BuiltinProtocol::Tls.tcp_ports()`. Dissection behavior is unchanged,
    and the catalog accessors now report the ports that were always bound.

- Assert the manifest count instead of a floor.
  - `packet_documents_round_trip_through_build` silently skipped manifest
    entries without a document and asserted only `checked >= 36`.
  - Status. done. A missing document now fails by name and the checked
    count must equal the manifest length.

- Deferred to the follow-up pass recorded below, which has since
  resolved each of these (landed or kept with evidence there).
  - One descriptor per protocol file, with the catalog as an index over
    them. Adding a protocol today touches `protocol/catalog.rs` (row and
    accessors), `protocol/builtin/bindings.rs` (discriminator bindings),
    `protocol/builtin/filter_fields.rs` (filter fields),
    `protocol/catalog.rs::Framing` selection, and the identity tables in
    `protocol/builtin/tests.rs`.
  - Shrink the `Codec::construct` hook protocol in `codec.rs` plus the
    one-caller fields in `codec::EncodeContext`.
  - Walk decoded packets in `protocol/headers.rs` instead of re-parsing
    bytes, which deletes the copy-agreement test
    `headers_match_capture_decoding` in `protocol/builtin/tests.rs`.
  - Move the six scan and identify document vocabularies out of
    `document/` (`service_probes`, `service_exclusions`,
    `os_fingerprints`, `port_catalog`, `udp_profiles`, and the scan
    profile inputs) beside their consumers in the `packetcraftr` crate.

- Kept after checking.
  - The error code enum in core. ADR 0003 puts the published spellings
    there on purpose, and `BoundaryError` already erases them at workflow
    edges.
  - `capture_file::compression` as a module. Its `Format` and `Limits`
    names collide with the capture file ones, which is why it is not
    re-exported flat like its siblings.
  - The 23 downcast sites, `reflective_layer!`, and the inline comments.
    The comments state invariants and RFC facts rather than restating code.

## packetcraftr-netio

- One data-capacity formula.
  - `resources::TCP_DATA_CAPACITY` and `Pool::new` computed the same
    reserve two ways, disagreeing for small pools.
  - Status. done. Both go through `resources::data_capacity`, pinned by a
    boundary test.

- Derive stub errors from the capability.
  - Seven sites hand-passed the same enabled flag, feature name, and
    operation tuple to `Unsupported::unbuilt` that
    `NativeCapability::check` already derives in one match.
  - Status. done. Callers pass only the capability and their operation,
    and the feature facts come from one `build_facts` match.

- Narrow the dispatch allowlist.
  - The `udp` entry existed only for a 10-line and a 15-line receive
    wrapper, and the `capture` entry covered a whole module tree for calls
    that live in `capture::system`.
  - Status. done. The receive logic lives in `udp.rs` behind one target
    conditional, the platform wrappers are deleted, and the capture entry
    names `capture::system`. The route, interface, and transmit entries
    name single files already, and their system providers carry real logic
    at layer 3.

- Kept after checking.
  - The duplicate `admit` helpers in `route.rs` and `capture.rs`. They look
    identical but return different error types, and a shared generic helper
    would be wider than the duplication.
  - The workers tests that reach into `tcp` and `resolution`. They test
    pool cleanup through real callers, their fixtures live with the pool,
    and ADR 0001 exempts test code from the layer rule with the couplings
    reported.
  - The snapshot accessors with no in-tree caller and the always-true
    `NativeSnapshot.supported`. They are published diagnostics for
    embedders, and the snapshot is serialized into CLI output.
  - The global pools, the entropy seam, and the cleanup-time swallowed
    panics. Each is bounded, single-purpose, and documented.

- Deferred to the follow-up pass recorded below, which has since
  resolved each of these (landed or kept with evidence there).
  - One native-query error below both `interface.rs` and `route.rs`, so
    interface enumeration in `platform/interface.rs` stops returning
    `route::Error` values.
  - Per-contract errors under a thin top-level `Error` in `error.rs`,
    mirroring what `route.rs`, `interface.rs`, `tcp/`, and `tls/` already
    do for their own contracts.
  - One blocking-call helper for the admit, spawn, wait, and retain
    sequence repeated across `workers.rs` callers, plus one classifier
    for the four pcap error mappings in `platform/capture.rs` and
    `capture/pcap_api.rs`.
  - One namespace-identity type shared by `workers.rs` and
    `transmit.rs`, which each parse the same `/proc` identity today.

## packetcraftr

- Align the two discarded results with their siblings.
  - `scan/followup/reverse.rs` discarded a statistics overflow that the
    same file maps to `StatisticsOverflow` a screen earlier.
  - `dns/engine/attempts.rs` discarded an `account` result whose siblings
    propagate.
  - Status. done for the statistics overflow, kept for the account call.
    `Deadline::account` commits its charge whether or not the phase fit,
    the step already validated the exchange against its grant, and expiry
    is enforced where the deadline is next used, at the TCP fallback
    boundary. Propagating there would turn accepted UDP answers into errors.

- Point the payload version test at its provenance.
  - `scan/profile/curated.rs` asserted a constant equals the constant it
    was built from. The real link is the provenance file the comment names.
  - Status. done. The test reads the name and version out of
    `data/udp-payloads.provenance.yaml`, so bumping one side fails it.

- Kept after checking.
  - The `engine::preparation::tests` case that reaches into `exchange`. It
    pins the pinned-route check using the preparation fixture, and tests
    are exempt from the layer rule.
  - The catalog identity test in `scan/catalog.rs`. It fails if the
    published identity is ever hard-coded away from the bundled catalog.
  - The unused `ProviderSet` methods and the per-workflow file template.
    They are public API and genuinely shared machinery respectively.

- Deferred to the follow-up pass recorded below, which has since
  resolved each of these (landed or kept with evidence there).
  - A private exchange step API in `exchange/` and a layer-3 transmit
    options type, so the workflows in `dns/`, `scan/`, `send/`, and
    `probe/` stop building fake public requests per step through
    `engine/execution`.
  - An immutable `policy::operation::Operation` with constructor inputs
    and returned spent stats instead of the backwards assignment its
    callers perform today.
  - One `Failure` conversion trait replacing the threaded function
    pointers and their five drifted copies across the workflow error
    modules, one of which truncates coordinates.

## packetcraftr-cli

- Remove the test-only published re-export.
  - `output::DifferentialReport` existed only so one integration test could
    build a fixture through the code under test.
  - Status. done. The test builds its campaign as a JSON document, both
    re-exports and the layer allowlist row are gone, and the crate root now
    documents two deliberate upward edges. This also removes a public type
    name for embedders, accepted on the same unpublished-workspace basis
    as the TLS wrapper. The published shape is unchanged, so consumers
    read differential output as the JSON document the output schema
    describes.

- Give the shared frame source type a shared home.
  - `analyze::dns::output::provenance::Source` was imported by http, http2,
    messages, and files export from an arbitrary first user.
  - Status. done. It lives in `output::frame` beside `Timestamp`, and the
    DNS-only provenance module is deleted.

- Name the format sets once.
  - About 36 commands spelled out the identical Text, Json, Ndjson triple,
    plus a few Json-less pairs.
  - Status. done for the two repeated sets. `TEXT_JSON` and
    `TEXT_JSON_NDJSON` in `output::contract` replaced 29 spellings. The
    capture-flavoured sets differ per command in ways that matter, so they
    stay spelled out.

- Inline the two rename wrappers.
  - `filtering::matches_decoded` had one caller, and
    `commands::increment_counter` wrapped `checked_add(1)` for two.
  - Status. done for `matches_decoded`, kept for `increment_counter`. It
    owns the overflow error shape two unrelated commands share, so deleting
    it would copy that shape rather than remove it.

- Use the schema constant in the integration tests.
  - `tests/offline_commands.rs` hard-coded `v19` four times beside uses of
    the constant.
  - Status. done.

- Kept after checking.
  - The 59 cancellation polls, the `output` to `commands::Command` edge,
    the process globals, and the staged-output test hooks. The coupling
    script documents why each poll remains, and splitting command identity
    from command formats would create a second list to keep in sync.
  - `input/manifest.rs` serving only scan. ADR 0005 records the reason.

- Deferred to the follow-up pass recorded below, which has since
  resolved each of these (landed or kept with evidence there).
  - Split `invocation::Invocation` at its seam into a control handle, a
    publisher, and diagnostics. Today its interface includes field access
    and unwritten call order that about 100 sites depend on, mostly under
    `commands/` and `staged_output/`.
  - Unify the two publication idioms by giving
    `commands/offline_analysis/event_output.rs` a retained aggregate mode
    and migrating the five hand-rolled commands onto it.

## Comments and tests sweep

Both additions ran as their own sweeps after the structural fixes. The
comment sweep sampled the roughly 1,200 inline comments across the four
crates and found them stating invariants, RFC facts, and platform behavior
rather than restating code, so it deleted nothing beyond comments that
documented deleted code. The spots each audit named individually are
recorded as kept in their crate sections above. The tests sweep made three
rewrites, the manifest floor, the curated provenance assertion, and the
differential fixture that was built through the code under test. It removed
no tests, because every candidate it examined still fails on a real
regression, and the candidates are recorded as kept with their reasons.

## Re-check round

Independent re-audits and a two-axis review of the whole diff then found
and fixed a second, smaller set. The layer-table guard now fails when a
crate root documents no table, flags a module documented at two layers,
and requires carved-out submodules to be documented by name. Boundary
exemptions in `check_coupling.py` go stale-checked like the cast
allowlists, five dead ones were pruned, and the downcast ceiling now sits
at the measured 23. The port catalog schema gained the parser rules JSON
Schema can state, control characters, empty presets, and duplicate rows.
In core, the dead `TLS_TCP_PORTS` re-export and its one-binding helper
went away, and `stream_decode` also refuses datagram framing. The DNS
planner now reads its dissect-as-DNS ports from the catalog instead of a
local copy, the security input gate names its commands through the
registry instead of string literals, the differential fixture shrank to
the fields the join actually reads, and two new tests that restated the
code they guarded were rewritten to assert behavior instead. One limit
stays recorded. A submodule that quietly inherits its parent layer is
covered by the parent documentation entry, so the layer guard cannot
notice it vanishing from a grouped list. The boundary exemptions also
keep their substring matching, unlike the exact-path cast allowlists,
because the exemptions name module families rather than files and the
stale check must measure the same set the metric exempts.

## Deferred pass

A follow-up pass then worked through the deferred lists above. Items
finished there move out of their deferred sections into this record.

- Thread the caller registry into message encode.
  - `EncodeContext` now carries the caller's registry, and
    `protocol/message.rs` validates against it instead of building the
    global builtin registry. No current message parse consults the
    registry, so behavior is provably unchanged, and the global is gone.
- Pass the caller registry into scan probe construction.
  - `Probe::packet` and `sent_probe_matches` take the operation
    registry, threaded from the executors and the evidence classifier
    through prepare, transmission, streaming, feed, and pipelined paths.
    Payload typing under a registry without the codec keeps payloads
    raw, pinned by a new test in `scan/plan/packet.rs`.
- Collapse the collector finish pair and the session options.
  - `analysis::Collector` has one required controlled `finish`. The
    compatibility default and every two-method implementation are gone.
  - `Session::new` takes `SessionOptions`, which holds only caller-owned
    inputs. The plan, TCP events, and source tracking are derived from
    collector needs inside the session, so no caller field is silently
    overwritten any more. Callers that forced TCP events on beyond a
    collector's needs lose that knob, and no in-tree caller used it.
- Relocate the published-type registry beside its commands.
  - All 79 rows moved from `output/contract.rs` into each command's
    `Spec::PUBLISHED` and are collected through the registry macro,
    guarded by a Rust test that every published command owns rows and
    every row names a real command. The output-schema checker scans all
    CLI sources for rows instead of reading one file.
- Extract the traced-hosts shared types into one owner.
  - `Scope`, `Stage`, and `reply_name` now live in
    `output/scan_failure.rs`. Scan and traceroute both import them from
    there, and the scan pass-through re-export is deleted.
- Make encoder identity optional.
  - `StreamEncoder::unattributed` serves paths that run before a command
    is selected. It reports errors without an identity and refuses data
    records, and the reference-generation startup path uses it instead
    of borrowing the protocols command.
- Put each command's published types on its spec. All 79 `PUBLISHED_TYPES`
  rows moved from `output/contract.rs` into each command's
  `Spec::PUBLISHED`, collected once as `commands::registry::PUBLISHED`.
  Output stays layer 1 without a world catalog. A Rust guard,
  `published_rows_cover_every_command_exactly`, asserts coverage,
  cross-command uniqueness, and the shared null fallback, and
  `scripts/check_output_schema.py` scans every CLI production source for
  the rows. `output/contract.rs` shrank 903 to 153 lines. Evidence: CLI
  tests 125 passed and the schema check passed against the live binary.
- Put one native error below both native query contracts. The shared
  native-query error moved from `route/error.rs` to a private `native`
  module, exposed publicly unchanged as `route::Error`. Interface
  backends and shared platform helpers now speak `native::Error`, so
  `interface::Error::native` no longer borrows the route namespace.
  Evidence: netio tests 101 passed with all features and the layer
  guard is green.
- Share one namespace identity. The transmit session snapshot kept its own
  device and inode pair. It now holds the workers `ExecutionContext`
  identity through `of_metadata`, so thread-pool matching and transmit
  verification define namespace sameness once. Evidence: netio tests
  101 passed with all features.
- Classify libpcap failures once. `platform/common/libpcap.rs` owns a
  `classify` for privilege and missing-device messages, and both the open
  and send mappings live there. Receive and statistics errors stay
  unclassified `Error::Capture`, as before, because a mid-stream failure
  carries no privilege question. Evidence: netio tests 101 passed with
  all features.
- Own the blocking-call skeleton in `Permit::call`. The route worker helper
  and the hostname lookup both hand-rolled spawn, wait, and
  retain-on-pending. `call` returns `Blocked::Finished`, `Panicked`, or
  `Pending`, and marks a pending task retained before its outcome is
  abandoned, which is the rule admission accounting depends on. Callers
  keep their error wordings. A new workers test proves an abandoned call
  stays charged until the work returns. Long-lived flows that keep their
  task, like capture activation and the netlink service, stay on
  `spawn_with_control`. Evidence: netio tests 102 passed with all
  features.
- Keep the top-level netio `Error` for the capture and transmit contracts.
  The standalone contracts already carry their own errors (`tcp`, `udp`,
  `tls`, `interface`, and `route` through `native`). Capture and transmit
  share live sessions and share variants in practice, with `Privilege`,
  `Device`, and `DeadlineExceeded` constructed on both sides, and capture
  groups wrap failures recursively through `Box<Self>`. Splitting would
  duplicate the shared variants and force conversions at every mixed
  session boundary without moving any variant closer to its only caller.
- Replace threaded failure conversions with one trait. Five workflow
  conversions from the shared `Failure` existed as a macro expansion in
  scan and traceroute plus hand copies in os, dns, and fuzz, and thirteen
  helper signatures threaded them as `fn(u64, Failure) -> E` pointers,
  including two structs that stored the pointer. `crate::error::FromFailure`
  is now implemented beside each workflow error, the macro is deleted, and
  every helper takes an `E: FromFailure` bound instead of a pointer.
  `Context` and `BatchEvidence` carry only a phantom error type. Sites
  where the pointer used to pin the error type now name it with a
  turbofish. Evidence: packetcraftr tests 170 passed, clippy clean with
  warnings denied, and no `fn(u64, Failure)` signatures remain.
- Give workflow exchanges a private step shape. `exchange_hooked` took the
  public `Request`, so both hooked callers fabricated a `stop: Window` that
  preparation discards. A crate-private `exchange::Step` now carries only
  template, send options, timeout, packet ceiling, and collection, sharing
  validation and template preparation with the public path. The public
  `Request` keeps its stop condition, honored by `Client::exchange` alone.
  Evidence: packetcraftr tests 170 passed.
- Make `engine::operation::Operation` evolve by transition, not by field
  writes. Callers assigned neighbors, mode, pause, limits, runtime, and
  spent after construction at sixteen sites, including through a `&mut`
  authorize helper. Those are now `with_spent`, `with_neighbors`,
  `with_neighbor_mode`, `with_neighbor_pause`, `with_limits`, and
  `with_runtime`, and scan's `NeighborBounds::authorize` consumes and
  returns the operation. Fields stay crate-visible for reads because the
  type is crate-private and reads dominate, but no write to an operation
  field remains outside `engine/operation.rs`. Evidence: packetcraftr
  tests 170 passed and clippy is clean with warnings denied.
- Split the CLI `Invocation` stop conditions into `invocation::Control`.
  Deadline and cancellation now live on their own type with the check,
  passive-lookup, and reader behavior. The whole `input` module, which only
  ever used those, takes `&Control` instead of fabricating output state in
  tests, and its polled source stores a `Control`. The one input path that
  also touches output, `open_capture`, takes the encoder as its own
  parameter for the regular-file observation. `Invocation` keeps format,
  encoder, JSON-once and stdout batching state, and diagnostics, which
  change together per command run. Evidence: CLI tests 125 passed and
  integration tests 31 passed.
- Keep the three publication idioms separate. Per-event output already runs
  through `offline_analysis::EventOutput`, whole-document reports share
  `bounded_json_len` with `emit_published` and `complete_published`, and the
  field `Projector` tracks rows, a text header, and a count that neither of
  the others has. The aggregate commands differ in ceiling, diagnostics,
  and NDJSON item projection, and the assessment report additionally stages
  an HTML file. Folding them into one mode would move those differences into
  flags rather than remove them.
- Keep the byte-level header walkers in core `protocol/headers.rs`. Their
  consumers are the capture transforms (rewrite, fragment, address map,
  repair), quoted-ICMP matching, and reassembly validation. Those work on
  raw frames by design and must keep byte fidelity for traffic the
  dissector would reject or normalize, so walking decoded packets instead
  would change behavior. The `headers_match_capture_decoding` test stays as
  the guard that both readings agree where they overlap.
- Keep the `Codec` construction hooks and the narrow `EncodeContext`
  fields. Each hook has a real overrider with a distinct job (seeding from
  text-shaped fields in six application codecs, DHCP finish in three, TLS
  read-only enforcement, opaque field preparation), and `Codec` is a public
  extension trait. The single-reader context fields carry cross-layer facts
  the builder computes once (segment-routing state, GRE sequence presence,
  outer-network and under-IPv6 position); deleting them would make codecs
  recompute facts they cannot see from their own layer.
- Keep the central protocol catalog. It is already one row per protocol
  feeding every generated view, and the `BuiltinProtocol` enum needs the
  central variant list regardless, so a descriptor per protocol file would
  split each protocol's declaration across two places instead of one. The
  bindings table is relational data between parent and child protocols and
  changes with both sides.
- Keep the dataset vocabularies under core `document`. They are published,
  versioned document formats alongside packet documents and recipes, not
  scan internals. Moving them beside their consumers would break core's
  public parsing API, and `udp_profiles` cannot move at all because netio
  takes its payload ceiling from it and core's own service-probe
  observations embed its payload type.

## Re-check round

Fresh subagent audits over the finished tree found the following, each
verified again in the code before fixing.

- Spell the self-or-raw acceptance rule once per codec against
  `protocol_id()` and `Raw::ID`. Nine hand copies restated their own
  canonical name and the `"raw"` literal, and `raw_ip` restated `"ipv4"`
  and `"ipv6"`; all now compare against the catalog identities.
- Derive every protocol `NAME` from its `BuiltinProtocol` variant. Thirty
  three files restated the canonical string as a literal while taking their
  schema identity from the catalog, and the messages collector hard-coded
  `"tcp"` three times beside a typed use.
- Let the SIP framer skip stream keepalives. `Framer::progress` now returns
  a `Progress` outcome (`Incomplete`, `Skip`, `Message`), so the messages
  collector lost its SIP special case and its copied bookkeeping. A new
  framing test covers the keepalive and the lone-CR wait.
- Single-source the AMQP preface and the supported MQTT level in their
  protocol modules; the messages collector reads those constants instead of
  restating the bytes and the level.
- Type the two closed-set text fields. Modbus `form` is now `PduForm` and
  IEC 104 `frame_type` is now `FrameType`, following the syslog and BSD
  reflective patterns and preserving document spellings. Invalid values now
  fail at construction, covered by two new tests.
- Finish the `FromFailure` migration in client admission. The approval and
  selection helpers still threaded `fn(u64, Failure) -> E` under a shorter
  spelling, fed by six one-line wrapper functions. They now bound
  `E: FromFailure`, `target::plan::Error` gained the missing impl from its
  hand copy, and all six wrappers are deleted. No `fn(u64, ...)` failure
  signatures remain anywhere in the crate.
- Publish the transient I/O kind sets once. `bounded::timed_out` joins a now
  public `bounded::retryable` in netio, replacing re-derivations in DNS-over
  -TCP, service identification, the differential responder, and the AF_ROUTE
  query path.
- Use the shared ephemeral-port helper in OS identification and the shared
  base constant in multipath flow allocation, instead of restating 49152
  and the 16384 width.
- Move the audit-only TLS fixtures beside the audit tests. Netio keeps only
  the CA its own verification tests use; the leaf, key, and untrusted CA
  moved, with a CA copy for the leaf chain.
- Spell the shared native error as `native::Error` in interface validation,
  the last interface-side user of the route name.
- Count cancellation polls by behavior, not variable name. The coupling
  ratchet now counts `check` and `check_interrupted` on every local receiver
  spelling, whitespace-insensitively, in CLI production sources; the true
  count is 73, not the 59 the old literal pattern saw. A script test pins
  the spellings.
- Guard the script crate tables against a fifth workspace crate. The layer
  checker now reports any discovered crate with no layer entry, and the
  manifest tests discover their crate set from the workspace instead of
  restating it.
- Scope the output-schema code inventory to production sources. It now skips
  test paths and strips `#[cfg(test)]` items (a shared `rust_source`
  helper), so test-only code literals no longer whitelist unpublished
  surface. The jsonschema import also goes through the documented
  `CheckError` before any registry work, as the module docstring promises.
- Replace the hand-written pre-clap argument scanner with the real command
  definition parsed with errors ignored and self-override allowed. Parse
  error reporting now inherits clap's answers for clusters, inline values,
  repeated globals, and command identification instead of approximating
  them. Four new tests pin the fallback behavior, including last-valid-wins
  for a repeated `--output`.
- Derive the published-schema path in the envelope identity test from
  `output::contract::SCHEMA` instead of a restated `v19` filename, take the
  typed `Format` in `TreeArgs::validate_format` instead of a caller-decided
  bool plus a display string, and share one generic decimal-or-hex parser
  across template values, VLAN rewrites, and TCP flags (which now all accept
  the `0X` spelling).
- One CLI audit item did not verify on re-check and is recorded as such: no
  `fetch_min` settings ceiling or library-maximum chain for
  `max_tree_bytes` exists in this tree; the declared setting reports the
  same typed field `FieldTree` charges against, so there is no gap for a
  guard test to close.

## Confirmation round

Three more subagents re-audited the tree after the re-check fixes. Every
re-check item verified as resolved, and the last same-class leftovers they
found are fixed here.

- Core: `"sip"` dispatches in the text-message codec and the message macro,
  `"raw"` literals in validation and message bindings, the PPP control name
  literals, the MQTT encode level literal, the AMQP prefix spellings, and
  the hard-coded `"resp"` framer name all derive from the catalog, their
  shared constants, or the caller-supplied framer name.
- Packetcraftr: the connect scan now classifies socket timeouts through
  `bounded::timed_out` like every other workflow (a `WouldBlock` result was
  previously reported as a local error there alone), and scan packet
  planning derives its tunnel identities and DHCP/NTP ports from the
  catalog rows beside its existing typed uses. The audit PEM fixtures are
  excepted from the `*.pem` ignore rule so a plain add-all cannot lose them.
- Scripts and CLI: the poll counter also catches the `cancellation`
  receiver and strips inline test items, so the production count stands at
  73; the shared test-item stripper now scans literals and comments
  properly and ends field and statement items at their terminators, with
  dedicated tests; published-code harvesting blanks comments so hostnames
  in prose no longer whitelist output codes; `check_documents` reports a
  missing jsonschema package through the same clean `CheckError`; and the
  one self-referential assertion in the new error-context tests now pins
  `Command::Build` directly.

A final confirmation pass over those fixes found five more one-line
leftovers of the same classes, also fixed: the AMQP magic in the framing
arm and the HTTP/2 preface length now derive from their constants, the
test-item stripper tracks every delimiter depth (with leak cases pinned by
tests) and the schema registry inventory strips test items like the code
inventory does, decode-as transports match to catalog variants without a
string round trip or a panic-capable expect, and the stale-allowlist script
test now asserts a known stale entry is reported, so it fails if that
reporting is ever deleted.
