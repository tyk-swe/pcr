# Deepen the shared mechanics: live step, batch evidence, stream generations, header walk, workflow output, stream selection

Status: ready-for-agent

## Problem Statement

A maintainer working in the hot parts of this codebase — the live workflow
engines, the offline analysis collectors, the packet transforms, and the CLI
command modules — keeps meeting six copied or leaky mechanics. In each case
the copies have already started to disagree, and the only way to find the
disagreement is to read every copy:

1. **The live step.** Scan and traceroute (through the shared probe
   runner), DNS, and fuzz each run "one request under the operation
   deadline" themselves: pace, start accounting, clip the timeout, execute,
   enforce the deadline, check the execution permit, validate the receipt,
   account elapsed time, add statistics. The copies disagree on
   safety-relevant behavior: when an executor error and an interruption
   happen together, the probe runner reports the executor error while DNS
   and fuzz report the interruption; after the pacing sleep the runner
   enforces the whole deadline while DNS and fuzz only check cancellation;
   fuzz skips the aggregate evidence-limit check and re-implements checked
   statistics addition. The budget tests are duplicated line for line
   across suites.
2. **Batch evidence.** Scan and traceroute each carry a ~240-line copy of
   batch processing — permit check, response selection, timeout/response
   evidence, undecoded retention, diagnostic publication. The probe
   lifecycle trait they implement is pass-through: two of its three
   methods are identical in both workflows. Scan's pipelined path
   re-assembles the same steps by hand. DNS and fuzz rebuild evidence
   retention without the shared evidence state, so retention limits and
   diagnostics drift per workflow.
3. **Stream generations.** The analysis pipeline decides when a TCP
   four-tuple has been reused, but only tells collectors by emitting an
   eviction. The HTTP/DNS source tracker, the TLS tracker, follow with its
   deduplication, and expert each rebuild the idea of a connection
   generation and the ordering rule ("expiry and replacement come before
   this frame's data; a clean close comes after it") in their own way.
   Reuse behavior is proven separately per collector.
4. **Header walks and checksum coverage.** IPv6 extension-chain walks,
   the "is this checksum still repairable" guard (fragmented datagram,
   IPv4 source-route options, IPv6 routing header, IPv6 Home Address
   option), pseudo-header checksum construction, and the Ethernet/VLAN walk
   are copied across the header rewrite, field edits, fragmentation, and
   netio's neighbor-discovery parser. The copies accept different
   extension-header sets and depth limits, and the canonical helpers in
   core are crate-private and almost unused. None of the transform modules
   has unit tests, and no contract test checks the source-route or Home
   Address refusals.
5. **Workflow output.** The live-command driver introduced by the previous
   orchestration work is deep, but each of its eight call sites pays ~45
   lines of adapter: converting the collected report into the wire result
   and again for text, and emitting events and terminal records through
   per-command functions that differ only by conversion method name.
   Fuzz-live and connect never fully migrated and still assemble their own
   session, runtime, and executor.
6. **Stream selection.** The analysis session takes a stream selector only
   to report "selected stream absent"; selection itself happens in the
   compiled filter. So four commands turn a parsed stream reference back
   into filter text, compile it, and pass the same reference again —
   keeping the two consistent by hand — then phrase the absent verdict in
   two different messages.

## Solution

Deepen six modules so each mechanic lives in one place with a small
interface, and call sites supply only what legitimately differs:

1. **Live step in `probe`** — one module owns pacing and the bounded
   execution of one request, including the permit check, aggregate
   evidence-limit validation, elapsed-time accounting, checked statistics,
   and a single precedence rule: an interruption wins over a concurrent
   executor error. Workflows supply the request, their receipt-specific
   validation, and an error adapter.
2. **Batch evidence in `probe`** — one module owns execute → validate →
   select → retain → publish for a batch. Workflows supply the response
   classifier and rank, the evidence constructor, and a post-probe hook.
   DNS and fuzz retain evidence through the shared evidence state.
3. **Stream generations in the analysis pipeline** — the pipeline emits,
   per frame, an ordered sequence of stream events that already carry the
   connection generation and already obey the ordering rule. Collectors
   consume it and keep only their protocol semantics.
4. **Header walk in core** — one module walks raw link and IP headers,
   decides whether a transport checksum stays repairable, and builds
   pseudo-headers. Transforms and netio's neighbor parser call it.
5. **Workflow output in the CLI `output` area** — each workflow family
   converts its events, summary, and report to the machine contract in one
   place. The live-command driver's per-command adapter shrinks to the two
   engine entry points and a text renderer; provider composition supplies
   the runtime and executor every live command needs.
6. **Stream selection in the analysis session** — the session takes an
   optional stream reference, derives the stream filter from it, and
   reports a typed "selected stream absent" outcome that every command
   phrases the same way.

User-visible behavior is preserved — same CLI output, same exit codes,
same `packetcraftr.output/v6` machine contract — except for the sanctioned
deltas listed under Implementation Decisions.

## User Stories

1. As a maintainer adding a new live workflow, I want to execute each
   request through one live-step interface, so that I cannot get the
   deadline, pacing, or accounting order wrong.
2. As a maintainer, I want the executor-error-versus-interruption
   precedence decided once, so that every live workflow reports the same
   cause when a user cancels mid-execution.
3. As a CLI user pressing Ctrl-C during `scan` or `traceroute`, I want the
   run to report cancellation rather than a secondary executor failure, so
   that the error names what actually stopped it, as `dns` and `fuzz`
   already do.
4. As a CLI user, I want a receipt that was already returned before an
   interruption to be validated and counted in the partial statistics, so
   that interrupted runs still report the traffic they sent faithfully.
5. As a maintainer, I want pacing to enforce the whole deadline after every
   sleep in every workflow, so that a duration budget cannot be overrun by
   one extra paced request.
6. As a maintainer, I want the execution-permit check done by the live
   step, so that no workflow can forget to reject evidence for a different
   execution.
7. As a maintainer, I want aggregate evidence limits validated for every
   live workflow, including fuzz, so that finite budgets hold at every
   executor boundary.
8. As a maintainer, I want statistics added with one checked operation,
   so that fuzz's hand-rolled aggregation and its dedicated test disappear.
9. As an executor author, I want the executor-facing receipt types to stay
   as they are, so that deepening the live step does not break my
   executor implementations.
10. As a maintainer adding pacing to `send`, connect, or the scan
    pipeline, I want to reuse the live step's pacer, so that rate delays
    are charged to the deadline the same way everywhere.
11. As a maintainer, I want budget contracts — zero or exhausted budgets
    never execute, clipped timeouts reject late evidence, prior pacing
    shortens the next timeout — tested once at the live step, so that the
    duplicated suites can be deleted.
12. As a maintainer adding a probe-style workflow, I want to supply only a
    classifier, a rank, an evidence constructor, and a post-probe hook, so
    that batch processing comes for free.
13. As a maintainer, I want scan and traceroute to stop carrying their own
    copies of batch processing, so that a fix to response selection or
    undecoded retention lands once.
14. As a maintainer, I want scan's pipelined path to process batches
    through the same module as its sequential path, so that the two paths
    cannot drift.
15. As a maintainer, I want DNS and fuzz to retain evidence through the
    shared evidence state, so that retention limits and their diagnostics
    behave identically across workflows.
16. As a CLI user running `fuzz` against a noisy target, I want undecoded
    frame retention to be finitely bounded like every other workflow, so
    that memory stays within the declared budget.
17. As a maintainer, I want the sink-failure, event-ordering, and
    invalid-sent-evidence contracts tested once at the batch-evidence
    interface, so that scan and traceroute suites test only their own
    semantics.
18. As a maintainer, I want the positional retention constructor out of
    the probe interface, so that the evidence module exposes capabilities
    rather than assembly details.
19. As a maintainer writing an analysis collector, I want each frame's
    stream events to arrive already ordered and tagged with a connection
    generation, so that I never re-derive TCP four-tuple reuse.
20. As a maintainer, I want the rule "expiry and replacement before this
    frame's data, clean close after it" enforced in one place, so that
    every collector sees the same order.
21. As a CLI user analyzing a capture where a client reuses a source port,
    I want `http`, `dns`, `tls`, `follow`, and `expert` to split the two
    connections identically, so that results agree across commands.
22. As a maintainer, I want collectors to declare that they need ordered
    stream events through their declared needs, so that the session only
    runs that stage when someone consumes it.
23. As a library consumer of core, I want the existing per-frame
    reassembly events to stay available and unchanged, so that my code
    keeps working while collectors move to the generation view.
24. As a maintainer, I want one scripted-event test suite for reuse,
    expiry, reset, and close ordering, so that per-collector reuse tests can
    shrink to collector semantics.
25. As a maintainer editing packet headers, I want one module that walks
    link and IP extension headers, so that rewrite, field edits,
    fragmentation, and neighbor discovery accept the same chains.
26. As a maintainer, I want one checksum-coverage guard, so that the
    refusals for fragmented datagrams, IPv4 source routes, IPv6 routing
    headers, and the IPv6 Home Address option cannot drift between header
    rewrite and field edits.
27. As a maintainer, I want pseudo-header construction and the
    UDP-checksum-zero rules in one place, so that transforms and netio
    compute identical checksums.
28. As a CLI user running `rewrite` or field edits on a source-routed or
    Home-Address packet, I want the same refusal from either path, so that
    I can predict which edits are safe.
29. As a maintainer of netio's neighbor discovery, I want to reuse core's
    header walk with my own depth bound, so that untrusted replies are
    parsed with the same rules as everything else.
30. As a maintainer, I want every header-walk refusal tested once in a
    table, so that both transform entry points inherit that coverage.
31. As a maintainer adding a live command, I want to implement one output
    conversion for my workflow family, so that NDJSON events, terminal
    records, JSON aggregates, and text all derive from it.
32. As a maintainer, I want the report converted to the wire result once
    per run, so that text rendering and JSON output cannot diverge.
33. As a maintainer, I want the per-command event and completion emitters
    deleted, so that the driver's per-command adapter shrinks from seven
    slots to the entry points and a renderer.
34. As a maintainer, I want provider composition to supply the runtime and
    executor for live commands, so that fuzz-live and connect stop
    assembling their own session, runtime, and preparation.
35. As a maintainer, I want each workflow's output conversion testable
    against the machine-output schemas without running an engine, so that
    contract drift is caught in isolation.
36. As a maintainer adding an analysis command with `--stream`, I want to
    pass the stream reference once, so that the filter and the verdict
    cannot disagree.
37. As a CLI user running `http`, `dns` (offline), `tls`, or `follow` with a
    `--stream` that is not in the capture, I want the same "not present"
    message from every command, so that behavior does not depend on which
    command I picked.
38. As a maintainer, I want the analysis setup to stop exposing its fields
    for callers to feed back into the session, so that preparing and
    running a session is one interface.
39. As an agent writing tests, I want to reach each of these mechanics
    through an in-process interface with existing fakes, so that I do not
    need to spawn the binary or open sockets.
40. As a maintainer, I want the existing process-level and public-behavior
    contract tests to keep passing, so that the refactors are provably
    behavior-preserving outside the sanctioned deltas.
41. As a maintainer, I want unit tests that only re-exercised duplicated
    mechanics deleted once interface-level tests exist, so that the suite
    does not carry redundant coverage.
42. As a reviewer, I want every sanctioned behavior change recorded under
    `[Unreleased]`, so that users see exactly what changed.

## Implementation Decisions

### 1. Live step (`packetcraftr`, `probe`)

- A crate-private live-step module in `probe` is the deep module for
  executing one request under the operation deadline. Its interface takes
  the deadline, the clock, the executor, the request (with its requested
  timeout), and a step-error adapter; it returns the validated receipt.
  A separate pacer operation charges a rate delay to the deadline.
- It owns, in this order: enforce the deadline; start accounting; clip the
  request timeout to the remaining budget; execute; check the permit;
  validate aggregate evidence limits and the workflow's receipt-specific
  rule; account elapsed time; add statistics with the shared checked add.
- **Precedence (decided):** when the executor fails and the deadline or
  cancellation has also fired, the interruption is reported. When the
  executor returned a receipt and an interruption fired, the receipt is
  permit-checked, validated, and its statistics accounted before the
  interruption surfaces, so partial summaries stay faithful (DNS's
  behavior today).
- After a pacing sleep the step enforces the whole deadline (cancellation
  and duration), not cancellation alone.
- The step-error adapter follows the shape of the admission gate-error
  adapter: it maps duration-limit, execution, clock, invalid-evidence, and
  statistics-overflow failures to the workflow's error type, keyed by the
  workflow's coordinate (batch sequence, DNS attempt, fuzz case index).
- The executor-facing receipt types (probe batch, DNS, fuzz) and the
  executor trait stay public and unchanged. The step reads receipts through
  a crate-private receipt trait exposing the permit, statistics,
  diagnostics, and the evidence the aggregate-limit check needs.
- Workflow-specific validation — exact sent-probe matching, DNS question
  matching, fuzz's expected-bytes rebuild — stays in each workflow and is
  supplied to the step as its validation hook.
- `send`, connect, and the scan pipeline reuse the pacer. Their execution
  loops otherwise stay as they are.

### 2. Batch evidence (`packetcraftr`, `probe`)

- The probe runner's lifecycle trait is replaced by a batch-evidence
  module that runs each batch through the live step, then selects
  responses, builds timeout or response evidence, retains undecoded frames,
  and publishes new diagnostics.
- Its interface takes a small workflow adapter with four capabilities:
  classify a selected response, rank competing candidates, construct the
  workflow's evidence for a probe (response or timeout), and a post-probe
  hook that may end the operation. It also needs a mapping from an
  undecoded frame to the workflow's event.
- Scan supplies its application-profile evidence, its rank, winners, and
  RTT; traceroute supplies its completion and terminal break. Scan's
  pipelined path drives the same module instead of calling validate and
  process by hand.
- The shared evidence state is the only retention path. DNS's private
  state and fuzz's private retention are removed; the positional
  undecoded-retention constructor and the free retention helpers leave the
  probe interface.
- Diagnostic codes are part of the machine contract and are preserved:
  the evidence state takes the workflow's own codes.

### 3. Stream generations (`packetcraftr-core`, analysis pipeline)

- The pipeline's reuse detection is the single source of truth for
  connection generations. Alongside the existing per-frame reassembly
  events, each frame record gains an ordered stream-event sequence in which
  every event carries its scoped flow and connection generation. The shape
  follows the application-layer event type that already exists (data, gap,
  conflict, closed with reset flag, evicted).
- The pipeline enforces the ordering rule: expiry of other flows and
  reuse-driven replacement precede this frame's data; a clean close
  follows it.
- A connection generation distinguishes successive connections that reuse
  one scoped four-tuple. This does not change how capture-global
  conversation indices are assigned.
- Collectors request the stage through their declared needs; the session
  enables it, as it already does for reassembly events.
- The HTTP/DNS source tracker, TLS tracker, follow and its deduplication,
  and expert's eviction reconciliation consume the generation view and
  delete their re-derivation.
- The existing public per-frame reassembly events remain available and
  unchanged for library consumers.

### 4. Header walk (`packetcraftr-core`, network protocol area)

- One public core module, placed with the existing network-envelope
  helpers, walks raw link and IP headers. The existing crate-private
  extension helpers fold into it so there is one public path.
- The Ethernet/VLAN walk and the IPv6 extension walk take a
  caller-provided depth bound and yield each header with its kind, offset,
  and length. The walk covers the canonical walkable set (Hop-by-Hop,
  Routing, Fragment, AH, Destination Options) and is policy-free; callers
  keep their own structural refusals (for example fragmentation's
  misordered Hop-by-Hop check).
- One checksum-coverage guard decides whether a transport checksum stays
  repairable after an edit and returns a typed refusal: fragmented
  datagram, IPv4 loose/strict source route, IPv6 routing header, IPv6 Home
  Address option.
- One pseudo-header builder owns the IPv4 UDP rules (a zero checksum
  stays disabled; a computed zero becomes all-ones).
- Header rewrite, field edits, and fragmentation call the module; netio's
  neighbor-discovery parser calls it through netio's existing core
  dependency. The codec and pcap wire modules are not touched.

### 5. Workflow output (`packetcraftr-cli`, `output` and `execution`)

- Each live workflow family (scan, connect, traceroute, DNS single and
  batch, fuzz offline and live, exchange) implements one output conversion
  in the `output` area with three operations: engine event → wire record
  plus diagnostics; engine summary → terminal record plus stats; engine
  report → wire result, diagnostics, and optional stats.
- The live-command driver takes that conversion instead of the four
  per-command conversion slots. Its per-command adapter keeps the command
  identity, the collecting and streaming entry points, and a text renderer
  over the already-converted result. Exchange's capture formats keep
  access to what they need through their own conversion.
- The per-command event and completion emitters are deleted.
- Provider composition vends the worker runtime and the prepared executor.
  Fuzz-live's own preparation and session, and connect's private session,
  are replaced by the shared ones.

### 6. Stream selection (`packetcraftr-core` analysis session, CLI analysis setup)

- The analysis session takes an optional stream reference and derives the
  stream filter from it, composed with any frame filter the caller
  prepared. Callers no longer format filter text from a stream reference.
- The session reports "selected stream absent" as a typed outcome; the CLI
  maps it to one error with one message for every analysis command.
- The CLI's analysis setup becomes one interface — prepare, open, and build
  a session from a collector and an optional stream reference — and stops
  exposing its fields.

### Sanctioned behavior changes

Everything else is a pure refactor. These deltas are deliberate, and each
is recorded under `[Unreleased]`:

1. `scan` and `traceroute` report an interruption, not the executor error,
   when both occur in one step.
2. `fuzz` validates aggregate evidence limits and bounds undecoded-frame
   retention like the other live workflows.
3. `http` and offline `dns` phrase the absent-stream error the way
   `follow` and `tls` do (`--stream <transport>:<N> is not present`).
4. Where the header-rewrite and field-edit copies refuse different header
   chains today, both adopt the guard's refusal set. The implementer lists
   every such difference before merging the copies; any chain that one path
   accepted before and now refuses is recorded as a user-visible change.

### Cross-cutting

- No change to the machine-output wire types, format sets, schemas, or
  `packetcraftr.output/v6`.
- No new external seams. All injection is in-process: closures, small
  adapter traits, and generics over existing traits. The existing fake
  executors, clocks, and providers are the second adapter that makes each
  seam real.
- No ADR conflicts: `docs/adr/` does not exist yet.

## Testing Decisions

- A good test asserts observable behavior through the deepened module's
  interface — reported errors and their precedence, receipts and
  statistics, emitted events and their order, refusals, wire records — and
  never internal state or private helpers. Tests must survive internal
  refactors; a test that breaks when the implementation moves was testing
  past the interface.
- **Replace, don't layer.** Once interface-level tests exist, delete the
  duplicated unit tests that only re-exercised the copied mechanics.
  Public-behavior tests under each crate's `tests/` and the CLI's process
  contracts stay as the regression net, and change only where a sanctioned
  delta requires it.

Per seam (confirmed with the maintainer — two new seams, the rest reuse
existing ones):

- **`probe` live step and batch evidence (new, crate-private).** Unit tests
  beside `probe` use the existing probe test fixtures, fake executors, and
  fake clock. Cover: interruption wins over a concurrent executor error; a
  returned receipt is validated and counted before the interruption
  surfaces; pacing enforces the whole deadline; zero or exhausted budgets
  never execute; clipped timeouts reject late evidence; prior pacing
  shortens the next timeout; permit mismatch is rejected; aggregate
  evidence limits are enforced; statistics overflow is reported with the
  workflow's coordinate; sink failure stops later work; events precede
  later work; retention limits emit the workflow's diagnostic once. Prior
  art: the probe runner's tests and fuzz's run tests, which this replaces;
  scan's and traceroute's duplicated lifecycle tests are deleted.
  `output_behavior` and the scan-pipeline contracts stay.
- **`analysis::Session` (existing) for stream generations and stream
  selection.** A recording collector driven by in-memory capture fixtures
  asserts the ordered, generation-tagged stream events: reuse with data in
  the replacing frame, expiry of another flow, clean close after data,
  reset. Stream-selection tests assert that a TCP or UDP stream reference
  selects only that conversation, composes with a frame filter, and yields
  the absent outcome after the trailing drain. Prior art: the session's
  empty-selector verdict test and the crate's capture fixtures. The HTTP,
  TLS, and follow reuse contracts shrink to collector semantics. The CLI's
  every-format absent-stream test for `follow` extends to `http`, offline
  `dns`, and `tls`.
- **Core header walk (new, public).** A table-driven unit suite beside the
  module covers each extension kind, truncation, depth-bound exhaustion,
  every guard refusal, and pseudo-header vectors, including the UDP-zero
  rules. The header-rewrite and field-edit contract suites gain the
  source-route and Home Address refusals they lack today. netio's
  neighbor-discovery tests stay as that crate's regression net.
- **`execution::run_workflow` (existing) and `output` conversions.** The
  driver's recording-hook tests keep covering every format path. Each
  workflow family's conversion is exercised by the existing NDJSON and
  aggregate schema-conformance tests. `process_contracts` stays the outer
  net, unchanged.

## Out of Scope

- The remaining review candidates: the read family's bounded frame loop,
  staged packet-set preparation, the shared `proto#N.field` address
  grammar, and making the scan pipeline reuse exchange correlation.
- Small fixes noted by the review: a union operation for filter
  requirements, pass-through collector adapters, moving stats and
  forwarding onto the session, the command descriptor table, and the
  staged PCAPNG writer.
- Merging the public executor receipt types, or narrowing the executor
  trait's pipeline methods.
- Removing or changing the existing per-frame reassembly events.
- Conversation-index assignment, exchange correlation semantics, DNS retry
  and TCP fallback, replay's exact-wire authorization, admission paths, and
  per-workflow budget arithmetic.
- The codec and pcap wire modules.
- Any machine-output contract change.

## Further Notes

- Suggested order: the live step (1) first, since batch evidence (2) is its
  process half; then stream selection (6), which is small and touches the
  same session as stream generations (3); then workflow output (5); then
  the header walk (4).
- The live step, batch evidence, and header walk each touch safety-relevant
  paths (finite budgets, evidence fidelity, checksum repair). Review them
  against AGENTS.md's untrusted-input and resource-boundary rules.
- Before implementing sanctioned delta 2, confirm which evidence limits
  fuzz's request already declares. If one is missing, derive it from the
  existing campaign limits rather than adding a new user-facing option.
- Scope for commits: `probe`/`scan`/`traceroute`/`dns`/`fuzz` for the live
  step and batch evidence, `analysis` for 3 and 6, `transform`/`netio` for
  4, `cli` for 5, all without the `packetcraftr-` prefix.
