# Deepen the orchestration seams: analysis session, live-run driver, operation admission

Status: ready-for-agent

## Problem Statement

A maintainer working in the hot parts of this codebase — the CLI command
modules and the workflow engines — keeps meeting the same three copied
patterns:

1. Every offline-analysis command (`http`, `dns_read`, `expert`, `follow`,
   `tls`) re-implements the collector lifecycle end to end: build the
   collector, prepare analysis options, open the capture, drive
   `run_with_ip_events` while calling `observe` per record, collect scopes,
   call `finish`, drain trailing events, and check whether a `--stream`
   selector matched nothing. `http` and `dns_read` are near-identical twins.
   Ordering bugs in this lifecycle can only be found per-command, and the
   `filter::Requirements → analysis::Plan` narrowing that skips unneeded
   pipeline stages is opt-in caller knowledge, so commands silently run the
   full pipeline.
2. Every live command (`scan`, `dns`, `traceroute`, `exchange`, `fuzz`,
   connect) re-implements the same dispatch: hand-assemble a
   `PolicyAuthorizer` and `CancellableClock`, then branch on the negotiated
   output format to pick `run_with_events` (NDJSON) or `run` (aggregate),
   then render — including a dead `Ndjson => Internal` arm in every copy.
   The copies have already drifted: `fuzz` checks cancellation inside its
   event callback and the others do not. Because each command constructs
   system types inline, these run bodies are only covered by process-level
   tests.
3. Every workflow engine re-implements admission ordering: resolve and
   authorize targets, reject empty/family-mismatched results, count units,
   compute worst-case duration, then call `approve_operation`.
   Authorization-before-discovery is the repository's core safety
   invariant, yet its sequencing is carried by convention across five
   engines, not enforced by an interface.

In each case the copy is orchestration mechanics — ordering, accounting,
plumbing — while the part that legitimately differs per call site (event
shapes, budget arithmetic, wire rendering) is small.

## Solution

Deepen three seams so each copied lifecycle lives in one module with a
small interface, and call sites supply only what varies:

1. **`analysis::Session`** (packetcraftr-core) — owns analysis preparation
   including requirements→Plan narrowing, the observe/finish loop over a
   capture reader, IP-event forwarding, trailing-event drain, and the
   empty-selector verdict. Commands supply a collector and an event sink.
2. **`execution::run_workflow`** (packetcraftr-cli) — owns the
   format-driven dispatch between `run_with_events` and `run`, event
   emission, the terminal record, and the dead-arm elimination.
   `Providers` vends the authorizer and clock its assembly already
   implies. Commands supply hooks: the two engine entry points, an
   event-to-wire adapter, a report-to-result adapter, and a text renderer.
3. **`admit_operation`** (packetcraftr `target`) — owns the
   resolve→authorize→count→worst-case→approve ordering. Engines supply
   only their budget arithmetic per resolved address set.

User-visible behavior is preserved: same CLI output, same exit codes, same
machine-output contract. The one deliberate delta is that cancellation
during event emission becomes consistent across live commands (today only
`fuzz` has it).

## User Stories

1. As a maintainer adding a new application-layer command, I want to supply
   only a collector and an event sink, so that I cannot get the
   observe/finish ordering wrong.
2. As a maintainer fixing a collector-lifecycle ordering bug, I want the
   fix to land in one module, so that every analysis command benefits at
   once.
3. As a maintainer, I want filter requirements to narrow the analysis plan
   inside the session, so that commands stop running pipeline stages they
   do not need.
4. As a CLI user running `pcr http --stream tcp:9` against a capture
   without that conversation, I want the same "not present" verdict from
   every analysis command, so that behavior does not depend on which
   command I picked.
5. As an agent writing tests, I want to drive the collector lifecycle
   against a scripted frame sequence, so that I do not need to spawn the
   binary to reach the logic.
6. As a maintainer adding a new live command, I want the format dispatch
   (stream vs collect) to come from one driver, so that my command gets
   NDJSON events, a terminal record, and aggregate rendering without a
   copied branch.
7. As a maintainer, I want the dead "NDJSON returned before aggregate"
   arm to exist at most once, so that unreachable code stops multiplying.
8. As a maintainer, I want the choice of resolver and clock for live
   commands to be made once by provider composition, so that swapping the
   system resolver does not mean editing five call sites.
9. As a CLI user pressing Ctrl-C during a live command's event stream, I
   want every command to honor cancellation during emission, not just
   `fuzz`.
10. As a maintainer adding a new workflow, I want admission ordering —
    authorize the declared target, then resolve, then approve the whole
    budget — enforced by the interface I call, so that the safety
    invariant is structural rather than conventional.
11. As a reviewer, I want engines to contain only their budget arithmetic
    at admission time, so that I can see at a glance that ordering is not
    re-litigated per workflow.
12. As a maintainer, I want admission-ordering tests to live beside the
    admission module with fake authorizers, so that regressions are caught
    without sockets or fixtures from five engines.
13. As a maintainer, I want each deepened module's tests to assert
    observable behavior through its interface, so that future internal
    refactors do not break the suite.
14. As a maintainer, I want existing process-level contract tests to keep
    passing unchanged, so that the refactors are provably
    behavior-preserving.
15. As a maintainer, I want unit tests that exercised only the duplicated
    plumbing (not real per-command behavior) deleted once the deepened
    module's interface tests exist, so the suite does not carry redundant
    coverage.
16. As a library consumer of packetcraftr-core, I want the analysis
    session interface to be usable without the CLI, so that embedding the
    collector lifecycle does not require copying CLI internals.
17. As a maintainer, I want no new external seams introduced — the
    injected pieces are in-process closures and existing fake providers —
    so the change adds depth, not indirection.
18. As a maintainer, I want the machine-output contract and its schemas
    untouched, so that downstream consumers see a pure refactor.

## Implementation Decisions

- **`analysis::Session` in packetcraftr-core** is the deep module for the
  collector lifecycle. Its interface accepts a capture reader, the prepared
  analysis state (registry, filter, time bounds, limits), an optional
  selector, a collector implementing the existing
  `new → observe(&FrameRecord) → finish(&Summary)` lifecycle, and an event
  sink. It returns the run summary plus collector output and trailing
  events. Internally it owns: requirements→Plan narrowing (a filter's
  declared requirements select pipeline stages instead of defaulting to
  all stages on), the `run_with_ip_events` drive, the trailing drain, and
  the selector-matched-nothing verdict. The informal collector lifecycle
  becomes a named contract on the session interface.
- **`execution::run_workflow` in packetcraftr-cli** is the deep module for
  live-command dispatch. Its interface accepts the composed providers, the
  negotiated format, the stream encoder, and a hooks record: `run`,
  `run_with_events`, `on_event` (engine event → wire event), `into_result`
  (engine report → contract result + diagnostics + stats), `render_text`,
  and `complete` (summary → terminal record). It owns the NDJSON/aggregate
  branch, cancellation inside event emission, and the terminal record. The
  unreachable aggregate-arm disappears because the driver picks the entry
  point before rendering.
- **`Providers` gains a session facet** in packetcraftr-cli: methods that
  vend the `PolicyAuthorizer` (constructed over the composed policy and
  system resolver) and the `CancellableClock` (over the installed
  cancellation signal). Commands stop constructing these by hand.
- **`admit_operation` in packetcraftr `target`** is the deep module for
  operation admission. Its interface accepts the authorizer, the deadline,
  the gate-error adapter, the declared target set, and a closure mapping
  resolved addresses to the operation's budget (unit count, worst-case
  wire bytes, worst-case duration). It owns resolution ordering, the
  empty/family gate, and the `approve_operation` call. Engines keep their
  bytes-per-unit arithmetic, which legitimately differs (ICMP vs
  port-count endpoints, UDP payload profiles, campaign sizing).
- **No new external seams.** All injected pieces are in-process closures
  or generics over existing traits. The fake providers already used in
  crate tests serve as the second adapter proving each seam is real.
- **Deliberately untouched**: the codec and pcap wire modules (fidelity
  contract requires explicit wire structure); the `Command` dispatch arms
  (one line each is correct locality); the `Format → per-command format`
  narrowing (load-bearing machine-contract seam); `system/` single-adapter
  providers (the real seam is the netio traits); DNS retry/TCP fallback,
  replay's exact-wire authorization, and exchange correlation (workflow
  semantics, not mechanics); `route::Plan`'s public fields (moving their
  semantics toward netio was rejected — preparation belongs to the
  workflow crate).
- **Consistent cancellation** inside event emission is the single
  sanctioned behavior change: every live command gains the check `fuzz`
  already performs.
- **No ADR conflicts**: `docs/adr/` does not yet exist; nothing here
  re-litigates a recorded decision.

## Testing Decisions

- A good test asserts observable behavior through the deepened module's
  interface — event order, emitted records, verdicts, authorization call
  order — never internal state or private helpers. Tests must survive
  internal refactors; anything that breaks when the implementation moves
  was testing past the interface.
- **`analysis::Session`**: unit tests beside the module drive scripted
  frame sequences through fake collectors (record `observe` calls, emit
  scripted trailing events) and in-memory capture fixtures. Assert: the
  lifecycle order, the trailing drain, the empty-selector verdict, and
  that a filter's requirements narrow the plan. Prior art: the crate's
  `tests/common` capture fixtures and the `pipeline_limit_contracts`
  tests, which move to the session interface where they covered
  orchestration rather than limits.
- **`execution::run_workflow`**: unit tests with recording fake hooks
  cover every negotiated-format path — NDJSON streams events then a
  terminal record; aggregate paths render text or emit the aggregate;
  cancellation during emission propagates. Prior art: the fake
  `Authorizer`/`Transmitter`/`Clock` already used by `replay` rendering
  tests; process-level `process_contracts` tests remain the outer net.
- **`admit_operation`**: unit tests beside `target` with a recording fake
  authorizer assert the call order (target authorization before budget
  approval), each gate's error short-circuits before approval, and
  `GateErrors` adapters surface workflow-specific error kinds. Prior art:
  `probe` test fixtures and the injected `Clock`/`Executor` fakes.
- **Replace, don't layer**: keep the crates' public-behavior contract
  tests untouched as the regression net; delete unit tests that only
  re-exercised the duplicated plumbing once interface-level tests exist.
- **Seams**: all three test at the highest seam available — the new
  module interfaces inside their owning crates — using existing in-memory
  fixtures and fake adapters. No new ports, no process-level tests added.

## Out of Scope

- The remaining review candidates: the bounded frame loop for the read
  family (`BoundedFrames`), staged multi-packet preparation
  (`prepare_all`), the progressive execution context, the scan/traceroute
  batch-evidence adapter, and the `Command` descriptor table. Each is a
  separate follow-up if it proves out.
- Any change to the machine-output contract: wire types, format sets,
  schemas, and `packetcraftr.output/v6` stay identical.
- Workflow semantics: budget arithmetic, authorization policy, retry and
  fallback behavior, evidence rules.
- New external seams or ports; all injection stays in-process.
- Renames or module moves beyond the three deepenings.

## Further Notes

- Origin: an architecture review of the recent hot spots (CLI command
  modules, workflow engines, the analysis pipeline). The collector-loop
  candidate was found independently by two passes, which is why it leads.
- No root `CONTEXT.md` or `docs/adr/` exist yet; vocabulary follows the
  AGENTS.md domain language (capture, frame, collector, workflow, engine,
  authorizer, provider, evidence, preparation, machine-output contract).
- The provider-facing crates are untouched: `packetcraftr-netio` contracts
  and platform dispatch are already clean seams and stay as they are.
