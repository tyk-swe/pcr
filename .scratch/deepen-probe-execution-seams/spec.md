# Deepen the probe execution seams: batch evidence, execution context, staged preparation

Status: ready-for-agent

## Problem Statement

A maintainer working in the live workflow engines (scan, traceroute, dns,
fuzz, replay, send, exchange) keeps meeting three copied lifecycles. Each
copy is orchestration mechanics that has drifted between call sites:

1. **Batch evidence.** Scan and traceroute each have about 200 lines of
   the same batch-evidence routines: the pass-through `ProbeLifecycle`
   impl, the batch processor (permit check, diagnostics, response
   selection, per-probe loop, emit), probe classification, response
   retention, undecoded retention, and diagnostic publishing. Scan's
   pipelined path skips the runner and ranks responses its own way. It
   repeats the `rank()*4 + profile` formula, but a later response
   replaces the current one only when its rank is strictly higher, so on
   a tie the first arrival wins. The serial path breaks ties by
   responder, then latency, then bytes. The same captured evidence can
   therefore produce a different winning probe outcome depending on
   whether the scan was pipelined. DNS and fuzz assemble their own
   evidence state from the 17 low-level helpers the evidence module
   exports.
2. **Execution context.** Five places copy the same pacing sequence: the
   probe runner, fuzz, dns, the DNS batch runner, and replay. The
   sequence is: start accounting the delay, sleep, check, surface a clock
   failure, account, and add the scheduled delay. After sleeping, the
   probe runner checks both elapsed time and cancellation. The other four
   check only cancellation, so when a clock failure and a spent deadline
   happen together, the reported error depends on the workflow. The
   single execution step has three copies with three different orders.
   The step is: clip the timeout, issue a permit, run the executor behind
   deadline checks, check the permit, validate evidence, merge stats,
   and account elapsed time. DNS merges stats before surfacing an
   interruption, the runner accounts time before validating, and fuzz
   checks the permit first. Fuzz's tests have to fill in every field of a
   private execution-phase struct to reach this logic, and they mirror
   the runner's tests one for one.
3. **Staged preparation.** The chain count-only budget → plan →
   preliminary authorization → cumulative wire budget → materialize (may
   emit neighbor discovery) → final authorization → transmit → sent
   packet is copied four times in the workflow crate: single send,
   `send_set`, exchange, and the scan pipeline. The block that turns
   cumulative-byte overflow into `ByteLimit` is copied three times. Fuzz
   re-derives route materialization to check that its executor sent the
   expected bytes, and its tests build those steps by hand a third time.
   The CLI's `send` and `exchange` commands each copy an eight-step
   pre-discovery sequence (option validation, policy validation, budget
   count, destination authorization, route preparation), and the copies
   have drifted. Policy validation runs twice per path, and the two
   commands validate options in a different order relative to recipe
   parsing. "Authorization before active discovery; final endpoint and
   bytes checked before transmission" is the repository's core safety
   invariant, but it is kept by convention across these copies instead
   of being enforced by an interface.

The part that legitimately varies at each call site is small: how a
workflow classifies and ranks a response and builds its evidence; the
workflow's error type; the work a step performs; and the budget count.

## Solution

Deepen three seams in the `packetcraftr` crate, plus the matching CLI
preparation step, so each lifecycle lives in one module with a small
interface and callers supply only what varies:

1. **Batch evidence in the probe runner.** The existing probe-runner seam
   takes over batch-evidence processing for scan and traceroute. Each
   workflow supplies a classifier hook: classify a response, rank it,
   build the probe's evidence, and decide whether the batch is terminal.
   Serial and pipelined scan both go through the same processing and the
   same candidate ordering. `EvidenceState` and the response selector
   become the only evidence interface.
2. **Execution context.** One in-process, crate-level module owns the
   operation deadline, the clock, pacing, scheduled-delay accounting,
   execution permits, timeout clipping, and stats merging. The probe
   runner, fuzz, dns, the DNS batch runner, and replay drive their work
   through it. Each supplies an error adapter, in the style of
   `GateErrors`, and the work of each step.
3. **Staged preparation.** The client's preparation seam becomes one
   module that takes packets and a budget and enforces the stage order.
   It has two orders: *all-before-discovery* for exchange and the scan
   pipeline, and *streaming* for `send_set`. Fuzz checks its executor's
   bytes through the same module. On the CLI side, `send` and `exchange`
   share one pre-discovery preparation step and supply only their budget
   count.

User-visible behavior is preserved apart from the sanctioned changes
listed under Implementation Decisions: the same commands, exit codes,
machine-output schemas, and `packetcraftr.output/v6` contract.

## User Stories

1. As a maintainer adding a new probe workflow, I want to supply only
   classification, ranking, evidence construction, and a terminal check,
   so that I cannot get batch-evidence ordering wrong.
2. As a maintainer fixing a bug in response selection or retention, I
   want the fix to land in one module, so that scan and traceroute both
   benefit at once.
3. As a CLI user running `pcr scan` with pipelining enabled, I want the
   same winning response a serial scan would pick from the same
   captured evidence, so that results don't depend on execution mode.
4. As a CLI user, I want tie-breaking between equally ranked responses to
   follow one documented rule (responder, then latency, then bytes), so
   that repeated runs over the same capture agree.
5. As a maintainer, I want the pipelined scan's completed-probe events to
   go through the same batch-evidence processing as serial batches, so
   that permit checks, diagnostics order, and retention match.
6. As a maintainer, I want `EvidenceState` and the response selector to
   be the only evidence interface, so that DNS and fuzz stop
   reassembling budgets, undecoded retention, and diagnostic logs by
   hand.
7. As a reviewer, I want scan and traceroute engines to contain only
   workflow-specific classification and evidence shapes, so that I can
   see at a glance where they really differ.
8. As an agent writing tests, I want to drive batch-evidence processing
   through the runner with a fake executor and a fake classifier, so
   that the test exercises the real validation path and not a fixture's
   copy of it.
9. As a maintainer, I want the scan and traceroute event-collection tests
   that check the same behavior to become one test at the runner
   interface, so that the suite has no duplicate coverage.
10. As a maintainer adding a paced workflow, I want pacing (delay
    accounting, sleep, deadline and cancellation checks, clock-failure
    reporting, scheduled delay) to come from one execution context, so
    that I cannot reorder those checks by accident.
11. As a CLI user pressing Ctrl-C or hitting `--max-duration` during a
    paced delay, I want the same error classification from every live
    command, so that scripts can handle interruption uniformly.
12. As a maintainer, I want every execution step to check the returned
    permit immediately, before any evidence is consumed, so that evidence
    from a different execution can never be charged or published.
13. As a maintainer, I want stats from an execution that reached the wire
    to be merged before a boundary interruption is surfaced, in every
    workflow, so that accounting stays faithful to traffic that was
    actually sent.
14. As a maintainer, I want timeout clipping against the remaining
    operation budget to happen in one place, so that no executor can be
    handed a timeout longer than the operation has left.
15. As an agent writing fuzz tests, I want to drive the fuzz campaign's
    pacing and execution through the execution context's interface, so
    that I no longer build a private phase struct field by field.
16. As a maintainer, I want the probe runner's and fuzz's mirrored pacing
    tests to exist once, beside the execution context, so that one change
    doesn't need edits in two suites.
17. As a maintainer, I want each workflow's error type to be produced
    through a small adapter, so that the execution context stays generic
    while errors stay workflow-specific and typed with their original
    sources.
18. As a maintainer, I want DNS retry/TCP fallback and the DNS batch
    runner's unattempted-vs-failed classification to stay in DNS, so that
    only mechanics move and workflow semantics don't.
19. As a maintainer adding a live command that transmits more than one
    packet, I want one preparation module to enforce the stage order, so
    that authorization before discovery is structural rather than
    conventional.
20. As a security reviewer, I want every packet in an exchange or scan
    pipeline to pass its preliminary packet, route, permissive-build, and
    cumulative-budget checks before any neighbor discovery runs, so that
    a later rejected packet never follows discovery traffic.
21. As a CLI user of `pcr send --repeat`, I want frames to keep streaming
    as they are confirmed, so that evidence published before a failure is
    preserved and large repeat sets don't have to be held in memory.
22. As a security reviewer, I want every streamed packet to still be
    authorized before its own discovery and checked for final endpoint
    and bytes before transmission, so that streaming mode doesn't weaken
    the invariant.
23. As a maintainer, I want the cumulative-bytes overflow to become one
    `ByteLimit` check inside the preparation module, so that the three
    copies can't drift.
24. As a maintainer of the scan pipeline, I want the check that
    send-time re-preparation matches the admitted cost to live inside
    the preparation module, so that the pipeline's bounded-memory
    rebuild path can't skip it.
25. As a maintainer of fuzz, I want the expected exact bytes for a packet
    on a given route to come from the preparation module, so that fuzz's
    executor check can't diverge from what was actually prepared.
26. As an agent writing fuzz tests, I want to stop hand-building route
    materialization steps, so that fixtures don't encode a third copy of
    the preparation rules.
27. As a maintainer of the CLI, I want `send` and `exchange` to share one
    pre-discovery preparation step that differs only in the budget count,
    so that option validation, policy validation, destination
    authorization, and route preparation run once and in the same order.
28. As a CLI user, I want option validation to run before recipe parsing
    for both `send` and `exchange`, so that invalid options fail before
    any hostname or interface work.
29. As a maintainer, I want policy validation to run exactly once per
    command, so that validation cost and error sites aren't duplicated.
30. As a maintainer, I want the existing netio route, neighbor, and
    transmit ports (with their system adapters and the test-support
    fakes) to remain the only seams under preparation, so that no new
    ports are introduced.
31. As a maintainer, I want every deepened module's tests to assert
    observable behavior through its interface (event order, emitted
    evidence, error kinds, provider call order), so that internal
    refactors don't break the suite.
32. As a maintainer, I want the crates' existing public-behavior contract
    tests and the CLI's process-level tests to keep passing, apart from
    assertions that pin a sanctioned behavior change, so that the
    refactor is shown to preserve behavior.
33. As a maintainer, I want unit tests that only exercised the copied
    plumbing deleted once interface-level tests exist, so that the suite
    doesn't carry redundant coverage.
34. As a downstream consumer of the machine output, I want schemas and
    wire types untouched, so that the change is invisible apart from the
    sanctioned tie-break and error-order fixes.

## Implementation Decisions

### Batch evidence (probe runner)

- The existing probe-runner module stays the seam and is deepened. Its
  interface keeps running already-approved batches, and it now also owns
  batch-evidence processing: the permit check, diagnostic recording
  and publishing order, response selection through the shared selector,
  retention of winning responses, undecoded retention with its diagnostic
  fallback, and the per-probe emit order.
- The workflow-owned hook narrows from `execute / validate / process` to
  a classifier: classify one response against a sent probe, rank that
  observation, provide the tie-break responder, build the probe's
  evidence (timeout or response outcome), map retained frames and
  diagnostics to the workflow's events, and say whether the batch ends
  the operation. `execute` and `validate` stop being hooks: the executor
  is passed to the runner, and batch-evidence validation is the runner's
  job.
- Scan uses the shared batch type. Its separate single-probe batch type
  and its own batch-plan impl go away, along with the slice-of-one and
  single-item iterator adaptations at the call sites.
- The pipelined scan path sends its completed-probe events through the
  same batch-evidence processing the serial path uses. The pipeline
  executor's in-flight "best so far" choice uses the same candidate
  ordering as the serial selector.
- **Sanctioned behavior change:** there is one tie-break rule, the serial
  one: rank, then responder, then latency preference, then bytes. The
  pipelined scan's first-arrival-wins behavior on ties goes away.
- `EvidenceState` plus the response selector become the evidence
  module's only interface. The low-level retention, undecoded-retention
  and best-candidate helpers become private to it. DNS and fuzz move onto
  `EvidenceState`, which replaces DNS's field-for-field copy and fuzz's
  separate budget and diagnostic log, and DNS's redundant pre-check
  before candidate selection disappears.

### Execution context

- A new crate-level, in-process module (not under `probe`, because
  replay and dns are not probe-runner workflows) owns the progressive
  execution mechanics: the operation `Deadline`, an injected `Clock`,
  pacing between steps, scheduled-delay accumulation and its addition to
  elapsed stats, issuing a fresh execution permit per step, clipping the
  step timeout to the remaining budget, and checked stats merging.
- The error adapter follows the `GateErrors` pattern: a small trait
  mapping duration-limit, interruption, clock failure, execution
  failure, invalid evidence (permit mismatch), and statistics overflow
  to the workflow's own typed error, keeping the original sources.
- The step is supplied as a closure that gets the clipped timeout and the
  permit and returns an execution carrying its permit and stats, plus a
  validation closure. The context owns the order around them.
- **Canonical pacing order (sanctioned change for fuzz, dns, dns batch,
  replay):** check → start accounting the delay → sleep → check both
  deadline and cancellation → surface any clock failure → account the
  delay → add the scheduled delay.
- **Canonical step order:** check → start accounting → clip timeout →
  issue permit → execute → observe interruption → surface execution
  failure → check permit → validate evidence → merge stats → surface the
  interruption observed after execution → account elapsed → check. The
  merge-before-surfacing rule comes from DNS, whose rationale applies to
  every workflow: traffic that reached the wire is accounted even when
  the operation stops at that boundary. The probe runner, scan,
  traceroute and fuzz adopt it; that is a sanctioned change.
- *Amendment (implementation):* when an execution fails and an
  interruption was observed at the same boundary, the interruption is
  reported rather than the execution failure. The failure is usually a
  consequence of the cancellation or spent deadline. DNS and fuzz already
  behaved this way, and user story 11 (uniform interruption
  classification) needs it. The probe runner's former failure-first
  behavior is the sanctioned change, and it is recorded under
  `[Unreleased]`.
- Pacing inputs stay workflow-owned: the probe runner's rate from the
  previous batch size, fuzz's cases-per-second, DNS's retry delay, the
  DNS batch runner's max-of-previous-and-current delay, and replay's
  source-timing delay. The context takes the delay; it does not compute
  it.
- The DNS batch runner's mapping of pacing failures to
  unattempted-vs-failed questions, and DNS retry/TCP fallback, stay in
  DNS.
- The probe runner is rebuilt on the execution context, so batch-evidence
  processing (above) sits on top of it.

### Staged preparation

- The client's preparation seam becomes one module with a small
  interface. It takes an expansion of packets, the send options, the
  deadline, and the operation's packet count for the count-only budget,
  and runs one of two orders:
  - **All-before-discovery:** every packet passes planning, preliminary
    build, MTU, packet and wire authorization, and the cumulative wire
    budget before any materialization. Exchange and the scan pipeline use
    it. Internally, prepared packets are either kept (exchange) or
    rebuilt at send time under the prepared-bytes limit (scan pipeline).
    The check that the rebuild matches the admitted cost is part of the
    module.
  - **Streaming:** each packet passes its preliminary checks and the
    cumulative budget, then is materialized, finally authorized, and
    transmitted before the next packet is planned. `send_set` uses it, so
    frames keep being emitted as they are confirmed and repeat passes
    re-expand. Single send is streaming with one packet.
- In both orders the module owns the final endpoint and bytes check
  immediately before transmission, the transmit call, the `SentPacket`
  construction, and the cumulative-bytes overflow → `ByteLimit` mapping.
- The module exposes a deterministic "exact bytes for this packet on this
  route" operation that uses the same materialization rules. Fuzz checks
  its executor's bytes through it instead of re-deriving materialization.
- The ports stay `route::Provider`, `neighbor::Resolver` and
  `transmit::Sender`. The system adapters and the test-support fakes are
  the two adapters that make these real seams. No new port is added.
- **CLI:** `send` and `exchange` share one pre-discovery preparation step
  in the CLI: validate options before recipe parsing, parse the recipe,
  build the template, validate policy once, authorize the budget count,
  authorize the expanded destinations, and prepare the packet route.
  Each command supplies only its budget count: `send` counts repeats
  through its set options, and `exchange` uses the expansion length. The
  CLI's `system/` single-adapter providers stay as they are (an earlier
  decision).

### Cross-cutting

- No new external seams. Everything injected is an in-process closure, a
  small adapter trait, or an existing netio port.
- The machine-output contract (wire types, format sets, schemas,
  `packetcraftr.output/v6`) is unchanged. Sanctioned behavior changes:
  the single tie-break rule, the canonical pacing order, and the
  canonical step order. Record them under `[Unreleased]` in the
  changelog.
- Suggested dependency order for tickets: the execution context first,
  then batch evidence on top of it; staged preparation is independent of
  both.

## Testing Decisions

- A good test asserts observable behavior through the deepened module's
  interface: emitted events and their order, the winning evidence,
  retained frames and diagnostics, error kinds and their sources,
  provider call order, and bytes handed to transmit. It never asserts
  private state or helper internals. A test that breaks when the
  implementation moves was testing past the interface.
- **Batch evidence:** tests beside the probe runner drive batches with a
  fake executor returning scripted executions and a fake classifier.
  Assert:
  - the permit-mismatch rejection;
  - diagnostics published before each probe's event;
  - the tie-break rule, including the case that used to differ between
    pipelined and serial;
  - retention limits and the undecoded fallback diagnostic;
  - terminal batches ending the operation.

  Prior art: the probe runner's existing fake-lifecycle tests (whose
  fake reimplements validation, and is replaced) and the evidence
  module's own tests, which move to testing through `EvidenceState`.
  The scan and traceroute tests that both check event collection
  preserves stats, diagnostics and evidence limits merge into one runner
  test. The scan pipeline contract tests remain the outer net for the
  pipelined path.
- **Execution context:** tests beside the new module use the existing
  `RecordingClock` and `Deadline::with_time_source`. Assert:
  - the canonical pacing order when the clock fails and the deadline is
    spent at the same boundary;
  - cancellation during a sleep;
  - scheduled delay added to elapsed stats;
  - timeout clipping to the remaining budget;
  - the permit mismatch failing before validation;
  - stats merged before a post-execution interruption surfaces;
  - stats overflow mapped through the adapter.

  Prior art: the probe runner's pacing and child-timeout tests and fuzz's
  mirrored run tests. Both sets collapse into this suite.
- **Staged preparation:** tests go through the client with the
  test-support netio fakes (fixed routes, a neighbor resolver that
  records calls, a transmitter that records frames). Assert:
  - in all-before-discovery order, a packet rejected by policy late in
    the expansion triggers no neighbor call;
  - in streaming order, each packet is authorized before its own
    discovery and frames are emitted as they are confirmed;
  - cumulative-byte overflow surfaces as `ByteLimit`;
  - a rebuild that doesn't match the admitted cost is rejected;
  - the exact-bytes operation matches what was transmitted.

  Prior art: the `send_set`, exchange-failure and scan-pipeline contract
  tests, and the shared netio fakes in the crate's test support.
- **CLI preparation:** unit tests on the shared step with an invalid
  option and an invalid recipe assert that options fail first for both
  commands. The CLI process contract tests remain the outer net.
- **Replace, don't layer:** keep public-behavior contract tests as the
  regression net. Delete unit tests that only re-exercised the copied
  plumbing once interface-level tests cover it. This includes fuzz's
  hand-built materialization fixture.
- **Seams:** each deepened module is tested at its own interface, the
  highest seam available inside its owning crate. No new process-level
  tests are needed.

## Out of Scope

- The other candidates from the same architecture review:
  - the CLI offline analysis driver;
  - moving TCP connection generation into the reassembler;
  - `Plan` owning requirements narrowing;
  - capture sessions with one finish step;
  - the application-collector byte ledger;
  - the bounded offline capture source for the read family.
- The `run` / `run_with_events` / `run_observed` entry-point trio,
  repeated in five workflows; a separate follow-up.
- The unfinished parts of the earlier `run_workflow` driver work: connect
  and fuzz still hand-build the authorizer and clock, and exchange keeps
  a dead aggregate render arm.
- Workflow semantics: budget arithmetic, `admit_operation` admission
  ordering, DNS retry/TCP fallback, replay's exact-wire authorization,
  exchange correlation, and evidence classification rules.
- The CLI's `system/` single-adapter providers and any change to netio
  provider contracts or platform dispatch.
- Any machine-output contract change.

## Further Notes

- Origin: the 2026-09-22 architecture review of recent hot spots. Scan
  and traceroute engines are among the most-churned files in the
  workflow crate. Staged preparation was found independently from both
  the workflow side and the CLI side.
- Behavior decisions confirmed with the maintainer:
  - these three test seams;
  - keeping `send_set` in streaming mode rather than forcing
    all-before-discovery;
  - including the CLI's shared preparation step.
- There is no root `CONTEXT.md` or `docs/adr/` yet, so nothing here
  re-opens a recorded decision. New terms this spec introduces are
  *batch evidence*, *execution context*, *staged preparation*,
  *all-before-discovery order* and *streaming order*. They are
  candidates for the glossary once it exists.
- Separate from this spec: the review also found that DNS checks
  `max_retained_bytes` against two independent counters, so the
  effective ceiling is about twice the documented one. It deserves its
  own bug ticket and regression test.
