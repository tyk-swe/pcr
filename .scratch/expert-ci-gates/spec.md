# Expert analysis gates for CI

Status: ready-for-agent
Feature ID: GATE
Parent: [offline investigation batch](../offline-investigation/spec.md)
Implementation: not started; this session is specification-only.

## User behavior

```console
packetcraftr expert capture.pcapng --fail-on warning
packetcraftr --output json expert capture.pcapng --fail-on warning --allow-findings 2 --minimum-frames 20
packetcraftr --output ndjson expert capture.pcapng --filter 'tcp.stream == 3' --fail-on error
```

Add three options to `expert`:

| Flag | Type/default | Rule |
| --- | --- | --- |
| `--fail-on info|warning|error` | Optional severity, absent by default | Presence enables a gate |
| `--allow-findings N` | u64, default 0 when gate enabled | Explicit use requires `--fail-on`; at most N triggering findings may pass |
| `--minimum-frames N` | Positive u64, default 1 when gate enabled | Explicit use requires `--fail-on`; N is minimum matched physical frames |

These are analysis criteria, not resource ceilings. Do not add them to resource
presets or use them to stop input early. No per-code gate, threshold file,
percentage, live-capture mode, or CI service integration is included.

Without `--fail-on`, preserve current successful expert exit 0, existing text,
and selected finding counters; v7 includes `gate: null`. Empty input remains
successful without a gate. Clap/help validation of dependencies occurs before
input opens, including when the explicitly passed allowance equals zero.

## Finding domain and verdict

The gate sees **every finding produced by the selected expert analysis**,
including decode diagnostics, capture evidence, and EOF/trailing TCP findings,
before `--min-severity`, `--code`, or aggregate retention. Existing packet
`--filter` and epoch bounds select per-frame observations; capture-global
reassembly/indexing and EOF finding behavior are unchanged. Specifically,
`tcp.incomplete_at_end` at EOF can describe a filtered-out pending flow, have
`stream: null`, and be attributed to the final physical input frame. It still
reaches the gate. Do not reimplement filtering, invent missing findings, or
silently suppress these existing EOF findings.

For each event increment `findings_observed` once. Increment
`triggering_findings` when its severity is at least `fail_on`. Thus `warning`
includes warnings and errors; `info` includes all severities. A physical frame
can yield several independent findings; count them individually. Gate counts
are not derived from selected counters or retained JSON findings.

Evaluate only after `Session::run` has emitted all finishing events and
succeeded. The truth table, in priority order, is:

| Condition | Verdict | Reason | Exit after successful report publication |
| --- | --- | --- | --- |
| triggering_findings > allow_findings | `fail` | `finding_allowance_exceeded` | 1 |
| Otherwise frames_matched < minimum_frames | `inconclusive` | `insufficient_frames` | 1 |
| Otherwise | `pass` | `within_allowance` | 0 |

An observed violation wins over insufficient coverage. Equality with allowance
and minimum-frame criteria passes. An enabled gate on an empty match set is
inconclusive unless actual emitted violations already make it fail.

`pass` establishes only the requested predicate over emitted findings and
matched-frame coverage. It does not claim complete observation, error-free
traffic, absence of packet loss, or network health. An incomplete reassembly
is handled only when it produces an existing expert finding, at its actual
severity; it does not create a new implicit inconclusive rule. In particular,
incomplete IP datagrams can appear solely in the IP lifecycle/report stream,
without an expert Finding. Such an incomplete datagram alone does not fail
even an info gate. Header decoding/byte-completeness requirements need their
own assertions; they are not silently added to this feature's predicate.

Report selectors remain independent. For example, `--min-severity error
--fail-on warning` may print no findings while returning fail for warnings;
the gate report exposes complete observed/triggering counts. A misspelled
existing `--code` selector can hide detail but cannot suppress a gate violation.

## Core API and placement

Add public `analysis::expert::gate` at `analysis/expert/gate.rs`; no CLI exit
status or serialized DTO belongs there. Public API:

```rust
pub struct Options {
    pub min_severity: diagnostic::Severity,
    pub allow_findings: u64,
    pub minimum_frames: u64,
}
pub struct Gate { /* private validated options and counters */ }
impl Gate {
    pub fn new(options: Options) -> Result<Self, Error>;
    pub fn observe(&mut self, finding: &expert::Finding) -> Result<(), Error>;
    pub fn finish(self, frames_matched: u64) -> Report;
}
```

`Report` has the fields in Output below; `Verdict` and `Reason` are owned here
and mirrored by CLI enums. `Gate::new` rejects zero minimum_frames; any u64
allowance is valid. Use checked counter increments. Counter overflow is typed
`policy.expert_gate_limit`/Kind::Policy; invalid minimum is
`cli.expert_gate`/Kind::Usage. No unbounded per-finding/per-code detail is stored:
gate state is constant-sized. `Gate::finish` is called only for a completed
analysis, and cannot be used to reinterpret a pipeline error as a verdict.

Do not change the expert Collector or the meaning of `expert::Summary`.
This reusable evaluator can observe the collector's public finding stream.
CLI owns creation and callback order: gate.observe first, then existing output
selector/count/render. Gate errors short-circuit analysis with their source.

## Output and process status

Family v7 adds required `gate: null | GateReport` to the expert aggregate result
and NDJSON `complete`. Existing top-level notes/warnings/errors/codes/findings
continue to count only findings kept by existing report selectors.

All GateReport fields are required:

| Field | Type/meaning |
| --- | --- |
| `verdict` | `pass`, `fail`, `inconclusive` |
| `reason` | `within_allowance`, `finding_allowance_exceeded`, `insufficient_frames` |
| `min_severity` | `info`, `warning`, `error` |
| `allow_findings` | u64 configured allowance |
| `minimum_frames` | Positive u64 required coverage |
| `frames_matched` | u64 same physical matched count as outer report |
| `findings_observed` | u64 all events observed by gate |
| `triggering_findings` | u64 matching threshold, at most findings_observed |

Add CLI-owned DTOs in `output/expert.rs`, using conversions from the core
report. The schema constrains types/enums; behavioral conformance tests enforce
the truth table and consistency across counters/exit status. Do not emit a
new NDJSON data event: ordinary `finding` events remain report-selected,
terminal gate counts are exact regardless of streamed/retained details.

Text retains current findings and summary, then appends one line when enabled:
`gate=<verdict> reason=<reason> severity=<severity> triggering=<N> allowed=<N> frames=<N> required=<N>`.
Use the existing sanitizing writer. A completed fail/inconclusive publishes one
normal completed report and returns `CommandExit::status(1)`, as forwarding
verification does; no contradictory error envelope follows it.

Invalid input, duration/resource exhaustion, cancellation, conversion failure,
sink failure, or broken output remain existing classified execution failures.
No final gate report is fabricated for a partial run; cancellation before
publication remains 130 without a completed gate. Preserve the existing startup
rule for a signal arriving after successful report publication: it may return
130 after a completed report, and must not retract or contradict that report.
Rendering/publication errors take precedence over a would-be verdict exit code.
Result-retention omission affects details/diagnostics only, never gate counts.

## Acceptance cases

| ID | Input/options | Required observation |
| --- | --- | --- |
| EG01 | No fail-on, findings or empty capture | Legacy behavior, exit 0, gate null |
| EG02 | 1 info, 2 warnings, 1 error; all three thresholds | Trigger counts 4/3/1 respectively, all observed count 4 |
| EG03 | Trigger count below/equal/above allowance | Pass/pass/fail given sufficient frames |
| EG04 | Matched count below/equal/above minimum, no excess findings | Inconclusive/pass/pass |
| EG05 | Excess findings and insufficient frames together | Fail with allowance reason, not inconclusive |
| EG06 | Empty capture or zero matching frames with no triggering EOF findings, gate enabled | Inconclusive/exit 1, normal completed report |
| EG07 | min-severity/code hide the actual triggering findings | Selected counters/details unchanged; gate still fails with complete counts |
| EG08 | Several findings in one frame and aggregate retention omission | Each event counted; omitted details cannot change verdict |
| EG09 | Trailing TCP finding only emitted during finish | Gate includes it before evaluation |
| EG10 | Allowance/minimum flag without fail-on; zero minimum; invalid severity/overflowing integer | Usage error before capture I/O |
| EG11 | Malformed capture, input/analysis limit, deadline/cancellation before publication, sink failure | Execution error and no completed gate, correct existing exit classification |
| EG12 | Pass/fail/inconclusive in text/JSON/NDJSON | Correct counters/exit; contiguous sequences; exactly one complete; never complete then error |
| EG13 | Output cannot publish otherwise passing/failing result | Output failure wins over verdict exit |
| EG14 | Ordinary filters, epoch windows, derived datagrams, compressed/stdin input | Existing analysis domain is preserved; no synthetic physical frames |
| EG15 | Filter excludes pending TCP bytes so matched frames are zero, then EOF emits an info finding | Info gate with allowance 0 fails; warning gate is inconclusive; preserve null stream/final-frame attribution |
| EG16 | Matched physical IP fragments remain incomplete but yield no expert findings | Info gate passes with sufficient matched frames; separate IP evidence remains visible |

## Tickets

[GATE-01](issues/01-core-gate.md) implements the reusable evaluator.
[GATE-02](issues/02-cli-gate.md) integrates selectors/reporting/status and docs.

## Comments

Code-specific gating was deliberately excluded: existing expert findings also
include open decoder diagnostic codes, and guessing a closed code catalog would
make typo detection or extension behavior inconsistent. Severity plus explicit
allowance/coverage gives a complete useful contract without that ambiguity.
