# Core expert notes for `analysis::expert::gate` (GATE-01) + CLI integration (GATE-02)

Authority: `.scratch/expert-ci-gates/spec.md`; tickets `.scratch/expert-ci-gates/issues/01-core-gate.md`, `02-cli-gate.md`. All paths below are relative to repo root `/home/ubuntu/code/pcr/1/pcr`. Line numbers verified on branch `tyk/offline-investigation` (= main).

## 1. Spec contract (what to build, verbatim constraints)

- Public `analysis::expert::gate` at `crates/packetcraftr-core/src/analysis/expert/gate.rs` (spec lines 79-96):
  ```rust
  pub struct Options { pub min_severity: diagnostic::Severity, pub allow_findings: u64, pub minimum_frames: u64 }
  pub struct Gate { /* private validated options and counters */ }
  impl Gate {
      pub fn new(options: Options) -> Result<Self, Error>;
      pub fn observe(&mut self, finding: &expert::Finding) -> Result<(), Error>;
      pub fn finish(self, frames_matched: u64) -> Report;
  }
  ```
- `Report` fields (spec lines 117-128): `verdict` (pass/fail/inconclusive), `reason` (within_allowance/finding_allowance_exceeded/insufficient_frames), `min_severity`, `allow_findings`, `minimum_frames`, `frames_matched`, `findings_observed`, `triggering_findings`. `Verdict` and `Reason` are owned in core, mirrored by CLI enums.
- Truth table in priority order (spec lines 54-58): `triggering_findings > allow_findings` → `fail`/`finding_allowance_exceeded`/exit 1; else `frames_matched < minimum_frames` → `inconclusive`/`insufficient_frames`/exit 1; else `pass`/`within_allowance`/exit 0. Equality passes both criteria.
- Triggering = `finding.severity >= min_severity` (spec lines 46-48): `warning` counts warnings+errors; `info` counts all.
- `Gate::new` rejects zero `minimum_frames` → `cli.expert_gate`/`Kind::Usage`; any u64 `allow_findings` valid. Counter overflow → `policy.expert_gate_limit`/`Kind::Policy`. Checked increments required. Constant-size state: no per-finding/per-code storage (spec lines 99-104).
- `Gate::finish` is called only for a completed analysis — CLI calls it only after `Session::run` returned `Ok` (which includes the trailing drain, see §4).
- Do NOT change `expert::Collector` or `expert::Summary` (spec line 106). CLI owns ordering: `gate.observe(&finding)` first inside the event callback, then existing selector/count/render. Gate errors short-circuit analysis with their source.
- GATE-01 ticket adds: "Use owner unit support for unreachable counter-overflow construction if needed" — i.e., an in-module `#[cfg(test)]` helper may force counters to exercise the overflow error.
- Vocabulary: CONTEXT.md already defines "Analysis gate" (offline investigation section): "A declared predicate over the findings and frame coverage of a completed offline analysis... A passing gate establishes that predicate for the selected evidence, not the health or completeness of the observed network. Avoid: network health verdict, error (for a completed failing gate)."

## 2. Module map: `analysis::expert` today

`crates/packetcraftr-core/src/analysis.rs` (43 lines, whole file): `pub mod expert;` (line 21); re-exports `pub use session::{Collector, CollectorNeeds, Outcome, Pass, Session};` (line 42), `pub use stream::{Endpoint, StreamRef, StreamTransport};` (line 43), `pub use error::{Constraint, Error};` (line 36), `pub use pipeline::{ClockReport, Conversation, DerivedDatagram, FrameRecord, ..., Limits, Options, Plan, Summary, ..., run, run_with_ip_events};` (lines 37-41).

`crates/packetcraftr-core/src/analysis/expert.rs` (155 lines):
- Module decls (lines 19-23): `mod finding; mod generation; mod observation; mod selector; mod tcp;` — all private; only `pub use selector::Selector;` (line 25). Types `Finding`, `Summary`, `Collector` are defined in this file directly.
- Submodule files:
  - `expert/finding.rs` (311 lines): `pub(super) fn from_capture_evidence`, `from_diagnostics`, `new(...)` — capture.* findings + decode-diagnostic findings; `#[cfg(test)] mod tests` for `diagnostic_stream` attribution.
  - `expert/generation.rs` (88 lines): SYN/generation transitions for `DirectionState`.
  - `expert/observation.rs` (38 lines): `pub(super) struct TcpObservation<'a>` (number, `stream: Option<StreamRef>`, `flow: &'a ScopedFlowKey`, `tcp: &'a Tcp`, payload_len, syn/fin/rst/ack).
  - `expert/selector.rs` (80 lines): `pub struct Selector { pub min_severity: Severity, pub codes: Vec<String> }`, `pub fn matches(&self, finding: &Finding) -> bool` = `finding.severity >= self.min_severity && (codes empty || codes.contains(finding.code))` (lines 33-37). `Default` = keep everything.
  - `expert/tcp.rs` (108 lines): `DirectionState`, `Collector::reconcile_tcp_evictions`, `observe_tcp`; `mod acknowledgment/sequence/window`; `pub(super) use sequence::finish;`.
  - `expert/tcp/{acknowledgment,sequence,window}.rs`: per-condition finders.
- Self-named convention: `expert.rs` sits beside `expert/`; `tcp.rs` beside `tcp/`. `clippy::mod_module_files = "deny"` in root `Cargo.toml:28` — no `mod.rs` allowed. Precedent for a nested public path: `analysis/reassembly.rs` has `pub mod ip; pub mod tcp;` + private `mod expiry;` — so `pub mod gate;` inside `expert.rs` is the shape for `analysis::expert::gate`. Alternatively keep `mod gate;` private and `pub use gate::{...}` flat — but spec explicitly says "public `analysis::expert::gate` at `analysis/expert/gate.rs`", i.e. a public *module* path like `analysis::expert::gate::{Options, Gate, Report, Verdict, Reason, Error}` (GATE-01 line 10). Nested `pub mod` precedent exists (`analysis::reassembly::ip::engine`-style internals are private; `reassembly::tcp`/`reassembly::ip` are the public ones).
- Visibility markers used inside the tree: `pub(super)` for sibling-crate plumbing (`finding::new`, `sequence::finish` is `pub(in crate::analysis::expert)`, sequence.rs:248).

## 3. `Finding`, `Summary`, `Severity` types

`Finding` (expert.rs:41-53), NOT serde — a library type:
```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    /// Stable machine-readable code, such as `tcp.retransmission`; always a
    /// literal from the published set.
    pub code: &'static str,
    /// 1-based capture frame number that revealed the condition.
    pub number: u64,
    pub stream: Option<StreamRef>,
    pub message: String,
}
```
Field names differ from the wire DTO: `number` (core) ↔ `frame` (CLI DTO); `stream: Option<StreamRef>` where `StreamRef { transport: StreamTransport, index: u64 }` (`analysis/stream.rs:37-41`; `StreamTransport::{Tcp,Udp}`, `as_str` → "tcp"/"udp", serde snake_case). YES, findings can carry `stream: None` (capture.* findings always do — finding.rs:36, 53; diagnostics may too via `diagnostic_stream` returning `None`, finding.rs:148-180).

`Severity` (`crates/packetcraftr-core/src/diagnostic.rs:30-51`):
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity { Info, Warning, Error }
```
Ordered least→most severe (`Info < Warning < Error`, test at diagnostic.rs:124-127), `as_str()` → "info"/"warning"/"error", `display_via_as_str!`. Same enum the spec's `Options.min_severity` uses (`crate::diagnostic::Severity`, imported at expert.rs:8 as `use crate::diagnostic::Severity;`).

`expert::Summary` (expert.rs:55-78): `clock: ClockReport`, `findings`, `errors`, `warnings`, `notes: u64`, `codes: BTreeMap<&'static str, u64>`. `count()` at lines 69-77. NOTE: this summary counts ALL produced findings (collector counts before any selector). The CLI does not use `outcome.summary` at all — it recounts *selected* findings in its own `State` (§6).

## 4. How findings reach consumers (event stream; EOF ordering)

Two consumption APIs exist:

a) `session::Collector` trait (`analysis/session.rs:73-95`):
```rust
pub trait Collector {
    type Event;
    type Summary;
    fn needs(&self) -> CollectorNeeds;
    fn scopes(&self) -> Vec<Definition> { Vec::new() }
    fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Self::Event>, BoundaryError>;
    fn finish(self, run: &Summary) -> Result<(Vec<Self::Event>, Self::Summary), BoundaryError>;
}
```
`expert::Collector` implements it (expert.rs:132-155): `type Event = Finding; type Summary = Summary;` — inherent `observe` returns `Vec<Finding>` (infallible, wrapped `Ok`); `finish` returns `(Vec<Finding>, Summary)`. `needs()` (expert.rs:138-146) returns `CollectorNeeds { tcp_stream: true, udp_stream: true, ip_reassembly: true, tcp_events: true, ..Default }` — NOT `track_sources`.

`CollectorNeeds` (session.rs:38-60): `tcp_stream`, `udp_stream`, `ip_reassembly`, `tcp_events`, `track_sources`; `plan()` keeps `ip_reassembly` on whenever either index is declared ("canonical stream numbering follows reconstructed conversations"). `Session::new` unions `needs.plan()` with the filter's `requirements()` and also ORs `options.tcp_events |= needs.tcp_events` / `track_sources` (session.rs:199-211) — i.e. the collector contract already pins the record fields findings rely on.

`FrameRecord` (`analysis/pipeline.rs:62-86`) — one MATCHED frame, in capture order: `number: u64` (1-based, counting unmatched too), `timestamp: SystemTime`, `decoded: &DecodedPacket`, `derived_datagrams()` (private field, accessor line 213), `tcp: Option<TcpView>` / `udp: Option<UdpView>` (innermost, per-view; `TcpView.conversation: Option<Conversation>` where `Conversation{index, flow: &ScopedFlowKey}`, pipeline.rs:88-93), `tcp_events: &[TcpEvent]` ("reassembly events in delivery order, including expiry of other flows"), `clock_regression: Option<Duration>` (rollback vs capture high-water; detected for every physical frame, only matched carry it).

b) `Session` drives it (`session.rs`): `Session::new(registry, options, collector, selector)` (line 193) narrows `options.plan` from filter requirements + `CollectorNeeds` and raises `tcp_events`/`track_sources` (lines 199-211).
- `Session::run(reader, ip_sink, event_sink) -> Result<Outcome<C>, super::Error>` (lines 227-241) = `self.observe(...)` then `.finish(&mut event_sink)`.
- Per matched frame: `collector.observe(&record)` → each event → `event_sink(event)` (lines 259-265). An event-sink error mid-run surfaces as `analysis::Error::Sink { number, source }`.
- `Pass::finish` (lines 122-142): `collector.scopes()` captured FIRST, then `collector.finish(&self.run)` → trailing events drained through the SAME `event_sink` → errors here surface as `Error::Collector`. Only after the drain does it return `Outcome`.
- `Outcome<C>` (lines 150-167): `pub run: Summary` (the pipeline Summary), `pub summary: C::Summary`, `pub scopes`, `selected_absent()`.
- KEY for the gate: **trailing (EOF) findings arrive through the same event callback before `Session::run` returns**, so `gate.observe` in the CLI callback sees every finding — including `tcp.incomplete_at_end` — before `Outcome` exists. `gate.finish(outcome.run.frames_matched)` runs after `run` returns `Ok`. This satisfies "Evaluate only after `Session::run` has emitted all finishing events and succeeded" (spec line 51).

EOF findings specifically (`expert.rs:114-129`): `Collector::finish` calls `tcp::finish(&self.streams, &summary.trailing_tcp_events, summary.frames_read)` → `expert/tcp/sequence.rs:248-283` filters `TcpEvent::Evicted` with `pending_bytes > 0` → `tcp.incomplete_at_end` (Severity::Info):
- `number` = `summary.frames_read` — the LAST physical frame number READ, not the last matched frame (may be a filtered-out or non-TCP frame).
- `stream` = `streams.get(flow).or_else(|| streams.get(&flow.reverse())).map(tcp_stream_ref)` (sequence.rs:270-274) — `streams` maps directional `ScopedFlowKey` → stream index, populated only in `observe_tcp` (tcp.rs:74-76) for matched frames whose `record.tcp.conversation` is `Some`. `None` when neither direction was recorded — the spec's `stream: null` EOF case (spec lines 40-43, EG15). Note: every reassembler push today comes from a matched frame's elected TCP conversation which registers `streams[flow]`, so the null case is narrow — EG15's fixture pins it (see §9 caveat).
- Mid-run `Evicted`/`Closed`/`Data`/`Gap`/`Retransmission` events in `record.tcp_events` feed state tracking (`reconcile_tcp_evictions`, `sequence::reconcile_events`, `record_clean_closures`) but only `Retransmission` events produce per-frame findings (sequence.rs:23-63); `Evicted`-with-pending produces findings ONLY via EOF `finish`.

IP-side counterpart for contrast (EG16): trailing incomplete reassembled datagrams surface as `IpEventRecord` via the `ip_sink`/`run_with_ip_events` channel (`analysis/pipeline/ip.rs:89`), not as expert `Finding`s — the gate never sees them; they are rendered through `ip_reassembly` evidence paths instead. Do not try to feed `ip_sink` records into `gate.observe` — its input type is `&Finding` only.

## 5. Matched vs read frames; filter/epoch ordering

Pipeline entry points (`analysis/pipeline.rs`):
```rust
pub fn run<R, F>(reader: &mut Reader<R>, registry: Arc<Registry>, options: &Options<'_>, sink: F) -> Result<Summary, Error>
    where R: Read, F: FnMut(FrameRecord<'_>) -> Result<(), BoundaryError>           // pipeline.rs:258-269
pub fn run_with_ip_events<R, I, F>(reader, registry, options, ip_sink, sink) -> Result<Summary, Error>
    where I: FnMut(IpEventRecord) -> Result<(), BoundaryError>                     // pipeline.rs:278-289
```
`run` delegates to `run_with_ip_events` with a no-op `ip_sink`. `Session::run` wraps `run_with_ip_events` (session.rs:243-267) and folds `collector.observe` per record before invoking the user `event_sink` per event (session.rs:259-265).

`analysis::Options<'a>` (`analysis/pipeline/limits.rs:255-294`): `plan: Plan`, `deadline`, `track_sources`, `cancellation`, `filter: Option<&Filter>` ("input selection for TCP reassembly, not session presentation: IP reconstruction sees all input, but TCP and collectors see only matches", lines 263-271), `stream: Option<StreamRef>` ("keeps only the frames of one conversation, applied with the filter"), `time_bounds: Option<frame::TimeBounds>` (inclusive capture-time bounds applied WITH the filter, after IP reconstruction/stream indexing; "all physical frames consume read budgets"; timestampless records skipped when bounds set, fail the run when unset), `tcp_events: bool` ("drives bounded TCP reassembly over the matched frames"), `ip_overlap: OverlapPolicy`, `limits: Limits` (validated at run start, pipeline.rs:290).

`analysis::Summary` (pipeline.rs:223-247): `frames_read` = all physical frames read (`input.frames()`, line 545, charged to budgets including excluded), `frames_matched` = frames passing `time_bounds` + `options.stream` + `options.filter` (incremented pipeline.rs:519), `trailing_tcp_events`, `ip_reassembly`, `clock`, `interfaces`, `scopes`, `bytes_read`, provenance fields.

Pipeline order per frame (pipeline.rs:374-542): read/charge → timestamp check → decode → **capture-global IP reassembly + stream-index assignment BEFORE selection** (lines 396-479: `advance_ip_reassembly`, `elect_transport_views`, `tcp_segment`, `tcp_streams.assign`) → `time_bounds` skip (480-484) → `options.stream` skip (485-493) → `options.filter` skip (494-518) → `frames_matched += 1` (519) → `reassembly_dispatch.dispatch` (521-526) → `sink(FrameRecord)` (529-541).

So: **TCP reassembly consumes only matched frames** (`Options::filter` doc, limits.rs:266-271: "This is input selection for TCP reassembly... IP reconstruction sees all input, but TCP and collectors see only matches"). Filtered-out frames DO advance: IP reassembly (can complete derived datagrams → `ip_sink` events on ANY frame), conversation-index assignment (canonical, direction-agnostic — `conversation_index.rs:55-74` `assign(&ScopedFlowKey)` → index shared by both directions), clock/high-water, and read budgets — but never reach `sink`/`Collector::observe`/the gate. `ip_datagram_incomplete` EOF evidence goes to `ip_sink` as `IpEventRecord` — NOT an expert `Finding` (spec EG16 relies on this).

Epoch bounds (`command_options/epoch_bounds.rs` → `frame::TimeBounds`, `options.time_bounds`) behave identically to the filter for selection (`continue` at 483) — same matched/not-matched semantics for the gate's `frames_matched`.

`frames_matched` for the gate = `outcome.run.frames_matched` — the same counter the outer report uses (`output::expert::Report.frames_matched` ← `summary.frames_matched`, rendering.rs:134). Confirmed: one counter, no separate accounting.

## 6. CLI consumption today (`crates/packetcraftr-cli/src/commands/expert.rs`, 90 lines)

- `Spec` impl (lines 17-41): `Format = ToolFormat`, `CANCELLATION = true`, `OFFLINE = true`; `run_time` = `self.limits`; `resources` uses `AnalysisStages::with_tcp(true)` + `settings.retained_result_items(self.limits.capture.max_frames)`. `run` maps `run(...)` to `CommandExit::SUCCESS` (line 39) — today the command ALWAYS exits 0 on success.
- `run()` (43-90): `prepare(arguments.limits, arguments.filter.as_deref(), &arguments.decode)` → `open_capture` → `Session::new(registry, prepared.options(), expert::Collector::new(), None)` — selector is `None` for expert.
- Event callback (lines 69-81):
  ```rust
  let outcome = session.run(&mut reader, ip_event_sink(format, stream), |finding| {
      if selector.matches(&finding) {
          state.count(&finding);
          rendering::render_record(format, finding.into(), &mut state, stream)
              .map_err(CliError::into_boundary_error)?;
      }
      Ok(())
  }).map_err(CliError::classified)?;
  ```
  `--min-severity`/`--code` filtering happens HERE via `expert::Selector::matches` — per finding, inside the sink. This is exactly where `gate.observe(&finding)` goes first (spec: "gate.observe first, then existing output selector/count/render"). A gate error returned as `BoundaryError` short-circuits: per-frame drain → `Error::Sink`; trailing drain → `Error::Collector` (§4). To preserve the typed source use `BoundaryError::from_error(gate_err)` or `CliError::classified(e).into_boundary_error()` (AGENTS: "typed errors with their original sources"; `CliError::into_boundary_error` keeps message+classification+causes but drops the source link — `from_error` retains it).
- `let summary = outcome.run;` (line 83) — the PIPELINE summary (`frames_matched`/`frames_read`/`ip_reassembly`/`clock`); `outcome.summary` (collector's `expert::Summary`) is discarded.
- Terminal render (85-89): `Text → render_text`, `Json → render_aggregate`, `Ndjson → render_stream`.

`commands/expert/arguments.rs` (58 lines): `Args { path: PathBuf, filter: Option<String>, min_severity: Severity (clap ValueEnum, default info), codes: Vec<String> (--code, Append), decode: DecodeArgs, limits: OfflineLimitsArgs }`. Local `Severity` enum (lines 22-38) maps to `diagnostic::Severity` via `From`. `AFTER_LONG_HELP` const is wired into the `commands!` macro at `commands.rs:263` (`#[command(after_long_help = expert::arguments::AFTER_LONG_HELP)] Expert(expert::arguments::Args) = "expert"`). Clap `requires` precedent for flag dependencies: `commands/dns/arguments.rs:58` (`#[arg(long, requires = "edns_udp_payload_size")]`), `fuzz/arguments.rs:43-58`; `conflicts_with` at dissect/read. For gate flags: `#[arg(long, requires = "fail_on")]` on `allow_findings`/`minimum_frames` gives EG10's "usage error before capture I/O" for free (clap exit 2 via `parse_error_exit`, startup.rs:180-221 — usage kind renders `cli.error`-ish envelope through negotiated format).

`commands/expert/rendering.rs` (138 lines): `State { selected: expert::Summary, retained: Retained<output::expert::Finding> }`; `count()` increments selected counters only; `render_record` writes text line `"#N severity code (tcp stream S): msg"` / retains for JSON / `stream.emit_data(finding)` for NDJSON; `render_text` prints `render_clock`, per-code `code=X findings=N` lines, then summary `"found N finding(s) (... ) in M of R frame(s)"` — spec's gate line appends after this (`gate=<verdict> reason=<reason> severity=<severity> triggering=<N> allowed=<N> frames=<N> required=<N>`, via existing `write_stdout_line`); `result()` (116-138) builds `output::expert::Report::from((selected, frames_read, frames_matched, findings, &summary.ip_reassembly))`.

`output/expert.rs` (102 lines): CLI DTOs — `Finding { severity: output::diagnostic::Severity, code, frame, transport?, stream?, message }` (`From<expert::Finding>` lines 25-36; `stream` skipped when None — spec wants `stream: null` tolerated downstream), `CodeCount`, `Report { clock, frames_read, frames_matched, errors, warnings, notes, codes, findings, ip_reassembly }` (`From<(expert::Summary, u64, u64, Vec<Finding>, &IpReassemblyReport)>` lines 62-96). `StreamRecord for Finding` → `event_name() = "finding"` (lines 98-102) — NDJSON data events stay report-selected; gate adds NO new data event; `gate: null | GateReport` is a required v7 field on the aggregate result + NDJSON `complete` result (spec 113-134). `output::diagnostic::Severity` is a `published_enum!` mirror (output/diagnostic.rs:10-17).

`output.rs:18-56` `published_enum!` — the mirror-enum macro for `Verdict`/`Reason` DTOs (precedent: `output/verify_forwarding.rs:24-31` `pub enum Verdict from analysis::Verdict`).

Exit-status pattern (precedent `commands/verify_forwarding.rs`): `const VERDICT_NOT_PASS: u8 = 1` (line 27); `match report.verdict { Pass => CommandExit::SUCCESS, Fail|Inconclusive => CommandExit::status(1) }` (141-146) computed BEFORE `rendering::render(...)`; `Ok(exit)` returned after render succeeds — render errors propagate as CliError and win over the verdict code (spec line 148). `CommandExit` defined `commands.rs:338-353` (`status(code)`, `get()`); mapped to `ExitCode` in `startup.rs:156-171` — `Ok(exit)` → `require_success_terminal` (NDJSON must have `is_complete()`) → `ExitCode::from(exit.get())`. Late cancellation after a completed run returns 130 without retracting the report (startup.rs:157-166; `command_failure` 236-284). `CliError::exit_code` maps Kind→{Usage:2, Packet:3, Capability:4, Io:5, Policy:6, Internal:70} (`errors.rs:184-193`), cancellation 130 (`CANCELLED_EXIT_CODE`).

`output/stream.rs` — `StreamEncoder::emit_data(record, diagnostics)` (173), `complete(result, diagnostics)` (193) writes the terminal `"complete"` event; error record via `emit_error`. `require_open`/`is_terminal` guard double completion. `emit_aggregate(command, result, diagnostics)` (rendering/machine.rs:104-113) writes the JSON success envelope.

Text writer: `write_stdout_line(fmt::Arguments)` (`rendering/human.rs:117`, sanitizing, interrupt-aware variant at 137) is where the `gate=...` line belongs; `render_text` already returns `Result<(), CliError>` so the writer error propagates identically to today. `emit_stderr_error`/`emit_json` at human.rs:177 and machine.rs:85.

## 7. Core error conventions (where `gate::Error` fits)

- `crate::error` (`src/error.rs`): `Kind { Usage, Packet, Capability, Io, Policy, Internal }` (36-47, `as_str` snake), `Classification { code: &'static str, kind: Kind, remediation: Option<&'static str> }` (67-82), `trait Classified { classification(); context() -> Option<Coordinate>; causes() -> Vec<String> default source_chain }` (199-214), `source_chain` (159-170).
- `BoundaryError` (`error/boundary.rs`, pub struct at line 14): `new(message: impl Into<String>, classification: Classification, causes: Vec<String>)` (24), `from_error<E: Classified + Error + 'static>(error: E)` (39 — boxes the typed source), `with_source(message, error, causes)` (58 — source retained as cause), `as_causes()` (79), `with_context(Option<Coordinate>)` (87), `internal_execution` (94), `execution_validation` (104).
- Public error convention (closest small example — `analysis/provenance.rs:28-53`):
  ```rust
  #[derive(Debug, thiserror::Error)]
  #[non_exhaustive]
  pub enum Error {
      #[error("physical-frame provenance exceeds its {limit}-byte budget")]
      Limit { limit: usize },
      #[error("could not allocate {bytes} provenance bytes")]
      Allocation { bytes: usize },
      #[error("source sets belong to different capture runs")]
      DifferentCapture,
  }
  impl Classified for Error {
      fn classification(&self) -> Classification { match self {
          Self::Limit{..}|Self::Allocation{..} => Classification::new("policy.provenance_limit", Kind::Policy, Some("raise the finite provenance budget or retain fewer source sets")),
          Self::DifferentCapture => Classification::new("internal.provenance_scope", Kind::Internal, Some("merge captures before combining their source references")),
      } }
  }
  ```
- Larger example: `analysis/application.rs:57-99` (`Error::{Analysis(#[from]), Provenance(#[from]), Limit{field,limit}, Sources{number}, Output(BoundaryError)}` — `policy.application_limit`/Policy; delegated causes()). `analysis/forwarding.rs:695-779` mixes `cli.verify_rule`/Usage vs `policy.verify_*`/Policy — same dual-kind shape the gate needs.
- Code-string catalog is NOT centralized — each `classification()` writes a `&'static str` literal. Prefix conventions observed (grep of `Classification::new`): `cli.<feature>` for caller/config errors (`cli.analysis_limit`, `cli.verify_rule`, `cli.error`), `policy.<feature>_limit` for exhausted finite budgets (`policy.application_limit`, `policy.verify_evidence_limit`, `policy.provenance_limit`), `packet.*`, `internal.*`, `io.*`, `analysis.verify_observation_contract` (one-off). Spec's `policy.expert_gate_limit` (counter overflow — unreachable in practice, still typed) and `cli.expert_gate` (invalid `minimum_frames == 0`) fit directly.
- `analysis::Error` (analysis/error.rs:11-95) is the pipeline error: `#[non_exhaustive]` enum with `#[source]`-carrying variants + `#[error(transparent)]` wrappers (`Cancelled`, `Provenance`, `Collector(BoundaryError)`); classification match at 135-211. `Sink { number, source: BoundaryError }` = consumer callback failures at a frame; `Collector(BoundaryError)` = finish/trailing-drain failures. Gate errors arriving via the sink land in one of these two — they keep the gate's own classification because `Sink`/`Collector` delegate to `source.classification()` (line 195).
- `crate::budget::deadline_error_conversions!(Error)` (error.rs:213) — the macro pattern for adding deadline conversions, if ever needed.
- `#[non_exhaustive]` on every public error enum; `thiserror::Error` everywhere (dep already present).

## 8. Tests — layout, helpers, registration

- No `[[test]]` entries anywhere: both crates autodiscover `tests/*.rs` binaries (check: `crates/packetcraftr-core/Cargo.toml` has only `[[bench]] benchmarks` harness=false; cli same). New file `crates/packetcraftr-core/tests/expert_gate_contracts.rs` is picked up automatically; add `mod common;` at top if fixtures needed. Naming: `*_contracts.rs` for behavior, `*_conformance.rs` reserved for schema checks (AGENTS + CONTEXT).
- Core test helpers `crates/packetcraftr-core/tests/common/mod.rs` (145 lines): `mod common;` then `use common::{CLIENT, SERVER, TcpSpec, client_tcp, server_tcp, registry, tcp_frame, udp_frame, reader}` — `reader(frames)` builds a pcap `Reader<Cursor<Vec<u8>>>`; `tcp_frame(registry, ts, spec, payload)` builds via `Builder`; `registry() = builtin::registry()`. Also `common/{ip_fragments,packets,pcap,probe,tls_capture,tls_frames,tls_vectors}.rs`.
- `expert_transition_contracts.rs` (747 lines) — the model to copy: drives `analysis::run(reader, registry, &Options{tcp_events:true,..}, |record| { findings.extend(collector.observe(&record)); Ok(()) })` then `collector.finish(&run_summary)` and extends findings with trailing (lines 27-50, `analyze_frames`). So the gate's equivalence test can reuse `analyze_frames`-style code OR the `Session` path — for the EOF (EG09) case the collector.finish trailing findings must be fed to `gate.observe` too. Fixtures: `(TcpSpec, &[u8])` segment lists; `finding(severity, code, number, message)` helper constructs expected `Finding` (line 68-84, uses `stream: Some(tcp:0)`); `assert_expert` compares `Vec<Finding>` + `expert::Summary` fields. `tcp.incomplete_at_end` exercised at lines 246-288 (gap→retransmit→conflict→EOF-residue; `number = 7` = last frame). capture.* EOF-style findings: `capture_evidence_*` tests (536-660) build snaplen-truncated frames via `Frame::try_with_lengths` and clock-regressing timestamps; `stream.is_none()` asserted (592).
- `pipeline_expert_contracts.rs` (90 lines): despite the name it's analysis `Error` classification coverage — asserts `classification().kind`/`code`/`causes`/`to_string` for InvalidLimit (Usage), StreamLimit (Policy), Reassembly malformed (Packet)/resource (Policy), IpReassembly Inconsistent (`internal.ip_reassembly`), Scope, and `Sink` with `BoundaryError::execution_validation`. The natural home for gate Error classification assertions (or the new gate contracts file).
- `session.rs` unit tests (274+): scripted `Probe` collector — shows the lifecycle ordering `observe → event → scopes → finish → trailing events` (test at 505-538) and that an event-sink failure mid-run surfaces `Error::Sink` while trailing-drain failure surfaces `Error::Collector` (`fail_observe_at`/`fail_finish` probe fields).
- CLI test helpers `crates/packetcraftr-cli/tests/common/mod.rs` (121 lines): `run(&[&str]) -> Output`, `run_success`, `parse_json` (schema-validates!), `parse_ndjson` (schema-validates each record!), `schema_validator()` over `output_schema()` (embedded `schemas/packetcraftr.output.v6.schema.json` via `test_support.rs:71-79`), `path_text`, `assert_contiguous` (re-exported from `packetcraftr_cli::test_support`), `run_with_stdin`/`decode_hex`/`append_truncated_record` in `common/process.rs` — some tests import it as `#[path = "common/process.rs"] mod process_support;` (offline_workflow_contracts.rs:17-18).
- CLI expert coverage in `offline_workflow_contracts.rs`: hex-capture fixtures `TCP_CLIENT/TCP_SERVER/TCP_DATA` (32-37 — produce `tcp.retransmission_conflicting` error finding); `write_capture*` builders (44-211); `expert_reports_tcp_state_in_aggregate_stream_and_text_modes` (783) incl. `--min-severity error --code tcp.reset` hiding; `expert_text_lists_one_count_line_per_code_before_the_summary` (821 — exact text tail); NDJSON IP-lifecycle ordering + single terminal (668-747); truncated-capture stream failure → last record error (867-899); usage-error cases `--max-flows 0` etc. (1767-1830, exit 2); `expert_surfaces_capture_evidence_in_every_output_mode` (2141+, capture.frame_truncated/clock_regression findings through all 3 modes).
- `process_contracts.rs`: `expert -` terminal-stdin rejection (89), `--output pcap expert` format rejection exit 2 `cli.output_format` (668), `["--output","json","expert",missing]` I/O error path (~894).
- `aggregate_schema_conformance.rs`: `expert_case()` (666-709) constructs `expert_output::Report::from((Summary{...},12,11,findings,&ip_reassembly))` wrapped in `envelope(Command::Expert,...)` and schema-validated — this conversion is where `gate` plugs in; every command with a JSON format needs a case (lines 138-151).
- `ndjson_conformance.rs`: `output::expert::Finding` event validated (405-416), terminal `output::expert::Report` literal (539-552) — adding a required `gate` field means these literals get `gate: None`; v6→v7 schema swap is BASE-01's job (`schemas/packetcraftr.output.v7.schema.json`, `SCHEMA_V7` replaces `SCHEMA_V6` at `output/contract.rs:13`; `test_support.rs:74` embeds the schema path).
- `error_classification_contracts.rs` (core): classification assertions style — `error.classification().code`, `.kind`, `.causes()`.
- GATE-01/02 validation commands are spelled out in the issue files; `cargo test --locked -p packetcraftr-core --test expert_gate_contracts --test pipeline_expert_contracts --test expert_transition_contracts`.

## 9. Findings inventory + the `stream: null` / filtered-EOF analysis

Complete produced-finding set the gate sees (every code, observed before selectors):
- `capture.frame_truncated` (Warning, `stream:None`), `capture.clock_regression` (Warning, `stream:None`) — `finding.rs:26-66`.
- Every `record.decoded.diagnostics` `Diagnostic` → `Finding` with `severity`/`code` copied verbatim, `stream` from `diagnostic_stream` (may be `None`), incl. derived-datagram children (`finding.rs:68-118`) — open decoder code set (`decode.*` etc.).
- TCP header findings (tcp.rs + tcp/*): `tcp.reset` (Warning), `tcp.keep_alive` (Info), `tcp.zero_window`/`tcp.zero_window_probe` (Warning/Info), `tcp.window_full`/`tcp.window_exceeded` (Warning), `tcp.duplicate_ack` (Warning), `tcp.previous_segment_not_captured` (Warning), `tcp.retransmission` (Warning) / `tcp.retransmission_conflicting` (Error) — from both header tracking and `TcpEvent::Retransmission` reassembly events.
- `tcp.incomplete_at_end` (Info) — ONLY in `finish` (§4).
- One physical frame can yield several findings — the gate counts each event (EG08).

`stream: null` for `tcp.incomplete_at_end`: mechanism is `streams.get(flow).or_else(|| streams.get(&flow.reverse()))` missing both keys (sequence.rs:270-274). `streams` is written only at tcp.rs:74-76 inside `observe_tcp`, which runs iff `record.tcp.is_some() && record.tcp.conversation.is_some()` — i.e., matched frames whose elected innermost TCP got a segment/conversation. Every reassembler `push` also flows through a matched elected segment (pipeline.rs:447-463, 521-526 + `dispatch.rs:46-84`), which registers `streams[flow]` — so a pending flow normally always resolves to `Some`. The null case per spec (line 40, EG15) is a pending flow that never appeared as an elected matched conversation — candidates: scoped-key divergence (physical carrier `transport_hidden_by_fragment` → `Ok(None)` at adapter.rs:462-464 while a derived child carries the same 5-tuple under a different `ScopeId`), or a flow evicted/created via `evict_reused_generation` bookkeeping. I could not fully construct it by reading — EG15's fixture defines it; the gate must accept `stream:None` findings regardless. IMPORTANT subtlety for EG15: `frames_matched == 0` means NOTHING reached `sink`, so NO reassembler pending can exist — an EOF finding with matched==0 therefore can only be explained if at least one frame matched while its bytes were excluded from the pending flow's `streams` entry — OR the fixture's "matched frames are zero" is loose for "the pending bytes' frames were filtered". When writing EG15, verify empirically what the emitted `stream`/`number` actually are; the spec requires only that the gate counts the finding with `stream:null` + `number`==last physical frame.

## 10. Deps & style constraints

`packetcraftr-core` deps (Cargo.toml): `bytes, flate2, zstd, md5, memchr, noyalib, serde, serde_json, sha2, thiserror`; dev-deps `criterion, proptest, tempfile`. No new deps needed: `u64::checked_add`, `core::cmp`, `std::fmt`, `thiserror::Error`, `serde` derive all present. `#![forbid(unsafe_code)]` at lib.rs:4.
Workspace lints (root Cargo.toml:15-28): `unsafe_code` deny, `unreachable_pub` warn, clippy `use_self`/`semicolon_if_nothing_returned`/`redundant_closure_for_method_calls`/`needless_raw_string_hashes`/`items_after_statements`/`match_same_arms` warn, `mod_module_files` deny, `undocumented_unsafe_blocks` deny — CI runs `-D warnings`. Edition 2024, rust-version 1.98.1 — `let-else`, `if let ... && let ...` chains are used throughout.
Style notes: counter increments in the codebase use `saturating_add`/plain `+` with justification comments ("u64 counters cannot reach u64::MAX from a bounded frame count", expert.rs:68, rendering.rs:31); the spec REQUIRES checked increments here ("Use checked counter increments"), so `checked_add(1).ok_or(Error::Overflow{...})`. `Summary::count` is deliberately unchecked — do not mirror that comment; the gate's overflow is a typed policy error.
Test vocab: `*_contracts.rs` behavior regressions in `crates/*/tests/`; helpers in `tests/common/`; unit tests beside owner in one inline `mod tests` or `<module>/tests.rs`. Schema checks go in `*_conformance.rs` — `expert_gate_contracts.rs` (behavioral) is correct per GATE-01/02.

## 11. Implementer checklist + naming subtleties

Core (`gate.rs`):
- `pub mod gate;` inside `expert.rs` (after `mod finding;` block); gate.rs imports `crate::diagnostic::Severity`, `super::Finding`, `crate::error::{Classified, Classification, Kind}` — same import style as finding.rs.
- `Verdict`/`Reason`: `#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]` `#[serde(rename_all = "snake_case")]` — mirrors `forwarding::Verdict` (evaluate.rs:38-49) so `published_enum!` conversion + `as_str` spellings come free. `min_severity` serializes via existing `diagnostic::Severity`.
- `Report` needs `Clone, Debug, PartialEq, Eq` (test comparison); serde is NOT required on it in core (CLI DTO carries the wire shape; `forwarding::Verdict` derives Serialize for its report fields — harmless to mirror).
- `Options`: `Clone, Copy, Debug, PartialEq, Eq` suffices (Severity is Copy).
- Checked math: `self.findings_observed.checked_add(1).ok_or(Error::Overflow { counter: "findings_observed" })?` — same for `triggering_findings`; pick one variant or a `{ counter: &'static str }` field; spec only pins code+kind.
- Truth table order in `finish`: check `triggering_findings > self.options.allow_findings` FIRST, then `frames_matched < self.options.minimum_frames` — fail beats inconclusive (EG05). Copy option values + counters into `Report` verbatim; do not recompute.
- `Gate::new` validation order is unspecified for zero minimum vs nothing — only `minimum_frames == 0` is invalid; keep it the sole constructor check.
- Gate observes `&Finding` only — no copy, no storage of findings (constant-size); the `Vec<Finding>` produced by the collector is unchanged.
- Naming collision to note: `Options.min_severity` in the gate means "fail-on threshold" (≥), while the CLI's existing `--min-severity`/`Selector.min_severity` means "report floor" (same `>=` semantics but different purpose). Do NOT reuse `Selector` for the gate.

CLI (GATE-02):
- New `Args` fields: `fail_on: Option<Severity>` + `allow_findings: Option<u64>` + `minimum_frames: Option<u64>` with `#[arg(long, requires = "fail_on")]` on the latter two (precedent `dns/arguments.rs:58`); `--fail-on` itself `Option`al (EG01 = gate null). Defaults when enabled: `allow_findings 0`, `minimum_frames 1` — apply at `Options` construction, not clap defaults, so `requires` still works.
- In `run()`: `let mut gate = arguments.gate_options().map(analysis::expert::gate::Gate::new).transpose().map_err(CliError::classified)?;` then inside the callback `if let Some(gate) = gate.as_mut() { gate.observe(&finding).map_err(...)?; }` BEFORE `selector.matches`; after `outcome`, `gate.map(|g| g.finish(summary.frames_matched))` → thread `Option<Report>` through `render_text`/`result`/`render_stream`.
- `CommandExit::status(1)` computed BEFORE `rendering::render` like `verify_forwarding.rs:141-146`; `Ok(exit)` after render — render failure beats verdict (spec line 148).
- `output::expert::Report` gains `gate: Option<GateReport>` — required v7 field (`None` serialized as `null`); `GateReport` DTO + `From<core Report>` + `published_enum!` for `Verdict`/`Reason` in `output/expert.rs`; schema literals in `ndjson_conformance.rs:539-552` and `aggregate_schema_conformance.rs:666-709` gain `gate`.
- NDJSON: `gate` lives ONLY in the terminal `complete` result; `"finding"` data events untouched (spec: no new data event).
- NDJSON incomplete-stream error path already maps to `io.stdout` (startup.rs:236-256 `command_failure`) — a gate error mid-run leaves the stream unterminated, so the process reports the classified gate-caused error (per `Error::Sink`/`Collector` delegation), never a fabricated gate result.
- Help text: `AFTER_LONG_HELP` for expert (commands.rs:263 wiring) should document the truth table + exit statuses per `--help` sweep expectations.

## 12. Invariants to preserve (regression checklist)

- `expert::Collector`/`expert::Summary` byte-for-byte behavior — `Summary::count` semantics (all produced findings), `codes` BTreeMap key set, `clock` copy in finish (expert.rs:118-128).
- Selector semantics: `--min-severity`/`--code` still gate ONLY report counters/retention/NDJSON `finding` events; `State.selected`/`State.retained` counts must be identical with/without a gate (spec lines 113-116).
- EOF attribution: `tcp.incomplete_at_end` keeps `number = frames_read` and the `stream` lookup rule; EOF findings still reach report selectors (a filtered-out finding counts toward `findings_observed` but not `selected`).
- `frames_matched` shared: outer `Report.frames_matched` and `gate.frames_matched` are the same `outcome.run.frames_matched` — never a separately counted value.
- Failure ordering: pipeline/capture errors still short-circuit before any verdict (no fabricated gate report for partial runs); sink errors keep `Error::Sink{number}` shape; trailing-drain errors keep `Error::Collector`.
- Exit statuses: 0 pass / 1 fail+inconclusive via `CommandExit` / 2 usage / 3-6 classified / 70 internal / 130 cancelled — no new exit code.
- Publication order: report writes complete BEFORE the non-zero exit is returned; JSON/NDJSON emit exactly one success payload; NDJSON keeps single terminal `complete` with `gate` inside `result`.
- Empty input: no gate → legacy success (empty report, exit 0); gate enabled → `inconclusive/insufficient_frames` exit 1 unless a triggering EOF finding forced fail first (EG06).
