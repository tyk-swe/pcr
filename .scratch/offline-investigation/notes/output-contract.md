# Output contract research: `packetcraftr.output/v6` → `v7`

Research for BASE-01 (`.scratch/offline-investigation/issues/01-output-v7.md`): new
`packetcraftr.output/v7` family + private `prepare_complete`/`publish_prepared_complete`/
`prepare_aggregate` seams. Spec source of truth: `.scratch/offline-investigation/spec.md`
§"Prepare artifact reports before publication" (L115–149).

All line numbers verified on branch `tyk/offline-investigation` (= main).

---

## 1. Schema versioning

### Producer constant

`crates/packetcraftr-cli/src/output/contract.rs:13`

```rust
/// Version identifier emitted by every structured CLI record.
pub const SCHEMA_V6: &str = "packetcraftr.output/v6";
```

Stamped only in `output/envelope.rs` — `use super::contract::{Command, Mode, SCHEMA_V6}` (L15),
then `schema: SCHEMA_V6` in four constructors: `published()` L249 (aggregate success),
`record()` L269 (stream success), `error()` L300 (aggregate error), `error_record()` L314
(stream error). For v7: rename constant to `SCHEMA_V7`/`"packetcraftr.output/v7"`; all four
stamp sites follow automatically.

### Embedded test schema

`crates/packetcraftr-cli/src/test_support.rs:71-79` — `output_schema()` lazy-loads
`include_str!("../../../schemas/packetcraftr.output.v6.schema.json")` into a `OnceLock<Value>`.
`schema_validator()` (L83-89, `#[cfg(test)]`) compiles it via `jsonschema::validator_for`.
`tests/common/mod.rs:21-26` has a duplicate integration-test `schema_validator()` built on the
same `output_schema()`. Both must point at the v7 file for "current binary identifies v7".

### Full `rg 'output/v6|output\.v6|SCHEMA_V6|v6-forwarding'` audit (excluding `.scratch/`)

**Current producer (migrate):**
- `src/output/contract.rs:13` — the constant itself.
- `src/output/envelope.rs:15,249,269,300,314` — stamp sites.
- `src/test_support.rs:75` — embedded schema path.
- `src/output/stream/tests.rs:306` — proptest asserts `record["schema"] == "packetcraftr.output/v6"`.
- `tests/machine_contracts.rs:5,26,40` — imports `SCHEMA_V6`, asserts aggregate + stream schema fields.
- `tests/process_contracts.rs:226` — `value["schema"] == "packetcraftr.output/v6"` literal.
- `tests/forwarding_verification_contracts.rs:635` — same literal.
- `schemas/packetcraftr.output.v6.schema.json:3,33` — `$id urn:packetcraftr:output:v6`,
  `"const": "packetcraftr.output/v6"` (new file needed; **v6 file stays byte-identical**).
- `examples/documents/output-*.json` (~70 files) — every doc line 2 `"schema": "packetcraftr.output/v6"`;
  regenerated/hand-migrated to v7.
- `scripts/verify-archive.py:15,19,90` — ASSETS lists v6 schema + v6 fixture; L90 asserts
  NDJSON `schema == 'packetcraftr.output/v6'`.
- `scripts/test-verify-archive.py:43-44` — fixture child emits v6 records.
- `scripts/check-native-capture.py:37` — asserts `schema == "packetcraftr.output/v6"`, `command == "capture"`.
- `scripts/test-native-capture.py:43,58` — fixture mutations + error row literal.
- `scripts/test-output-consumer.py:16` — loads `v6-forwarding.json` fixture.
- `examples/consumers/forwarding.py:17` — `SCHEMA = "packetcraftr.output/v6"` (becomes
  explicit family dispatch v6|v7, reject others; NDJSON first record picks family for the stream).
- `examples/consumers/fixtures/v6-forwarding.json` — **frozen, unchanged**; add `v7-forwarding.json`.
- `.github/workflows/release.yml:251` — staging asset list includes the v6 fixture.
- `README.md:236,249`, `docs/consumer-compatibility.md:3,15-18,51,60-69`,
  `docs/migration-unreleased.md:5,10,42,86,168,385,492`, `CHANGELOG.md:39,215` — prose.

**Historical/frozen (do NOT touch):** `schemas/packetcraftr.output.v6.schema.json`,
`examples/consumers/fixtures/v6-forwarding.json`, released-archive references
(`docs/migration-beta.3.md` etc.). v6 schema + fixture must diff empty post-change.

---

## 2. Envelope + stream encoder (EXHAUSTIVE)

### Envelope — `src/output/envelope.rs` (325 lines)

Supporting types:
- `ErrorKind` L22-58 (`pub`, `Serialize`, `snake_case`): `Cli/Packet/Capability/Io/Policy/Internal`,
  `From<Kind>` maps `Kind::Usage→Cli` (v6's frozen `"cli"` name). `as_str()`.
- `ErrorContext` L64-89 (`pub`, externally tagged): `SourceFrame(u64)`/`ProbeSequence(u64)`/
  `Attempt(u32)`/`CaseIndex(u64)`; `TryFrom<Coordinate>` returns `Err` for unpublished
  coordinates (context silently omitted by `Error::with_context` L145-148).
- `Error` L91-149 (`pub`, `Clone+Debug+PartialEq+Eq+Serialize`): `code: String`,
  `kind: ErrorKind`, `message: String`, `causes: Vec<String>`, then `Option` fields
  `context/capture/scan/remediation` all `skip_serializing_if = "Option::is_none"`
  (`capture: Option<Box<super::capture::Snapshot>>`, `scan: Option<Box<super::scan::Failure>>`).
  Ctors `new(classification, message, causes)`, `classified(&impl Classified+Display)`,
  builders `with_capture/with_scan/with_context` (`#[must_use]`).
- `Stats` L152-177 (`pub`, `Default`): `packets_attempted/packets_completed/bytes: u64`,
  `elapsed: Duration`, `capture: super::capture::Stats`. `From<packetcraftr::Stats>` + `From<&..>`.
- `Published<T>` L181-203 (`pub`): `{result: T, diagnostics: Vec<Diagnostic>, stats: Option<Stats>}`.
  `pub(crate) fn new(result, diagnostics: Vec<LibraryDiagnostic>)`, `with_stats` (`pub(crate)`).
- `is_zero` L205 (`pub(super) const fn`) — used as `skip_serializing_if` in `capture.rs`.
- `OutputPayload<T>` L209-214 (private enum, `#[serde(tag="status", rename_all="snake_case")]`):
  `Success{result: T}` / `Error{error: Error}` — produces `"status": "success"|"error"` plus
  `result` or `error` key.

`Envelope<T>` L218-234 (`pub struct`, `Clone+Debug+Serialize`) — fields all private:

```rust
schema: &'static str,
command: Option<Command>,
mode: Mode,                                   // Aggregate | Stream
#[serde(skip_serializing_if="Option::is_none")] sequence: Option<u64>,
#[serde(skip_serializing_if="Option::is_none")] event: Option<&'static str>,
#[serde(flatten)] payload: OutputPayload<T>,  // status + result|error
diagnostics: Vec<Diagnostic>,
#[serde(skip_serializing_if="Option::is_none")] stats: Option<Stats>,
#[serde(skip_serializing_if="Option::is_none")] resources: Option<super::resources::Report>,
```

Constructors:
- `Envelope::success(command, result, diagnostics)` L237 (pub) → aggregate success.
- `Envelope::published(command, Published<T>)` L242 (pub) — unpacks `Published`; carries stats.
- `Envelope::record(command, sequence, event, result, diagnostics)` L261 (`pub(super)`) —
  NDJSON data record; `event` is caller-supplied discriminator.
- `Envelope::error(command: Option<Command>, error)` L298 (pub) — aggregate error.
- `Envelope::error_record(command: Option<Command>, sequence, error)` L312 (`pub(super)`) —
  stream error, event hardcoded `"error"`.
- Builders: `with_resources(Report)` L283 (pub), `with_stats(impl Into<Stats>)` L289 (pub).

### Stream encoder — `src/output/stream.rs` (519 lines)

```rust
pub trait StreamRecord: Serialize { fn event_name(&self) -> &'static str; }  // L24
```

`write_unattributed_error(writer, command: Option<Command>, error: Error)` L31-44 (pub) —
one-off sequence-0 `error_record` for pre-command-selection failures (only place a null
`command` is legal in a stream).

Private state L46-79:
```rust
enum EncoderState { Open, Complete, Error, Failed }          // L46, private
struct EncoderOutput { state, sequence: u64, writer: EncoderWriter }  // L56, private
enum EncoderWriter { Direct(Box<dyn Write+Send>),
                    Bounded { sink: Worker<Vec<u8>>, timeout: Duration } } // L63
```
`require_open()` L71: Open→Ok; Complete|Error→`EncodeError::Terminal`; Failed→`Failed`.

```rust
#[derive(Clone)]
pub struct StreamEncoder {                                  // L82-89
    deadline: Option<Arc<Deadline>>,
    command: Command,
    output: Arc<Mutex<EncoderOutput>>,                      // THE shared identity
    resources: Option<Arc<dyn Fn() -> super::resources::Report + Send + Sync>>,
    terminal_error_timeout: Option<Duration>,
}
```

- `Clone` shares `output` Arc — **clones are the same encoder**; `Arc::ptr_eq` on `output`
  is the identity check the `publish_prepared_complete` seam needs.
- Builders (`#[must_use]`): `with_deadline(Arc<Deadline>)` L97, `with_resource_diagnostics(Fn)` L105,
  `with_terminal_error_timeout(Duration)` L116.
- Ctors: `new(command, writer)` L121 — Direct writer, `send+'static`; `new_bounded(command,
  writer, runtime, timeout)` L141-171 — wraps writer in a `Worker<Vec<u8>>` callback
  (`write_all`+`flush` per emit, `io.stdout` classification); retains worker permit past timeout.
- Emitters:
  - `emit_data(result, diagnostics)` L173 → `emit_published` L182 — rejects empty/`"complete"`/
    `"error"` event names (`ReservedEvent`), calls `write_success(event, published, false)`.
  - `complete(result, diag)` L193 → `complete_published` L211 → `write_success("complete", …, true)`.
  - `complete_with_stats(result, diag, stats)` L201 — same + stats.
  - `emit_error(error)` L218-236 — locks, `require_open`, builds `error_record(command, seq)`,
    samples resources (unconditionally, unlike data records), serializes, `write_line` with
    `next_state=Error` and `terminal_error_timeout` override.
- Status probes: `is_open()` L240, `is_terminal()` L246 (Complete|Error), `is_complete()` L254,
  private `state()` L329 (try_lock → Option<EncoderState>).

`write_success` L258-308 — the core emit path:
1. unpack `Published{result, diagnostics, stats}`;
2. `lock_output()` (deadline-aware try_lock loop 1ms sleep / plain lock);
3. `require_open()`; read `sequence`; `next = sequence.checked_add(1)` for non-terminal
   (`SequenceOverflow`), `None` for terminal;
4. `Envelope::record(command, sequence, event, result, diagnostics)`;
5. **resources sampled when `sequence==0 || terminal`** (first + terminal records only);
6. `with_stats` if stats;
7. `serialize_line` → `check_publication_budget(deadline, "serialization")`;
8. `write_line(&mut output, line, sequence, next_state, deadline, timeout_override=None)`;
9. advance `output.sequence = next` only on success, still under lock.

`write_line` L334-367: `check_publication_budget(deadline,"publication")` → Direct
`write_all`+`flush`, or Bounded `sink.emit(line,&wait)` where `wait = deadline.for_wait(timeout)`
(deadline-aware) else `Deadline::new(timeout)`. On write failure: `state = Failed`,
`EncodeError::Write{sequence, source}`; on success `state = next_state`.

`check_publication_budget` L369-383: `deadline.enforce()` → `Interrupted::Cancelled`→Cancelled,
`Exceeded`→`Deadline{phase, source}`, other→Cancelled.

`MAX_RECORD_BYTES: usize = 16*1024*1024` L387 (pub). `serialize_line(record, sequence)` L389 →
`serialize_line_with_limit` L393-445: inner `BoundedLine` writer — counts bytes, fails the
serde write on overflow (`exceeded` flag → `RecordLimit{sequence,limit}`), `try_reserve_exact`
growth capped at limit, then appends `b"\n"` (newline counted). Private `fn`, not `pub`.

`EncodeError` L447-516 (`pub`, `thiserror`, `non_exhaustive`): `Deadline{phase, source}`,
`Cancelled`, `RecordLimit{sequence,limit}`, `ReservedEvent`, `Terminal`, `Failed`, `Poisoned`,
`SequenceOverflow`, `Serialize{sequence, source}`, `Write{sequence, source}`.
`Classified` L486: Deadline→`io.output_deadline`, RecordLimit→`io.output_record_limit`,
Write→`io.stdout`, Cancelled→passthrough, rest→`internal.ndjson_stream` (all Kind::Io
except Cancelled passthrough + Internal fallback). **No `PreparedComplete` variant yet** —
the spec's `internal.prepared_output`/Internal/70 needs a new variant here (or a separate
typed error), since `CliError::from(EncodeError)` keeps classification → exit 70 via
`exit_code_for(Kind::Internal)` (`src/errors.rs:184-193`: Usage=2, Packet=3, Capability=4,
Io=5, Policy=6, Internal=70; `CANCELLED_EXIT_CODE=130` L182).

### Stream tests — `src/output/stream/tests.rs` (506 lines)

- `bounded_terminal_writes_fail_incomplete_without_retrying_or_releasing_the_worker` L44 —
  `BlockedWriter` fixture (mpsc gate in `write`); both `complete` and `emit_error` paths;
  asserts: error contains "incomplete", `!is_open`, `!is_terminal`, subsequent emits fail,
  writer retains worker permit until released.
- `bounded_output_keeps_sequences_contiguous_and_writes_one_terminal` L98 — 3 data + complete
  with stats; 4 newline-terminated records; sequences 0-3; exactly one `complete` event.
- `classified_error_includes_typed_context` L142 — `ErrorContext` one-key serialization.
- `serialized_limit_counts_escaping_and_newline_at_exact_boundaries` L164.
- `every_partial_data_or_terminal_write_and_flush_failure_is_final` L203 — `FailAfter` writer;
  every partial byte count 0..=len and flush failure → `Write{sequence:0}`, then all emits→`Failed`.
- proptest `complete_invocation_traces_have_one_terminal_and_no_post_terminal_data` L264 —
  random emit/complete/error actions; parses records; asserts contiguous sequence,
  `schema=="packetcraftr.output/v6"`, command string, terminal is last and complete|error.
  **v7: update literal to v7** (or make it read the constant).
- `serialization_that_spends_the_budget_is_not_published_and_can_report_an_error` L327 —
  deadline + spend-during-serialize → `Deadline{phase:"serialization"}`, buffer empty,
  owner still `emit_error` OK.
- `an_operation_deadline_bounds_waiting_for_the_encoder_lock` L366 — `phase:"lock"`.
- `writer_wait_uses_remaining_operation_budget_and_retains_cleanup_capacity` L414;
  `extended_wait_accepts_a_slow_writer_and_cleanup_uses_its_own_ceiling` L475 —
  `with_terminal_error_timeout`.

**Where the `prepare_complete`/`publish_prepared_complete` seam hooks** (spec L119-134):
- `prepare_complete(result, diagnostics)` → `PreparedComplete` (opaque, crate-private, **non-Clone**):
  fields needed = `output: Arc<Mutex<EncoderOutput>>` (identity), `sequence: u64`, `line: Vec<u8>`
  (fully serialized newline-ended record incl. resources+stats baked in), maybe `command`.
  Implementation lives in stream.rs so it can reuse private `serialize_line`/`Envelope::record`/
  `check_publication_budget`. Under `lock_output()`: `require_open()` → capture sequence → build
  `Envelope::record(command, seq, "complete", result, diag)` + `with_resources(observe())` (sample
  now, per spec "resource diagnostics sampled immediately before commit") + optional stats →
  `serialize_line` → `check_publication_budget` before AND after serialization → **release lock
  without writing or advancing**.
- `publish_prepared_complete(prepared)`: `Arc::ptr_eq(&self.output, &prepared.output)` for
  same-encoder check (clones share Arc — correct semantics); re-lock → `require_open()` +
  `output.sequence == prepared.sequence` (stale check) → `write_line(&mut output, prepared.line,
  seq, EncoderState::Complete, deadline, None)` — reuses normal deadline/bounded-writer/flush/
  Failed-state machinery. **Does not reserialize, does not resample resources.** Wrong encoder/
  stale sequence → new `EncodeError` variant classified `internal.prepared_output`/Internal →
  exit 70. After a discarded prepare, normal `emit_error` at the same sequence must still work
  (prepare took no state).
- Constraint noted in spec: no other event between prepare/publish in the two artifact commands
  (HTTP-B02 body artifact, SPLIT-02 capture parts) — enforced by callers, not the encoder.

---

## 3. Machine rendering — `src/rendering/machine.rs` (242 lines)

`BoundedJsonError` L15-30 (`pub(crate)`): `Limit` / `Serialize(serde_json::Error)`;
`into_cli_error(limit_fn)` maps Limit→caller policy error, Serialize→`Kind::Internal`.

Counting writer L46-83 (`bounded_json_len_with_formatter`): `Counter{remaining, exceeded}`
`impl Write` — serde serializes into it; error from serde + `exceeded`→`Limit`, else
`Serialize(source)`. Public wrappers `bounded_json_len` (compact) L32 and
`bounded_pretty_json_len` L39 (`pub(crate)`). Used by `commands/application_output.rs:32`
to charge `--max-application-output-bytes` per event. **This is the "existing pretty-JSON
counting writer" the spec names for `prepare_aggregate` preflight.**

`emit_json(value)` L85-94 (`pub(crate)`): `crate::invocation::check()` →
`io::stdout().lock()` → `BufWriter::with_capacity(64*1024)` → `serde_json::to_writer_pretty`
→ `write_all(b"\n")`+`flush`. `json_error` L96-102: io→Kind::Io else Kind::Internal.

Emitters (all `pub(crate)`, all call `crate::cancellation::check()` first):
- `emit_aggregate(command, result, diagnostics)` L104 → `emit_json(resources::decorate(Envelope::success(...)))`.
- `emit_aggregate_with_stats` L115 — same + `.with_stats`.
- `emit_published(command, Published<T>)` L127 → `Envelope::published` + decorate.

`crate::resources::decorate(envelope)` (`src/resources.rs:521-526`) calls `snapshot()`
(L455-519): returns `Some(output::resources::Report{settings, workers, cooperative_deadlines,
hard_rss_limit})` only when `--resource-diagnostics` configured (OnceLock `CONTEXT`); else
None → envelope unchanged. Snapshot also folds in runtime worker samples
(`Worker::from((name, runtime.snapshot()))`).

**Aggregate vs NDJSON differences:** aggregate = one pretty-printed JSON document, no
`sequence`/`event`, `mode:"aggregate"`, resources decorated unconditionally at emit time;
NDJSON = compact lines, `mode:"stream"`, `sequence`/`event`, resources only on seq0+terminal,
16MiB/record cap (`MAX_RECORD_BYTES`). **Aggregate has NO byte limit** — spec L139-141:
item/application limits bound payload, 16MiB is NDJSON-only.

**`prepare_aggregate`/`PreparedAggregate<T>` seam** (spec L135-141): crate-private type in
machine.rs owning the decorated success envelope. Prepare: `cancellation::check()` → build
`Envelope::success(command, owned_dto, diagnostics)` → `resources::decorate` (snapshot now)
→ `bounded_pretty_json_len(&envelope, usize::MAX)` as pure preflight (verifies serializability;
usize::MAX is just the overflow ceiling — no real cap, no second buffer). Store `Envelope<T>`.
`publish(self)`: `emit_json(&self.envelope)` — same frozen envelope, no redecorate.
`PreparedAggregate<T>` should be non-Clone; dropping it is a no-op.

---

## 4. CLI-owned output DTOs

Conventions (enforced by `src/output.rs` module doc L4-12, ADR-0003): **the CLI owns every
published field**; library types convert via `From`/`TryFrom`, never embed serde directly.
`published_enum!` macro (`src/output.rs:18-56`) — CLI-owned enum mirrored variant-for-variant
from a library enum: derives `Clone+Copy+Debug+PartialEq+Eq+PartialOrd+Ord+Hash+Serialize`
with `#[serde(rename)]`, generates `as_str()`, `Display`, `From<source>`.

- `output/http.rs` (270 lines): `Status` via `published_enum!` L17-30 (9 variants,
  `snake_case` names). `Body` L33-58: `#[serde(tag="type", content="length")]` — `{"type":"length","length":N}`.
  `StartLine` L61-102: `#[serde(tag="type", rename_all="snake_case")]` Request/Response;
  `String::from_utf8_lossy` text + `compact_hex` raw twin (`target`/`target_hex` pattern).
  `Header`/`Message`/`Issue`/`Summary`/`Complete`/`Report` — plain `#[derive(Debug, Serialize)]`
  structs with `From`/`TryFrom` (`Complete::try_from((&library::Summary, analysis::Summary, Vec<Definition>)`
  L234 — tuple conversions are the convention for multi-source DTOs).
  `Message` impls `StreamRecord` → `event_name()="http_message"` L171-174;
  `Issue` → `"http_stream_issue"` L194-197.
  `Report` L253-269 uses `#[serde(flatten)]` for `complete: Complete` — **aggregate report
  flattens the same complete DTO that NDJSON's terminal record publishes** (single source of truth).
  **v7 HTTP fields per spec**: `transactions: []`, `transaction_summary: null`,
  `body_export: null` on pre-feature reports — explicit null serialization (NOT
  skip_serializing_if), see below.
- `output/expert.rs` (102 lines): `Finding{severity, code: &'static str, frame: u64,
  transport: Option<StreamTransport>, stream: Option<u64>, message}` L13-36 — options use
  `skip_serializing_if`. `CodeCount{code, findings}` L38. `Report{clock, frames_read,
  frames_matched, errors, warnings, notes, codes, findings, ip_reassembly}` L46-96, tuple-`From`.
  `Finding` impls `StreamRecord` → `"finding"` L98-102. **v7: `gate: null` pre-feature.**
- `output/frame.rs:52-55` — `Timestamp{unix_seconds: i64, nanoseconds: u32}` (`pub`,
  `Clone+Copy+Serialize`). `TryFrom<SystemTime>` L57-70: post-epoch `i64::try_from(secs)` fails
  `Error::TimestampOutOfRange`; pre-epoch handled by `from_pre_epoch_duration` L72-112 with
  floor-seconds encoding (`(-3, 750_000_000)` = -2.25s, Display L118-127 prints conventional
  signed decimal). Whole negative range incl. `i64::MIN` edge supported.
- `SourceFrame` L22-48: `#[serde(transparent)]` newtype over `NonZeroU64`; `TryFrom<u64>`
  rejects 0 with `Error::InvalidSourceFrame` (one-based position contract).
- `output/analysis.rs`: `Scope{id, interface: Option<u32>, encapsulation: Vec<EncapsulationIdentifier>}`
  L116-146 (`TryFrom<Definition>`); `Clock{regressions, max_regression: Duration,
  max_forward_step, max_forward_step_frame: Option<u64>}` L148-166; `StreamTransport` via
  `published_enum!` L168; `StreamRef{transport, index}` L177; `Endpoint{address: IpAddr,
  port: u16}` L193 + SocketAddr Display; `FlowKey`/`ScopedFlowKey` L215-249.
- `output/diagnostic.rs`: `Severity` `published_enum!` (info/warning/error);
  `Diagnostic{code: &'static str, severity, message, layer: Option<usize>,
  field: Option<&'static str>}` — layer/field `skip_serializing_if`.
- `output/resources.rs`: `Value` untagged Number(u64)|Policy(String); `Setting{name, value,
  unit, stage, scope, source, enabled}`; `Worker{name, supported, capacity, active,
  rejected_admissions, cleanup_retaining_capacity}`; `Report{settings, workers,
  cooperative_deadlines: bool, hard_rss_limit: bool}`.
- **Optional-field serialization convention**: metadata-level absence uses
  `skip_serializing_if="Option::is_none"` (key absent); contract-level "present but empty"
  uses explicit `null` (e.g. v7's `transaction_summary: null`, `gate: null`, `body_export: null`
  — plain `Option` fields with no skip attr). Empty-vec fields may use
  `skip_serializing_if="Vec::is_empty"` (follow.rs:88, network.rs:273, protocols.rs:123);
  counters may use `skip_serializing_if="is_zero"` (capture.rs:24 via `pub(super) const fn
  is_zero` envelope.rs:205).
- Integers: `u64` counters everywhere; `usize` only for memory-internal counts
  (`incomplete_datagrams: usize` http.rs:229); bounded by schema `maximum`/`minimum`
  declarations where frozen (e.g. DNS `query_type` 0-65535, `source_frame` ≥1).

---

## 5. Consumers + fixtures

### `examples/consumers/forwarding.py` (287 lines)

`SCHEMA = "packetcraftr.output/v6"` L17; bounds `MAX_RECORD=16MiB`, `MAX_STREAM=64MiB`,
`MAX_RULE_DECLARATIONS=256`, `MAX_RULE_DECLARATION_BYTES=64KiB`, `STATES` enum L18-22.
`decode()` L51-59: `json.loads` with `unique_object` pairs hook (rejects duplicate keys) +
`reject_constant` (rejects NaN/Infinity) → require `schema == SCHEMA` ("explicit migration
required" error) + `command == "verify-forwarding"`.
`consume(source, format, exit_code)` L224-269: json → one aggregate decode ≤MAX_RECORD;
ndjson → line loop: `line.endswith(b"\n")`, contiguous `sequence` from 0, `event in
{"event","complete","error"}`, terminal exactly-once, no post-terminal records; then
`status`/`event` agreement, error-envelope → `{"execution":"error"}` (exit must be nonzero),
success → `validate_report(terminal["result"])` → verdict `pass/fail/inconclusive` vs exit
code (0 iff pass). `validate_report` L152-221 enforces rules/capture/summary counters,
omission sums, declared-check ordering, per-check state machines.
**v7 work**: `SCHEMA` → family dispatch `{v6: <v6 semantics>, v7: <v7 semantics>}` — v7 NDJSON
first record selects family for the whole stream, mid-stream family switch rejected
(spec L26-30); forwarding semantics identical today, kept behind an explicit dispatch so
future divergence is contained.

### `examples/consumers/fixtures/v6-forwarding.json` (190 lines)

Frozen single-record NDJSON envelope: schema/command/mode=stream/sequence=0/event=complete/
status=success/result{verdict pass, rules{identity/preserve/expect/comparison/warnings/
preserve_presence/expect_absent}, assumptions[], captures{ingress,egress:path+read+selected+
keyed+unkeyed+incomplete}, summary{unique_matches…checks_unevaluable}, matches[key+ingress/
egress{frame,timestamp{unix_seconds,nanoseconds},link_type}+orders+reordered+checks[
{check{kind,field[,value]},outcome,expected/actual{type,value},expected_state,actual_state}],
violations, unmatched, unkeyed, ambiguous, omitted{…}} + diagnostics[].
**Frozen — do not modify. Add `v7-forwarding.json` beside it.**

### `examples/documents/` layout

~70 `output-*.json` files, one per `output-{command}-{kind}.json` where kinds come from
`published_example_matrix.rs:40-69` (`expected_kinds`): aggregate-only commands publish
`success`+`error`; stream commands add `event`+`complete`; all commands publish `error`.
Non-output siblings: `packet-*.json` (packet/v2), `rewrite-*.json`, `udp-profiles.json` —
unrelated families, untouched.

### How tests consume these

- `published_example_matrix.rs` (190 lines): `every_command_publishes_its_required_example_kinds`
  L71 — every `Command::ALL` × `expected_kinds` must exist as `output-{cmd}-{kind}.json`;
  `every_published_output_example_validates_against_the_schema` L82 — every output-*.json
  validates via `common::schema_validator()`; `every_published_error_code_agrees_with_its_kind`
  L151 — error code prefix ∈ `output_schema()["$defs"]["error"]["kind"].enum`.
- `published_schema_conformance.rs` (139 lines): validators per schema file via `include_str!`;
  output schema comes from `common::schema_validator()`; mutates example docs to test
  boundary accept/reject (source_frame≥1, query_type bounds, schema-version `const` rejection
  `"packetcraftr.output/v2"` L76-77).
- `ndjson_conformance.rs` (915 lines): `COMPLETION_FIXTURES` L19-120 — every NDJSON-capable
  command's published `*-complete.json`/`success` re-emitted through `StreamEncoder` +
  schema-validated; `production_typed_event_variants_are_schema_valid` L353 — real
  `output::*` event DTOs (read/capture/replay/follow/expert/tls/scan/traceroute/dns/fuzz/
  exchange/reassembly) emitted + validated; `validate_ip_event_stream` L486 — multi-event
  + terminal report + post-terminal rejection; framing/rejection tests L878-915.
- `aggregate_schema_conformance.rs` (1939 lines): `CASES` L73-120 — 50+ `fn() -> Value`
  cases keyed (Command, name); every case wraps `Envelope::success`/`published` + validates
  vs schema; `every_frozen_enum_serializes_exactly_the_vocabulary_the_schema_declares` L1695
  cross-checks `published_enum!` vocab vs schema `enum` lists.

---

## 6. Scripts + packaging

- `scripts/verify-archive.py` (125): `ASSETS` tuple L11-42 — includes
  `'schemas/packetcraftr.packet.v2.schema.json'`, `'schemas/packetcraftr.output.v6.schema.json'`,
  `'examples/consumers/forwarding.py'`, `'examples/consumers/fixtures/v6-forwarding.json'`
  (+rewrite/udp-profiles schemas, captures, selected output-*.json examples, docs,
  completions, `man/`). Verify L54-109: every asset nonempty → build-manifest identity →
  `--version`/protocols/build/dissect exact bytes → `--output ndjson read` stream: every
  record `schema=='packetcraftr.output/v6'` + int sequence == index + event frame|complete +
  terminal complete → JSON parse of packet-file build → man page per subcommand.
  **v7: add v7 schema + v7 fixture to ASSETS (keep v6 entries); update the stream assertion
  to the current family (or accept {v7} for current binary).**
- `scripts/test-verify-archive.py` (218): builds fixture archives from `VERIFIER.ASSETS`;
  CHILD stub emits v6 NDJSON L43-44; mutation modes exercise bad-schema/sequence/event/
  completion/non-object/unterminated/malformed/empty; `NativeArchiveTests` (env-gated)
  repackages a real binary + copies ASSETS.
- `scripts/test-output-consumer.py` (255): loads `forwarding.py` + v6 fixture; ~25 tests —
  valid fixture, additive fields, v5 rejection, truncation/duplication, enum validation,
  counters, verdict consistency, execution-vs-verdict, bounds, duplicate keys, exit-code
  contract, aggregate-json path. **v7: parametrized family runs (v6 fixture + v7 fixture +
  mixed-family stream rejection).**
- `scripts/check-native-capture.py` (125): opt-in native loopback smoke; `terminal()` L22-44
  parses NDJSON file: ≤16MiB/line, newline, unique keys, `schema=='packetcraftr.output/v6'`,
  `command=='capture'`, int sequence contiguous, exactly one complete|error terminal;
  `completed_sources` L47 — sources[].ready/shutdown_confirmed/metadata_valid===true +
  requested-settings applied. Emits evidence dir + manifest.
- `scripts/test-native-capture.py` (67): offline tests of `terminal()`/`completed_sources` —
  fixture from `examples/documents/output-capture-complete.json` + sequence injection.
- `scripts/forwarding-regression.py` (261): generates pcap fixtures + runs binary cases
  through `CONSUMER.consume` (imports `forwarding.py` as `CONSUMER`) — follows whatever
  family dispatch the consumer gains; manifest `packetcraftr.regression/v1`.
- `scripts/test-forwarding-regression.py` (84): generator/checksum/budget/contract tests —
  no schema literals.
- `scripts/check-external-consumer.py` (51): compiles an external Rust API consumer offline —
  unaffected.
- `scripts/check-architecture.py` (60): Cargo-metadata dependency direction — unaffected.
- `.github/workflows/release.yml`: staging `assets` tuple L232-252 (includes forwarding.py +
  v6 fixture; `shutil.copytree("schemas", staging/"schemas")` L259 ships ALL schema files —
  v7 schema auto-included once added; L261 copies all of docs). Archive smoke runs
  `verify-archive.py` L277-281 — so verifier ASSETS is the real gate.

---

## 7. Test helpers

`src/test_support.rs` (100 lines, `#[cfg(any(test, feature="test-support"))]`):
- `SharedBuffer` L14-39 — `Arc<Mutex<Vec<u8>>>` `impl Write`; `bytes()`, `records()` (parse NDJSON).
- `stream(command)` L42 — `(StreamEncoder, SharedBuffer)` over `StreamEncoder::new`.
- `parse_ndjson(bytes)` L47 — UTF-8 + trailing-newline assert + per-line `serde_json::from_str`.
- `assert_contiguous(records)` L61 — sequence == index.
- `output_schema()` L71 — embedded v6 schema OnceLock; `schema_validator()` L83 (`#[cfg(test)]`).
- `TestRecord<T>` L92-100 — `#[serde(transparent)]` `impl StreamRecord` → `"frame"`.

`tests/common/mod.rs` (121): re-exports `SharedBuffer/TestRecord/assert_contiguous/
output_schema/stream`; integration `schema_validator()` L21; `path_text(path)` L28 (UTF-8
temp path); `run(arguments)` L32 → `Command::new(CARGO_BIN_EXE_packetcraftr)` → `Output`
(stdout/stderr as `Vec<u8>`); `run_success` L39 (asserts success + dumps output on fail);
`parse_json(output)` L50 — newline-terminated stdout → `serde_json::from_slice` →
schema-validated; `parse_ndjson(output)` L68 — same per record. Capability gates:
`require_procfs()` L85 `#[cfg(packetcraftr_test_procfs)]`, `require_util_linux_script()` L103,
`require_dev_full()` L116 (stdout→/dev/full write-failure contracts).
`tests/common/process.rs` (45): `run_with_stdin(args, input)`, `decode_hex`,
`append_truncated_record`. `tests/common/stats_report.rs` (152) + `tls_capture.rs` (466) —
domain fixture builders.

Failure-injection writers used across unit tests (patterns to reuse): `FailAfter` (byte
budget + flush fail), `BlockedWriter`/`Blocked`/`WaitingWriter` (mpsc-gated write),
`FailingSerialization` (serde error mid-seq), `SpendDuringSerialization` (flag in
`serialize`), `SharedBuffer` (read-back), `/dev/full` via `require_dev_full`.

---

## 8. CLI test targets (v7 assertion placement)

- `tests/aggregate_schema_conformance.rs` (1939): 50+ real-DTO envelope cases vs schema;
  frozen-enum vocab cross-check; additive-field tolerance + invalid-field rejection.
  **v7: cases auto-flow once `output_schema()` points at v7; add case fns for new v7 fields
  (transactions/body_export/gate/split result) and vocab entries.**
- `tests/ndjson_conformance.rs` (915): completion fixtures inventory == every NDJSON command;
  typed event emission; multi-event streams; framing/terminal rules.
  **v7: same auto-flow; extend `COMPLETION_FIXTURES` only if command set changes; add v7
  event-type emits (http_transaction etc.) to `production_typed_event_variants_are_schema_valid`.**
- `tests/published_schema_conformance.rs` (139): schema↔example boundary checks.
  **v7: schema const assertion lines (e.g. L76 "packetcraftr.output/v2" reject still works;
  maybe also assert v6 const is rejected by v7 schema).**
- `tests/published_example_matrix.rs` (190): example inventory + schema validation + error
  code/kind consistency. **Auto-flows; add expected_kinds for any new command.**
- `tests/machine_contracts.rs` (75): envelope discriminator assertions (schema/mode/status/
  sequence presence). **v7: swap `SCHEMA_V6` import/expect to `SCHEMA_V7`.**
- `tests/process_contracts.rs` (1366): process-level contracts; L226 literal v6 assert in
  `offline_build_supports_json_hex_and_raw_without_terminal_style`; `stalled_ndjson_stdout…`
  L1024; `published_quick_start_capture_reads_as_a_complete_stream` L1098.
  **v7: literal → v7.**
- `tests/forwarding_verification_contracts.rs` (902): verify-forwarding verdicts/exits/
  terminal records; L635 v6 literal. **v7: literal → v7.**
- `tests/output_conversion_contracts.rs` (390): DTO From/TryFrom field-preservation checks —
  no schema literals; **extend for new v7 DTO conversions.**
- `src/output/stream/tests.rs`: add prepared-complete tests per spec L36-40: no write/state
  during prepare; envelope/newline/resource sizing; same-encoder + sequence enforcement;
  normal write/flush failure → Failed; error publication after discarded prepare.
- `src/rendering/machine.rs` tests: `bounded_*_json_len` exact-count/limit/serialize-failure
  already covered; add `prepare_aggregate` no-emit + publish-through-emit_json coverage if
  seams get unit tests (spec asks same coverage class).

Python side: `scripts/test-output-consumer.py` (family-parametrized + mixed-stream),
`test-verify-archive.py` (ASSETS-driven mutations — follows ASSETS automatically),
`test-native-capture.py` (literal schema updates), `test-forwarding-regression.py` (unchanged).

---

## 9. Spec cross-check: exact edit surface for BASE-01

Issue L42-56 lists `output/{contract,envelope,http,expert}.rs`, `stream.rs`, `stream/tests.rs`,
`rendering/machine.rs`, `test_support.rs` + CLI test targets + consumers/fixtures/scripts/
release.yml/docs — matches findings above. Additional files the audit surfaced beyond the
issue's list: `tests/process_contracts.rs:226`, `tests/forwarding_verification_contracts.rs:635`,
`tests/machine_contracts.rs:5`, `src/output/stream/tests.rs:306` (literals),
`docs/consumer-compatibility.md`, `README.md`, `CHANGELOG.md`, `docs/migration-unreleased.md`,
`scripts/test-verify-archive.py:43-44`, `check-native-capture.py:37`, `test-native-capture.py:58`.
