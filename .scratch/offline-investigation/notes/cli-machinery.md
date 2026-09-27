# CLI machinery research for the offline-investigation batch

Research for implementing the four feature specs under `.scratch/`
(`http-transactions`, `http-body-export`, `capture-split`, `expert-ci-gates`).
This note documents existing machinery only; the specs are authoritative for
new behavior. Paths are relative to repo root `/home/ubuntu/code/pcr/1/pcr`;
the crate root is `crates/packetcraftr-cli` unless stated otherwise. Line
numbers are from the `tyk/offline-investigation` checkout.

## 1. Command registration: `src/commands.rs`

### Module list and the `commands!` declaration

Every command is one module under `src/commands/` (declared at
`src/commands.rs:40-70`) plus exactly one entry in the `commands! { ... }`
invocation at `src/commands.rs:228-315`. Per the module-header convention
(`src/commands.rs:4-23`): `commands/<cmd>.rs` holds the `Spec` impl,
validation, composition, and format dispatch; `commands/<cmd>/arguments.rs`
holds clap `Args` plus `AFTER_LONG_HELP`; `commands/<cmd>/rendering.rs` holds
text rendering only; helpers sit beside them (`follow/write.rs`); shared clap
groups live in `command_options/`. A declaration line looks like
`Http(http::arguments::Args) = "http"` with
`#[command(after_long_help = http::arguments::AFTER_LONG_HELP)]`.

The `= "name"` literal is significant (`src/commands.rs:111-117`): a variant
**with** a published name is an output-contract command — it gets a `Command`
enum variant serialized under that name (also its command-line name) and
startup routes it through `Launch::publish`. A variant **without** a name
(`Documentation(documentation::arguments::Args)` at :313-314) writes files via
`Launch::generate`. From the one list (:139-225) the macro derives
`enum CommandLine` (clap `Subcommand`), `CommandLine::offline()`
(`Spec::OFFLINE`; `false` for unnamed variants), `preset_defaults(preset)`,
`start(launch)` (dispatches to `publish`/`generate`), and `pub enum Command` —
the frozen output-contract vocabulary with `Command::ALL`, `as_str()`, and
`formats()` (= `<<Args as Spec>::Format as FormatSubset>::FORMATS` per
variant). Adding `split` is therefore: `mod split;`, one
`Split(split::arguments::Args) = "split",` line in `commands!` (hand-sorted in
`--help` order), and the `Spec` impl — the rest follows automatically.

### The `Spec` trait (`src/commands.rs:77-109`)

```rust
pub(crate) trait Spec: Sized {
    type Format: FormatSubset;
    const CANCELLATION: bool;
    const OFFLINE: bool = false;
    fn run_time(&self) -> Option<&dyn Bounded> { None }
    fn publication_duration(&self) -> Option<Duration> {
        self.run_time().map(Bounded::max_duration)
    }
    fn resources(&self, _settings: &mut Settings<'_>) {}
    fn run(self, format: Self::Format, stream: &StreamEncoder)
        -> Result<CommandExit, CliError>;
}
```

- `Format` — a narrow enum declared by `format_subset!`; most offline analysis
  commands use `ToolFormat` (text/json/ndjson, contract.rs:165-173), `stats`
  uses `AggregateFormat` (text/json only, :157-163).
- `CANCELLATION` — startup installs the shared SIGINT handler before dispatch
  (`src/startup.rs:151-155`); `OFFLINE` gates `--resource-preset`
  (`src/presets.rs:47-55`).
- `run_time()` — the `Bounded` group owning `--max-duration-ms`;
  `publication_duration()` becomes the invocation deadline.
- `resources()` — declares every `--max-*` setting for diagnostics/presets
  (§3); `run()` — narrowed-format dispatch; returns `CommandExit`.

`commands::execute` (:319-330) enters the deadline (`invocation::enter`),
clones the stream with it (`with_deadline`), narrows the global format via
`kind.require_format(format)` (contract.rs:32-41 — unsupported combinations
fail **before any I/O**), then calls `arguments.run(...)`. Reference impls:
`merge` (`commands/merge.rs:18-34`) — `ToolFormat`, cancellation + offline,
`run` maps a free `run()` onto `CommandExit::SUCCESS`; `stats`
(`commands/stats.rs:23-47`) — `AggregateFormat` (a no-NDJSON command uses the
narrower format type), `run_time = Some(&self.limits)`.

### `CommandExit` and the exit-1 precedent

`CommandExit` (`commands.rs:338-356`) is a `u8` wrapper with
`CommandExit::SUCCESS` (= 0), `const fn status(u8)`, `const fn get()`. Its doc
comment (:332-337) states the rule: almost every command exits `SUCCESS`; a
command whose result is a *verdict* reports it through `CommandExit` instead
of an error record. The precedent is `verify-forwarding`
(verify_forwarding.rs:27, :147-156):

```rust
const VERDICT_NOT_PASS: u8 = 1;
let exit = match report.verdict {
    forwarding::Verdict::Pass => CommandExit::SUCCESS,
    forwarding::Verdict::Fail | forwarding::Verdict::Inconclusive => {
        CommandExit::status(VERDICT_NOT_PASS)
    }
};
rendering::render(format, stream, &report, &arguments, ...)?;
Ok(exit)
```

Ordering matters: the report is rendered **first**, then the status returned —
a rendering failure wins over the verdict exit, and no error record follows a
completed report. `Spec::run` returns the `CommandExit` directly
(verify_forwarding.rs:58-64). Expert gates mirror this: publish normally, then
`Ok(CommandExit::status(1))` for fail/inconclusive. The root `--help`
exit-code table at `src/cli.rs:40` names only verify-forwarding for code 1 —
update it when expert gains verdicts.

### `commands/execution.rs` — the workflow driver (orientation only)

Live workflow commands (`scan`, `traceroute`, `dns`, `fuzz`, `exchange`,
`replay`, `capture`) share `run_workflow` (:69-105) via a `Hooks` struct
(:37-58): `Emit<E>` (:16), `run: Collect<S, R>` (:19), `run_with_events:
Publish<S, E, U>` (:22), `on_event`/`into_result`/`render_text`/`complete`
adapters (:47-57); `emission_check` (:110-113) wraps each emission with
cancellation + deadline. None of the four features uses this — they drive
`analysis::Session`/`capture_file` readers directly; `http`, `dns-read`,
`expert`, `export`, `verify-forwarding` are the models.

## 2. Argument conventions

Every command's `Args` is `#[derive(Debug, clap::Args)]` on a `pub(crate)`
struct; shared groups attach with `#[command(flatten)]` (http flattens
`application`, `decode`, `limits`, `commands/http/arguments.rs:35-40`). Leaf
options use `#[arg(...)]` with doc comments as help text; the vocabulary is
`value_name`, `default_value_t`, `value_enum`, `action = ArgAction::Append`
(repeatables — expert's `--code`), `required = true`, `value_parser =`.

### Offline capture limits (`command_options/offline_limits.rs`)

`OfflineCaptureLimitsArgs` (:50-60) holds `max_frames`, `max_bytes: u64` and a
flattened `reader: CaptureReaderBoundsArgs` (:65-82 — `max_encoded_bytes`,
`max_decoded_bytes`, `max_frame_bytes: usize`, `max_interfaces: usize`).
`retention_ceiling()` (:106-108) converts `max_frames` into the aggregate-JSON
retention bound (`commands/expert.rs:64`). `OfflineLimitsArgs` (:136-201) is
the full capture+analysis group (provenance, flows, scope bytes, TCP/IP
reassembly bounds, idle expiries, `ip_overlap`, `EpochBoundsArgs`,
`MaxDurationArgs<Analysis>`); `split` flattens `OfflineCaptureLimitsArgs` only
— it runs no analysis stages.

### `MaxDurationArgs<R>` and `RunTime` (`command_options/duration.rs`)

`RunTime` (:13-22) is a marker trait: `const HELP: &'static str` and `const
PARSED: RangeInclusive<u64> = 0..=u64::MAX`. `MaxDurationArgs<R>` (:42-52)
declares `--max-duration-ms` (default `MAX_MILLISECONDS` = 3_600_000, :27) with
`value_parser = clap::value_parser!(u64).range(R::PARSED)`. `PARSED` defaults
to unbounded; markers narrow it (fixture at :233-234). The split spec needs a
local `SplitRunTime` marker with `PARSED = 1..=3_600_000` so bad durations fail
as `cli.error` at parse time. `within_ceiling` (:78-86) is the post-parse check
for commands keeping the loose parser (`offline_analysis::prepare` calls it at
:99-105). `MaxDurationArgs::resources` (:88-90) declares `max_duration_ms:
Milliseconds @ Operation preset(30000, 300000)` — flattening the group carries
the frozen preset values automatically. `Bounded` (:56-59) is what
`Spec::run_time` returns. The same marker trick parameterizes `Budget`
(`command_options/policy.rs:64-69`), `Destination` (`compression.rs:37-42`),
`Window` (`duration.rs:104-113`) — e.g. `CaptureDestination`
(`capture/arguments.rs:241-247`), `Analysis` (`offline_limits.rs:203-209`).

### Mutual requirements, compression, help

`requires = "arg_id"` is a direct clap attribute (dns's `--dnssec-ok` requires
`--edns-udp-payload-size`, `dns/arguments.rs:58`); `conflicts_with` /
`conflicts_with_all` appear at `dns/arguments.rs:65`, `scan/arguments.rs:140-143`.
Arg ids are snake_case field names. HTTP body export wants both directions:
`body_message` with `requires = "write"` and `write` with
`requires = "body_message"` — pairing failures stay ordinary clap `cli.error`
usage/2. For mass requirements on an inherited group,
`#[command(mut_arg("id", |arg| arg.requires("live")))]` at
`fuzz/arguments.rs:42-59` is the pattern. Context-dependent checks run in `run`
— `capture` rejects rotation-without-`--write` and JSON-without-`--write` at
`commands/capture.rs:94-124` via `CliError::new(Kind::Usage, ...)`.

`CompressionArgs<D: Destination>` (`compression.rs:49-55`) is one flattened
`--compression none|gzip|zstd` group. `for_output(format)` (:64-74) rejects
compression for non-capture formats; `for_file()` (:77-79) returns it for
saved files. `SavedPcapNg`/`CaptureStdout` are the existing markers (:82-97);
`split` needs its own (its files may be classic PCAP).
`Compression::writer(w)` (:32-34) wraps a writer in `compression::Output`,
whose `finish()` runs **before** `sync()` — `merge` calls
`writer.into_inner().finish()`, `staged.sync()`, `staged.persist()`
(merge.rs:86-89); `export` the same via `writer.finish()` (export.rs:90). Each
published command supplies `#[command(after_long_help = ...)]` in `commands!`;
the constant is paragraphs ending in an `Examples:` block
(`http/arguments.rs:12-19`; `verify_forwarding/arguments.rs:10-21` documents
exit codes in prose — the convention the expert spec follows). Doc comments
double as the `scope` text diagnostics copies (`resources.rs:321-324`).

`--output` is a global `value_enum` on the root `Cli` (`cli.rs:100-109`),
converted to `output::contract::Format` at :151-165; other globals are
`--resource-diagnostics`, `--resource-preset`, `--output-timeout-ms`
(NDJSON-only, startup.rs:136-143), `--force-binary-stdout`, `--color`.
`Selector<T>` (`command_options/stream.rs:22-44`) stores raw text plus a
deferred `Result<T, String>`; `get()` (:39-43) raises the usage error where
the command reads it, preserving error precedence. `stream_selector` (:59-65)
parses `tcp:INDEX`/`udp:INDEX` into `analysis::StreamRef`; HTTP's TCP-only
restriction is command-side validation (`commands/http.rs:63-68`).

## 3. Resources and presets (`src/resources.rs`, `src/presets.rs`)

### Vocabulary

`enum Unit { Count, Bytes, Milliseconds, Policy }` (:38-44); `enum Stage`
(:59-74) — `Output`, `CaptureStorage`, `Preparation`, `Comparison`,
`ObservationCollection`, `ResultRetention`, `IndexedMetadata`, `NativeCapture`,
`PhysicalInput`, `Operation`, `ActiveState`; `enum Enabled { Fixed(bool),
StreamIndex }` (:96-103) — `StreamIndex` defers until `stream_index_needed(bool)`
runs after filters compile (:457-461; used at `verify_forwarding.rs:101-107`);
`SettingValue` (:112-132) covers `u8`/`u64`/`usize`/`Option<T>`; `policy_value`
(:135-139) renders a `ValueEnum` under its CLI spelling.

`declare!` (:174-204) names typed fields — the field name **is** the clap arg
id (asserted at :288-301 and by the every-command test at `commands.rs:392-415`):

```rust
declare!(settings, self, [max_http_body_bytes: Bytes @ Operation]);
declare!(settings, self, [
    max_flows: Count @ IndexedMetadata preset(1024, 8192) if index,
    max_ip_outcomes: Count @ ResultRetention preset(128, 1024) if index,
]);
```

`preset(ci, ws)` supplies `ci-v1`/`workstation-v1` defaults; `if expr` marks a
stage-enabled setting. An unset `Option` field is skipped by diagnostics but
still receives its preset (:251-258, :282-284).
`Settings::retained_result_items(max_frames)` (:265-269, :331-349) declares an
aggregate-JSON retention bound derived from the frame ceiling (expert,
`commands/expert.rs:31`); only `enabled` under `--output json`.

### Emission path and presets

`resources::configure` (:399-412) stores settings + a runtime registry in a
`OnceLock` at startup (`startup.rs:90-103`) — only for JSON/NDJSON, else a
usage error (:120-135). `snapshot()` (:481-519) produces the `Report`
(`settings`, `workers`, `cooperative_deadlines`, `hard_rss_limit`); workers
include `native_process`, `tcp_connect_process`, and each `resources::runtime`
registration (:465-479 — the NDJSON writer registers `output_writer`,
`rendering/ndjson.rs:28`). `decorate` (:521-526) attaches the report to an
envelope; JSON aggregates decorate inside `emit_aggregate`
(`rendering/machine.rs:110-112`), NDJSON attaches to sequence-0 and the
terminal record only (`output/stream.rs:281-286`). Each `Setting` carries
`name` (`--long` spelling), `value`, `unit`, `stage`, `scope`, `source`,
`enabled` (:315-327); `source` is `"override"` for `ValueSource::CommandLine`,
`"preset:<name>"` for a preset default, else `"default"` (:308-314).

`Preset::{CiV1, WorkstationV1}` (`presets.rs:14-27`). `parse_from` (:41-60) is
a two-pass parse: parse once; if `--resource-preset` is present and the command
`offline()`, collect `preset_defaults` and re-parse argv against a mutated
command tree (`definition` at :32-39 sets each declared arg's `default_value`).
Command-line values keep `ValueSource::CommandLine` and always win regardless
of flag order (tested at :101-141). A preset on a non-offline command is an
`ArgumentConflict` error. New settings take preset values only where a feature
spec lists them (split's four bounds); frozen values do not change.

## 4. `EventOutput` and `offline_analysis::inspect` — the application-event seam

### `EventOutput` (`src/commands/application_output.rs:11-51`)

```rust
pub(super) struct EventOutput<'a> {
    format: ToolFormat,
    stream: &'a StreamEncoder,
    remaining: usize,
}
impl<'a> EventOutput<'a> {
    pub(super) fn new(format: ToolFormat, stream: &'a StreamEncoder,
                      maximum: usize) -> Self;
    pub(super) fn emit<T: StreamRecord>(
        &mut self,
        value: T,
        retained: &mut Vec<T>,
        render_text: impl FnOnce(&T) -> Result<(), CliError>,
    ) -> Result<(), CliError>;
}
```

`emit` (:32-48) does three things, in order:

1. `bounded_json_len(&value, self.remaining)` — serializes the value to a
   **counting** writer under the remaining budget
   (`rendering/machine.rs:32-83`). `Limit` maps to `CliError::new(Kind::Policy,
   "application output exceeds --max-application-output-bytes")` (fallback code
   `policy.denied`, exit 6); a serialization failure becomes `Kind::Internal`
   (exit 70). The budget is **not** charged on failure — `self.remaining -=
   bytes` runs only after successful sizing (:40).
2. Routing: `Json` appends to the caller's `retained` vector; `Ndjson` calls
   `stream.emit_data(value, Vec::new())` (`EncodeError` → `CliError` via `From`
   at `errors.rs:144-148`, preserving `io.stdout` classification); `Text` calls
   the supplied renderer, whose `CliError` propagates unchanged. Serialized-JSON
   size is the measure of "application output" in every format — the budget is
   charged for **text** too (per the flag's help,
   `command_options/application.rs:29-31`).

Invariants proven by its tests (:101-262): one budget shared across record
types and vectors; a sizing failure leaves the stream untouched so the NDJSON
prefix stays publishable (`http_contracts.rs:146-183` shows
`["http_message", "error"]` after exhaustion); a serialize failure still leaves
the stream open for the terminal error. Per the body-export spec, `inspect`
will change to borrow `&mut EventOutput` from the command, and `EventOutput`
gains `charge(&impl Serialize)` — `emit` delegates its sizing step to it, so
the artifact-metadata charge lands on the same remaining allowance.

### `offline_analysis` (`src/commands/offline_analysis.rs`)

```rust
pub(super) struct Inspection<'a> {                    // :118-124
    path: &'a Path,
    limits: OfflineLimitsArgs,
    decode: &'a DecodeArgs,
    application: ApplicationLimitsArgs,
    selector: Option<StreamRef>,
}
pub(super) fn inspect<C: analysis::Collector>(        // :132-162
    inspection: Inspection<'_>,
    collector: C,
    format: ToolFormat,
    stream: &StreamEncoder,
    mut publish: impl FnMut(&mut EventOutput<'_>, C::Event) -> Result<(), CliError>,
) -> Result<analysis::Outcome<C>, CliError>;
```

`inspect` (:139-161): `prepare(limits, None, decode)` → `Session::new(registry,
setup.options(), collector, selector)` → `open_capture(path,
limits.capture.reader)` → `EventOutput::new(format, stream,
application.max_application_output_bytes)` → `session.run(&mut reader,
ip_event_sink(format, stream), |event| publish(&mut output, event)
.map_err(CliError::into_boundary_error))` → reject `selected_absent()` with
`Kind::Usage` (:158-160). It returns `analysis::Outcome<C>` — `outcome.run`
(the pipeline `Summary`,
`packetcraftr-core/src/analysis/pipeline.rs:224-247`: `frames_read`,
`bytes_read`, `frames_matched`, `clock`, `ip_reassembly`, `incomplete_sources`,
`source_outcomes_omitted`, `trailing_tcp_events`, `interfaces`, `scopes`),
`outcome.summary` (the collector's own `Summary`), `outcome.scopes`.

`prepare` (:59-114) validates capture bounds (`validate_capture_stream_limits`,
`input.rs:450-487`), builds the decode registry, compiles an optional filter
with `Capabilities::stream_capable()` (`filtering.rs:35-38, 40-67`), maps every
`OfflineLimitsArgs` field into `analysis::Limits` (TCP flow count is
`max_flows * 2`, :80-87), validates it, and checks the duration ceiling.
`AnalysisSetup::options()` (:41-54) installs the invocation deadline and the
shared `Cancellation` into `analysis::Options` — session-driven commands need
no further deadline/cancellation wiring. Supporting helpers in the same module:
`Retained<T>` (:165-197) — bounded retention with an `omitted` counter whose
`push` skips the conversion closure at the ceiling; `omitted_diagnostic`
(:201-214) — the one warning a truncated document carries; `ip_event_sink`
(:219-235) — IP reassembly lifecycle events reach **NDJSON only**, other
formats fold them into the terminal `ip_reassembly` report;
`render_scope`/`render_clock` (:237-255) — shared text lines.

`Collector`/`Session` (core `analysis/session.rs:38-79`): `CollectorNeeds`
flags (`tcp_stream`, `udp_stream`, `ip_reassembly`, `tcp_events`,
`track_sources`) are unioned with filter requirements when the session narrows
the pipeline `Plan`; `observe` failures become `Error::Sink` attributed to the
folded frame — an `EventOutput` budget failure surfaces as `"analysis consumer
failed at frame N"` with the policy error as a `cause`
(`http_contracts.rs:80-141`); `finish` failures surface as `Error::Collector`.
**EOF findings flow through the same `publish` closure** — exactly what the
expert gate needs (§7). Callers: `http` (`commands/http.rs:70-93`) emits
`wire::Message`/`wire::Issue` then a terminal `wire::Complete`; `dns-read`
(`commands/dns_read.rs:53-85`) adds `wire::Transaction` between them —
`--transactions` slots a third arm into `http`'s `match event` with
`Event::Transaction(Box<Transaction>)`, its own retained vector + renderer,
charged through the same `EventOutput`.

## 5. Staged files and publication (`src/staged_output.rs`, `commands/follow/write.rs`)

### `StagedFile` (`staged_output.rs:21-89`)

```rust
pub(crate) struct StagedFile { file: tempfile::NamedTempFile, destination: PathBuf }
impl StagedFile {
    pub(crate) fn stage(destination: &Path) -> Result<Self, CliError>;   // :30
    pub(crate) fn destination(&self) -> &Path;                           // :58
    pub(crate) fn as_file_mut(&mut self) -> &mut std::fs::File;          // :62
    pub(crate) fn sync(&self) -> Result<(), CliError>;                   // :69
    pub(crate) fn persist(self) -> Result<(), CliError>;                 // :79
}
```

Every failure uses classification `io.output_file`/`Kind::Io` (:13-17) via the
`output()` helper (:91-100), which puts `source.to_string()` plus
`source_chain(&source)` into `causes` — the I/O source is never flattened into
the headline.

- `stage` (:30-56): `cancellation::check()` first; `symlink_metadata` rejects
  existing files **and dangling symlinks** (tests :108-134); the parent
  defaults to `"."` when empty; `NamedTempFile::new_in(parent)` keeps staging
  on the destination's filesystem. Staging happens **before any input is read**
  (`merge` stages at :44 before opening sources; `export` at :62 before
  `snapshot_capture`; body export stages the same way per its spec).
- `sync` (:69-76): `cancellation::check()` before and after `sync_all()`.
- `persist` (:79-88): `cancellation::check()` immediately before
  `persist_noclobber` — the comment (:80-82) is the rule the artifact commands
  honor: *the successful rename is the commit boundary; expiry after commit
  must not claim rollback* (test :216-241).
- Drop of the `NamedTempFile` removes unpublished temporaries — best effort,
  unreported (the body spec explicitly keeps that promise level).

Callers writing through a compressor wrap `staged.as_file_mut()` in a 64 KiB
`BufWriter` + `compression.for_file().writer(...)`, then `finish()` the
compressor **before** `sync()` (`merge.rs:55-89`, `export.rs:78-96`).
`export.rs:91` carries the convention the batch formalizes: *"Construct all
fallible report fields before publishing the saved capture."* The
`seal`/`SealedFile` split the spec describes does not exist yet — there is no
`into_temp_path` call in `src/` today (only `NamedTempFile::new_in` +
`persist_noclobber` at `staged_output.rs:50,85` and capture rotation at
`commands/capture/files.rs:305-310`); implementing it means sync, close via
`into_temp_path`, retain the path for a later `persist_noclobber`,
drop-cleanup unchanged.

### The multi-file publish/rollback helper (`commands/follow/write.rs`)

`DirectionFiles` (:37-40) holds `staged: Vec<Staged>` plus one shared
`remaining: usize` byte budget. `stage` (:45-75) builds deterministic
destinations `{transport}-{index}-{client|server}.bin` (:58-63) and calls
`StagedFile::stage` on **every** selected destination before the capture is
read — collisions fail early with no input consumed (test :239-247); `write`
(:79-109) ignores unselected-direction chunks, rejects a chunk larger than the
shared remaining budget with `Kind::Policy`, and charges before writing.

The ordered publication helper the split spec wants extracted into
`staged_output.rs` (:114-171):

```rust
pub(super) fn publish(self) -> Result<Vec<Written>, CliError>;
fn publish_with(
    self,
    mut sync: impl FnMut(&StagedFile) -> Result<(), CliError>,
    mut remove: impl FnMut(&Path) -> std::io::Result<()>,
) -> Result<Vec<Written>, CliError>;
```

Its exact algorithm: sync **every** staged file first — no destination is
published until all are synchronized (in-code comment at :124) — then persist
in deterministic order, collecting `Written` results and a `published` path
list. On a `persist` failure it removes each of *this invocation's* published
paths, counts successes as `rolled_back`, collects `remove` failures as
`CliError::new(Kind::Io, "remove published follow output ...")` secondaries,
rebuilds the primary error via `CliError::from_classification` with the
message `"{orig}; rolled back {rolled_back} published file(s)"` plus the
original `causes`, attaches each cleanup failure via
`failure.with_secondary("follow rollback", cleanup)`, and returns it.
`publish` injects `StagedFile::sync` and `std::fs::remove_file`, making the
ordering/rollback independently testable.

Contract it proves (tests :250-361): sync-all-then-persist ordering (a
second-file sync failure leaves zero destinations and allows a clean retry);
deterministic publication order; on a persist failure only this invocation's
published paths are removed, a colliding third-party file is untouched, the
primary classification is preserved while cleanup errors append via
`with_secondary`, and the message reports the real rolled-back count — never
"all removed" when cleanup failed. Unpublished staged files clean up on drop.
It is **not** a filesystem transaction; the report must be prepared before
the first commit, and a post-commit failure leaves earlier artifacts in place
with honest reporting.

## 6. The `http` command shape — where transactions and body export attach

### Arguments (`commands/http/arguments.rs:21-41`)

```rust
pub(crate) struct Args {
    pub(crate) path: PathBuf,                                  // positional; "-" = stdin
    #[arg(long, value_name = "TRANSPORT:INDEX", value_parser = stream_selector)]
    pub(crate) stream: Option<Selector<StreamRef>>,
    #[arg(long = "http-port")] pub(crate) http_ports: Vec<u16>,
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub(crate) max_http_body_bytes: u64,
    #[command(flatten)] pub(crate) application: ApplicationLimitsArgs,
    #[command(flatten)] pub(crate) decode: DecodeArgs,
    #[command(flatten)] pub(crate) limits: OfflineLimitsArgs,
}
```

`--transactions` becomes a `bool` field; `--body-message` a `Option<u64>` with
`requires = "write"`, and `write: Option<PathBuf>` with
`requires = "body_message"`.

### `Spec` and `run` (`commands/http.rs`)

`Spec` (:25-50): `ToolFormat`, `CANCELLATION = true`, `OFFLINE = true`,
`run_time = Some(&self.limits)`; `resources` declares
`max_http_body_bytes: Bytes @ Operation`, then
`self.application.resources(settings)` and
`self.limits.resources(settings, AnalysisStages::with_tcp(true))`.

`run` (:52-105) — the sequence every HTTP extension must fit:

1. `args.application.validate_output()` — `--max-application-output-bytes`
   must be `1..=268435456` (`command_options/application.rs:60-68`).
2. `ports.extend([80, 8080])` — defaults merge with `--http-port`.
3. `Collector::new(args.application.core(), ports,
   args.max_http_body_bytes).map_err(CliError::classified)` — this is where
   `.with_transactions()` and `.with_body_sink(message, sink)` chain on,
   **before** the first `observe` (spec: configuration closes on first observe;
   repeated `with_transactions` is idempotent before it).
4. Stream-selector validation — `Selector::get()` then the TCP-only check
   (:58-68), `Kind::Usage`. The body spec's precedence rule (a `--stream`
   selection error beats an absent body message) follows from this order.
5. `inspect(...)` with the event callback (:70-93): each `Event` maps to
   `output.emit(<DTO>, &mut <retained>, <renderer>)`. A `Transaction` arm slots
   in beside `Message`/`Issue` with a `transactions` vector and
   `rendering::render_transaction`; NDJSON gets `event_name() =
   "http_transaction"`; JSON gains a `transactions` array in `Report`.
6. Terminal: `wire::Complete::try_from((&outcome.run, outcome.summary,
   outcome.scopes))` then dispatch — `Json → emit_aggregate(Command::Http,
   Report::from((messages, issues, complete)), Vec::new())`, `Ndjson →
   stream.complete(complete, Vec::new())`, `Text →
   rendering::render_complete`. `transaction_summary` and `body_export` ride on
   `Complete`/`Report` (null when disabled).

For body export the command owns `EventOutput` directly (per the spec's
`inspect` refactor), `commands/http/body.rs` holds the disjoint `BodyWriter`
(`BufWriter<&mut File>` + SHA-256 + count; `sha2` is already a dependency —
`Cargo.toml:40`) and `SelectedMessage` tracker updated from the same event
callback. End-of-run order: consume the collector → flush/`finish` `BodyWriter`
→ validate the selected message status and byte count →
`EventOutput::charge(&body_export_dto)` once → build the prepared success
record → `sync`/`persist` → publish the prepared result.

### Text rendering (`commands/http/rendering.rs`)

`render_message` (:13-45): one sanitized summary line per message —
`"HTTP tcp:{} message={} status={} {} body_bytes={} request={} frames={}"` —
then two-space-indented header lines and an optional `error:` line. All
captured text goes through `escaped` (:68-70, `char::escape_default`); the test
(:77-82) proves control and bidi characters are stripped. `render_issue`
(:47-52), `render_complete` (:54-63, `write_summary_line`). Transactions add
one escaped line per row and extend the summary only when enabled.

### Wire DTOs (`src/output/http.rs`)

`Status` (:17-30) is a `published_enum!` from `analysis::Status`
(complete/incomplete/malformed/limit/gap/conflict/reset/evicted/upgrade) —
`"limit"` is a message **status**, not an error; body export maps it to
`policy.http_limit`. `Body` (:33-58) tags framing; `StartLine` (:62-101) keeps
decoded text *and* `target_hex`/`reason_hex`; `Header` (:104-118) keeps
`name`/`value`/`value_hex`. `Message` (:121-175): `index`, `stream`,
`generation`, `flow: ScopedFlowKey`, `request: Option<u64>` (the existing FIFO
association transactions reuse), `status`, `start`, `headers`,
`header_wire_hex`, `framing`, `body_bytes`, `trailers`, `error`,
`sources: Vec<Source>` — `TryFrom<analysis::Message>` can fail
(`output::contract::Error` on timestamp/source conversion). `Issue` (:177-198);
`Summary` (:200-222) has all seven counters; `Complete` (:223-252) is built
`TryFrom(&library::Summary, analysis::Summary, Vec<scope::Definition>)`;
`Report` (:253-270) flattens `Complete` — aggregate JSON gains
`transactions`/`transaction_summary`/`body_export` beside it; NDJSON `complete`
gains the same fields. `StreamRecord` impls: `Message → "http_message"`
(:171-175), `Issue → "http_stream_issue"` (:194-198); the `Transaction` DTO
adds `"http_transaction"`.

## 7. The `expert` command shape — where the gate attaches

`commands/expert.rs:17-41` — `Spec` as http's plus
`settings.retained_result_items(self.limits.capture.max_frames)` (:31).

`run` (:43-90): `prepare(limits, filter, decode)` (a `--filter` **is** passed,
unlike http/dns-read, which pass `None` and use a stream selector) →
`open_capture` → `Session::new(registry, options, expert::Collector::new(),
None)` → `session.run(reader, ip_event_sink(format, stream), callback)` — the
callback (:73-80):

```rust
|finding| {
    if selector.matches(&finding) {
        state.count(&finding);
        rendering::render_record(format, finding.into(), &mut state, stream)
            .map_err(CliError::into_boundary_error)?;
    }
    Ok(())
}
```

`selector` is `analysis::expert::Selector { min_severity, codes }` (:65-68)
built from `--min-severity` (the `Severity` value enum at `arguments.rs:22-38`
— reuse it for `--fail-on`) and repeated `--code` (:52-53). `state` is
`rendering::State` (:14-42): `selected: expert::Summary` counters plus
`Retained<Finding>` bounded by the frame ceiling — **only selected findings are
counted/retained**. Gate insertion point (per spec): inside this closure, call
`gate.observe(&finding)` **before** `selector.matches` so hidden findings still
gate; a gate error short-circuits the run through the same `BoundaryError`
path. Since `Session::finish` drains trailing findings through the same sink
(session.rs:63-72), EOF findings reach the gate for free. After `session.run`,
`gate.finish(summary.frames_matched)` yields the verdict; render the normal
report (each `render_*` gains the gate line/field), then
`Ok(CommandExit::status(1))` for fail/inconclusive.

Rendering (`commands/expert/rendering.rs`): `render_record` (:44-74) writes
text per-finding lines / retains for JSON / `stream.emit_data` for NDJSON
(`"finding"` event, `output/expert.rs:98-102`). `render_text` (:76-92) prints
the clock line, per-code `code=… findings=…` lines in BTreeMap order, then the
totals line. `render_aggregate` (:94-106) emits `Report` with the
`expert.findings_omitted` diagnostic; `render_stream` (:108-114) emits the
terminal record — both share `result()` (:116-138) where `include_findings` is
true only for JSON. `output/expert.rs:46-96` — `Report { clock, frames_read,
frames_matched, errors, warnings, notes, codes, findings, ip_reassembly }`; the
gate DTO joins as a required `gate: null | GateReport` on both aggregate and
terminal records (v7).

## 8. Generated documentation

`commands/documentation.rs:21-30` writes `completions/` + `man/` under
`--directory`; `documentation/rendering.rs:15-25` calls
`clap_complete::generate_to` per shell and `clap_mangen::generate_to` — **from
the finalized `Cli::command()` tree**, so a registered command and its args
appear automatically in `--help`, completions, and man pages. The contract test
(`tests/generated_documentation_contracts.rs:11-79`) scrapes the `Commands:`
section of `--help` and asserts one non-empty `packetcraftr-<cmd>.1` per
subcommand — adding `split` extends coverage without a handwritten list;
option-presence assertions follow the `--dissect`/`--decode-as` pattern. Update
`commands.rs` docs and each feature's `AFTER_LONG_HELP`/`Examples:` in the same
change.

## 9. Error conventions (`src/errors.rs`, `src/startup.rs`)

### `CliError` (`errors.rs:14-129`)

```rust
pub(crate) struct CliError {
    pub(crate) message: String,
    pub(crate) classification: Classification,   // { code, kind, remediation? }
    context: Option<Coordinate>,
    pub(crate) causes: Vec<String>,
    capture: Option<Box<output::capture::Snapshot>>,
    scan: Option<Box<output::scan::Failure>>,
}
```

Constructors:

- `CliError::new(kind, message)` (:26-35) — fallback classification from
  `fallback_code` (:157-166): `cli.error`/`packet.error`/
  `capability.unavailable`/`io.runtime`/`policy.denied`/`internal.error`.
- `CliError::classified(error)` (:37-42) — keeps a `Classified` source's
  code/kind/remediation/context/causes; **prefer this** whenever the source
  implements `Classified` (all public core errors do —
  `packetcraftr-core/src/error.rs:199-214`).
- `CliError::caused(kind, source)` (:46-52) — retains the typed source's
  rendered chain in `causes`; `CliError::refused_option(message, source)`
  (:56-65) — a usage error keeping the refusal's text+causes.
- `CliError::from_classification(classification, message, causes)` (:67-80) —
  fully explicit, the standard for new codes:
  `Classification::new("cli.capture_split", Kind::Usage, Some("remediation"))`
  (`packetcraftr-core/src/error.rs:67-82`).
- `.with_secondary(phase, error)` (:108-117) — appends a cleanup error without
  losing the primary (the publish-rollback helper uses it);
  `.into_boundary_error()` (:93-96) — converts into the `BoundaryError`
  callbacks return to core (`http`'s publish closure, `ip_event_sink`,
  `follow/write.rs`); `.output_error()` (:119-128) — the wire `envelope::Error`
  (code, kind, remediation, context, capture/scan attachments).

Typed-error-with-source convention: `thiserror` types with `#[source]` fields
preserve chains — `input.rs`'s `FileIo`/`InputRead` (:241-257), `PayloadFile`
(:166-172), `EncodeError` in `output/stream.rs:447-516` (`Deadline →
io.output_deadline`, `RecordLimit → io.output_record_limit`, `Write →
io.stdout`, else `internal.ndjson_stream`). `source_chain` (core
`error.rs:159-170`) renders distinct sources outermost-first, skipping
`#[error(transparent)]` duplicates.

### Exit codes (`errors.rs:170-193`)

`exit_code_for`: Usage→2, Packet→3, Capability→4, Io→5, Policy→6, Internal→70;
`CANCELLED_EXIT_CODE = 130` (:182). `CliError::exit_code()` (:84-86) is a pure
function of `classification.kind` — a new failure's exit status is decided by
choosing its `Kind`, so spec-mandated codes (`cli.capture_split`/Usage/2,
`policy.capture_split_limit`/Policy/6,
`packet.capture_split_source_changed`/Packet/3, `cli.http_body_message`,
`packet.http_body_incomplete`, `policy.http_limit`,
`internal.http_body_evidence`) are just `Classification`s. Exit 1 comes only
from `CommandExit::status(1)` — never from `CliError`.

### Startup publication (`startup.rs`)

`Launch::publish` (:68-175): binary-stdout terminal refusal (:74-89) →
resource-diagnostics configuration (:90-103) → stream creation (`ndjson` gets
`stdout_stream(command, timeout)`; others a plain encoder, :104-119) →
global-flag validation (:120-143) → cancellation install (:151-155) →
`commands::execute` (:156). On `Ok(exit)`: a late interrupt emits stderr + 130
for JSON (the aggregate is already out), or a terminal NDJSON error otherwise
(:158-167); `require_success_terminal` (:168-171, :223-234) turns a missing
NDJSON terminal record into Internal/"NDJSON command returned without a
terminal completion record". On `Err`: `command_failure` (:236-284) — a failed
NDJSON stream gets the synthetic `io.stdout`/"stream is incomplete" error
(:243-256); cancelled runs exit 130; then one structured error: JSON envelope
(:263-268), NDJSON `emit_error` when the stream is open (:269-274), or stderr
for other formats (:275). A failed error-publication write replaces the status
with the write error's (:277-282). An NDJSON command may therefore publish
earlier data events and still end in exactly one terminal record — success
(`complete`) or error, never both. `parse_error_exit` (:180-221) renders clap
errors in the negotiated format (JSON error envelope / NDJSON unattributed
error record via `rendering/ndjson.rs:36-54` / text documents), keeping clap's
own code (2 for usage).

### Contract and envelope (`output/contract.rs`, `output/envelope.rs`, `output/stream.rs`)

`SCHEMA_V6 = "packetcraftr.output/v6"` (contract.rs:13); the batch introduces
the v7 family — `Envelope` hardcodes `schema: SCHEMA_V6` in `success`/`record`/
`error` (`envelope.rs:249,269,300`), the single seam a v7 bump touches.
`Format` (:52-62) is the global 9-value enum; `FormatSubset`/`format_subset!`
(:96-155) generate narrow enums; `require_format` (:32-41) narrows before I/O;
`ToolFormat` (:165-173) is what all four features use.

`Envelope<T>` (`envelope.rs:219-234`): `schema`, `command`, `mode`
(aggregate|stream), `sequence`/`event` (stream only), `payload` tagged `status`
(`success → result` / `error → error`), `diagnostics`, `stats`, `resources`;
`Published<T>` (:182-203) carries result + diagnostics + optional stats.
`StreamEncoder` (`stream.rs:83-256`): `emit_data`/`emit_published` (data
records; `complete`/`error` are reserved event names, :186-190);
`complete`/`complete_published`/`complete_with_stats` (terminal); `emit_error`;
`is_open`/`is_terminal`/`is_complete`; `with_deadline` (:97-100) and
`with_resource_diagnostics` (:105-111) clone-attach. `MAX_RECORD_BYTES = 16
MiB` (:387) bounds every serialized line via `serialize_line` (:389-445);
`write_line` (:334-367) enforces the publication deadline around bounded writer
waits. The prepared-output seam the base spec describes
(`prepare_complete`/`publish_prepared_complete`) is new code riding on
`write_success`'s locked sequence/state machine.

## 10. Split-command assembly and cross-cutting checklist

The `split` command assembles: `Args` = path + `--frames-per-file` +
`--write-dir` + `CompressionArgs<SplitDestination>` +
`OfflineCaptureLimitsArgs` + `MaxDurationArgs<SplitRunTime>` (`PARSED =
1..=3_600_000`); `Spec` OFFLINE/CANCELLATION with `run_time` via the duration
group; `resources` declares the spec's four new bounds (`ResultRetention` file
count, `IndexedMetadata` metadata, `Operation` output bytes);
`input::snapshot_capture` (`input.rs:347-382`) supplies the seekable reader;
deterministic `part-NNNNNN.{pcap,pcapng}[.gz|.zst]` destinations (extension
from the detected container, not the source filename) are all staged before
generation, then synced, committed in order, and rolled back per §5. The
prepared complete record rides the BASE-01 seam (§9); core splitting logic is
covered by `.scratch/offline-investigation/notes/core-capture-file.md`.

Cross-cutting for all four features:

- Every new `--max-*` field must be declared in `resources()` or the
  every-command test at `commands.rs:392-415` (and the resource-diagnostic
  suite) fails.
- New published fields go in `src/output/` DTOs with `From`/`TryFrom`
  conversions, never a library serde derive.
- An NDJSON terminal record is mandatory on success (`startup.rs:223-234`).
- Machine output goes through the v7 schema + `schemas/` + `*_conformance.rs`
  updates (BASE-01/BASE-02 own the mechanics); `tests/resource_diagnostic_contracts.rs`
  also needs extension for split's new bounds (§3).
