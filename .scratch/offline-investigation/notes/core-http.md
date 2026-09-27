# Core HTTP investigation notes

Research for HTTP-T01 (header transactions + capture-observed timing) and
HTTP-B01 (selected-message body sink). Authorities:

- `.scratch/http-transactions/spec.md` (HTTP-T; acceptance HT01–HT15)
- `.scratch/http-body-export/spec.md` (HTTP-B; acceptance HB01–HB17)
- `.scratch/http-transactions/issues/01-core-header-transactions.md`
- `.scratch/http-body-export/issues/01-core-body-sink.md`
- `docs/adr/0005-http-artifacts-and-timing-preserve-observed-evidence.md`

All paths below are relative to `/home/ubuntu/code/pcr/1/pcr` and all line
numbers are as of branch `tyk/offline-investigation` (= main).

---

## 1. `crates/packetcraftr-core/src/analysis/http.rs` (974 lines) — the real work site

Module declared `pub mod http;` at `crates/packetcraftr-core/src/analysis.rs:25`.
Self-named module file: adding `mod transaction;` requires the directory
`src/analysis/http/` with `transaction.rs` inside (AGENTS: no `mod.rs`).

### Public types

- `Status` (lines 22–34): `Complete, Incomplete, Malformed, Limit, Gap,
  Conflict, Reset, Evicted, Upgrade` — `Copy`, `Serialize` snake_case.
- `Message` (35–51): `index: u64, stream: u64, generation: u64,
  flow: ScopedFlowKey, request: Option<u64>, status: Status,
  head: Option<Head>, header_wire: Bytes, framing: Option<Body>,
  body_bytes: u64, trailers: Vec<Header>, error: Option<http::Error>,
  sources: SourceSet`. `index` is 1-based parse-start order within the run.
- `Issue` (52–58): `number: u64` (attributing frame), `flow`, `stream`,
  `status`. Serialized for CLI wire.
- `Event` (59–63): `Message(Box<Message>) | Issue(Issue)` — exhaustive match
  in CLI (`commands/http.rs:81–92`); adding `Event::Transaction` will break
  that match and the fuzz targets' filters (both use `if let`/`match`, see §9).
- `Summary` (64–73): `messages, complete_messages, incomplete_messages,
  malformed_messages, upgraded_connections, responses_without_request,
  requests_without_final_response` — spec adds
  `transaction_summary: Option<TransactionSummary>`.

### Private state

- `Pending { index: u64, method: String }` (74–77) — one pending request;
  `method` is kept to feed `Head::body(request_method)` for HEAD/CONNECT
  response framing. Spec adds a "header-availability marker" field here.
- `Live { index, header: Vec<u8>, head: Option<Head>, body: Option<BodyDecoder>,
  framing: Option<Body>, request: Option<u64>, sources: SourceSet }` (78–86);
  `buffered()` (87–93) = pending header bytes + head wire len +
  `BodyDecoder::buffered_bytes`.
- `Direction { stream: u64, generation: u64, disabled: bool,
  live: Option<Live> }` (94–99) — one per `ScopedFlowKey` (per direction).
- `type Connection = (u64, u64);` = `(stream, generation)` (100).
- **`type RequestKey = (Connection, ScopedFlowKey)`** (101) — the pending
  queue key: `((stream, generation), request_direction_flow)`.
- `Collector` (102–113): `limits: Limits, max_body_bytes: u64,
  tcp: TcpSources, directions: BTreeMap<ScopedFlowKey, Direction>,
  requests: BTreeMap<RequestKey, VecDeque<Pending>>,
  upgraded: BTreeSet<Connection>, generations: BTreeMap<u64, u64>,
  buffered: usize, retained: usize, summary: Summary`.
  Spec adds: `transactions: bool`/config-closed flag, optional body-sink
  target, and a `Collector<'a>` lifetime for `&'a mut dyn BodySink`.

### Construction & entry points

- `Collector::new(limits, ports, max_body_bytes)` (115–140): calls
  `limits.validate()`, `application::normalize_ports(ports, "http_ports")`,
  and rejects `max_body_bytes == 0 || > 256 MiB` with
  `Error::Limit { field: "max_http_body_bytes", limit: 256*1024*1024 }`.
- `scopes()` (141–143): iterates `self.tcp.scopes.values()`.
- **`observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, Error>`**
  (144–150): iterates `self.tcp.observe(record)?` and calls
  `self.event(event, record.number, &mut output)?`. **The physical
  `FrameRecord` — including `record.timestamp: SystemTime` — is visible here
  but only `record.number` is currently forwarded.** The per-observation
  event vector is `output`, returned to the caller; session drains it only on
  `Ok` (spec: "published only if the observation succeeds").
- `finish(mut self, run: &RunSummary) -> Result<(Vec<Event>, Summary), Error>`
  (151–172): drains `self.tcp.trailing(&run.trailing_tcp_events,
  run.frames_read)` — `Evicted` routes to `self.stop(&flow, Incomplete,
  false, ..)`, everything else to `self.event(event, run.frames_read, ..)`
  (note: `number = run.frames_read`, **no timestamp exists at EOF** — marker
  must be `None`). Then flushes every direction as `Incomplete`, then
  `requests_without_final_response += Σ pending queue lengths` (166–170).
  **This is where EOF `unanswered` retirement goes** — spec: "merge pending
  queues and emit globally in ascending request-message index", before or
  while the counter is bumped, appended to `output` after existing events.
- `fn event(&mut self, event: application::Event, number: u64,
  output: &mut Vec<Event>)` (173–214): dispatches `Data → self.data(...)`;
  `Gap|Conflict|Evicted|Closed{reset}` → `Issue{number, flow, stream,
  status}` pushed when `!clean`, then `self.stop(&flow, status, clean)`;
  `Status::Reset` also stops `flow.reverse()`. **This is the seam where an
  `Availability` marker can ride** — signature is private; pass
  `Option<Availability>` (or `number: u64, timestamp: Option<SystemTime>`)
  alongside `number` for `Issue.number`.
- `fn direction_for(&mut self, data, output) -> Result<Direction, Error>`
  (217–254): **generation-reuse cleanup.** When
  `generations.insert(stream, generation)` reports a change: drops
  `upgraded` entries for the stream and `requests.retain(...)` removes all
  pending queues whose key's stream matches, bumping
  `requests_without_final_response` by each queue's len (228–235). **Spec
  point 4: emit the old stream's pending `unanswered` rows here, in ascending
  request-message index, before the new generation parses.** Note `retain`
  does not give the drained queues back — replace with explicit removal +
  emit.
- `fn data(&mut self, data: application::Delivery, output)` (256–463): the
  parse loop. `connection = (data.stream, data.generation)`; direction from
  `direction_for`; `input = data.bytes`.
  - New message creation (266–283): inside `while !input.is_empty() &&
    !direction.disabled && !upgraded`; `max_messages` charged
    (`Error::Limit{field:"max_messages"}`), `summary.messages += 1`, `Live`
    born with `index = summary.messages`, `sources = data.sources.clone()`.
    Message index = 1-based parse-start order.
  - Source merging (284–294): first delivery of a *continuing* message merges
    via `SourceSet::union`; `max_source_spans` check on `frames().len()`.
  - Head accumulation (295–332): `run` = bytes through next LF;
    `bare_crlf_offset` (594–617) catches bare CR/LF; `check_buffer` charges
    `max_buffer_bytes` (465–473); `> MAX_HEADER_BYTES` → `Status::Limit` +
    `Limit::HeaderBytes`; bare → `Malformed`; no `\r\n\r\n` → `continue`.
  - Retained charge on head completion (333–342):
    `retained += header.len()*32 + 4096`, compared to
    `max_retained_bytes`. **Spec adds +512/pending request, +32/informational
    ref, +512/emitted transaction to this same counter — no refund.**
  - `parse_head(&Bytes::copy_from_slice(&live.header))` (343); `Err` →
    `flush(failure_status(&error))` + `disabled` (344–358). **Rejected head →
    no transaction (spec point 5).**
  - Head classification (359–388):
    - `head.status().is_some()` → response: `key = (connection,
      data.flow.reverse())`; `queue.front()` → `live.request` +
      `request_method`; **`status >= 200 || status == 101` pops the queue
      front** (so 100–199 ≠ 101 stays pending — spec's informational rule
      matches); empty queue is removed; no request →
      `responses_without_request += 1` (377–379). **Paired/orphan transaction
      emission belongs exactly here, before `Head::body` is consulted —
      append `Event::Transaction` to `output` before any message event caused
      by this head (spec NDJSON ordering).**
    - `head.method()` → request: `requests.entry((connection,
      data.flow.clone())).or_default().push_back(Pending{index, method})`
      (380–388). **Enqueue happens BEFORE `Head::body` validates framing —
      spec point 1 preserves this; the request is registered even if body
      framing later fails (HT11).**
  - `head.body(request_method)` → `framing` (389–406): `Err` → `Malformed`
    flush + disabled. `live.framing`, `live.body = BodyDecoder::new(framing,
    self.max_body_bytes)`; `Body::Length(n) > max_body_bytes` → `Limit` +
    `Limit::BodyBytes`. Immediately-complete bodies (None/Tunnel/Length(0)):
    `Body::Tunnel` → `upgraded.insert(connection)` +
    `upgraded_connections += 1` + `Status::Upgrade`, else `Complete` → flush
    (408–431).
  - Body consumption (432–457): `additional_buffer_bound` pre-charges
    `check_buffer`; `body.consume(input)` → `Progress{consumed, complete}`;
    `Err` → `flush(failure_status)` + `disabled`.
    **HTTP-B: this is the single body-consumption call site — swap to
    `consume_with` with a callback that forwards entity spans to the selected
    sink only when `live.index == selected_message`.**
  - Loop end (459–462): final `check_buffer`, `buffered +=`, reinsert
    direction.
- `fn stop(&mut self, flow, status, clean, output)` (474–500): removes the
  direction, `body.close()` → `Complete` when clean FIN closes a
  close-delimited body (spec HB04), else `status`; reinserts `disabled`.
- `fn flush(&mut self, flow, direction, status, error, output)` (501–560):
  takes `live`, updates summary counters (`Complete|Upgrade →
  complete_messages`; `Malformed|Limit → malformed_messages`; else
  `incomplete_messages`), charges retained `= (body buffered + header if no
  head)*32 + 4096` (517–534), builds `Message` (`header_wire` from
  `head.wire()` or raw `live.header`; `body_bytes` from
  `BodyDecoder::body_bytes`; `trailers` cloned), pushes `Event::Message`.
- `session::Collector` impl (563–588): `needs() = { tcp_stream: true,
  tcp_events: true, track_sources: true }`; `observe`/`finish` adapt errors
  via `BoundaryError::from_error`.
- `failure_status` (620–626): `http::Error::Limit → Status::Limit`, else
  `Malformed`.
- Unit tests (628–974): same-module tests call the **private** `data()`
  directly with fabricated `application::Delivery` (`Delivery` is
  `pub(crate)` — constructible inside the crate): `delivery(tracker, flow,
  number, bytes)` builds `Delivery{flow, stream:1, generation:0, bytes,
  sources: tracker.single(SourceFrame{number, timestamp: UNIX_EPOCH +
  number s})}`. **`data()`/`event()` signatures can change freely — only this
  file's tests call them.** Any marker plumbing must be threaded through
  these test call sites too.

## 2. `analysis/application.rs` (506 lines) — shared bounds + TCP delivery

- `Limits` (21–45): `max_messages` (default 4096, hard ceiling 100_000 in
  `validate()` at 100–124), `max_streams` (1024/100k), `max_buffer_bytes`
  (16 MiB/256 MiB), `max_retained_bytes` (64 MiB/256 MiB),
  `max_source_spans` (16384/100k). All ceilings via
  `Error::Limit{field, limit}` → `policy.application_limit`, `Kind::Policy`.
- `Error` (57–70, `#[non_exhaustive]`): `Analysis(#[from] super::Error)`,
  `Provenance(#[from] provenance::Error)`, `Limit{field, limit}`,
  `Sources{number}`, **`Output(#[source] BoundaryError)`** — exists already;
  HTTP-B sink failures go here. **There is NO `Configuration` variant yet** —
  HTTP-T's `cli.http_configuration`/`Kind::Usage` variant must be added
  (classification block at 71–99; `causes()` override handles
  `Analysis`/`Output` specially, others use `source_chain`).
- `normalize_ports` (131–145): sort/dedup, nonempty, ≤256, no 0.
- **`Delivery`** (147–154, `pub(crate)`): `{flow: ScopedFlowKey,
  stream: u64, generation: u64, bytes: Bytes, sources: SourceSet}` — **no
  frame/timestamp field; spec says do not change this shared type.**
- **`Event`** (156–175, `pub(crate)`): `Data(Delivery) | Gap{flow,stream} |
  Conflict{flow,stream} | Closed{flow,stream,reset} | Evicted{flow,stream}`.
- `TcpSources` (184–208): `ports, limits, spans: HashMap<ScopedFlowKey,
  Vec<Span>>, span_count, streams: HashMap<ScopedFlowKey,u64>,
  generations: HashMap<u64,u64>, syns, closed, pub(crate) scopes:
  BTreeMap<u32,Definition>`.
- `TcpSources::observe(record)` (209–304): uses `record.tcp` +
  `view.conversation`; detects tuple reuse (`reassembly_reused ||
  observed_reused`) → `reset_stream` (bump generation) + optional
  `Event::Evicted`; buffers `Span{sequence,length,number:record.number,
  sources:record.tcp_sources()}`; then folds `record.tcp_events` via
  `self.event(event, record.number, &mut output)`.
- `TcpSources::event` (351–446): `TcpEvent::Data{sequence,bytes,..}` → for
  each span intersection `parts.push((lo,hi,sources))`; pushes
  `Event::Data(Delivery{flow, stream, generation: self.generations[&stream],
  bytes: bytes.slice(lo..hi), sources})`. **One `Data` event per contiguous
  attributed slice — several Deliveries per frame possible.** Gap/Closed/
  Evicted/Retransmission(→Conflict) events forwarded directly.
- `trailing(events, number)` (305–315): same `event()` at EOF — invoked from
  `Collector::finish` with `run.frames_read`.

### Frame → HTTP delivery trace

`analysis::pipeline::run_inner` (`pipeline.rs:323–573`):
`next_frame` (801–816) → timestamp validated present (379–383,
`Error::TimestampUnavailable` otherwise) → decode → IP reassembly w/
`PhysicalFrame{decoded, number, timestamp}` (405–421; derived datagrams
attach to the *completing* physical frame's record) → transport views →
stream index → filter/time/stream selection → `tcp_events =
reassembly_dispatch.dispatch(header, segment, timestamp, number)` (521–526)
→ `sink(FrameRecord{number, timestamp, ..., tcp_events})` (529–541).
`Session::observe` (`session.rs:248–271`) calls
`collector.observe(&record)` and drains each returned event through
`event_sink` — **if `observe` errs, that record's whole vector is
discarded** (matches spec "no report is fabricated for that failed
observation"). `Pass::finish` (122–142) drains `finish()`'s trailing events
through the same sink.

**Minimal marker path (per spec):** in `Collector::observe` build
`Availability{frame: record.number, timestamp: record.timestamp}` once and
pass `Option<Availability>` into private `event()`/`data()` (`None` for the
`trailing`/`finish` path). Every delivery within one observe call shares the
marker (HT09). Gap-fill bytes and IP-reassembled deliveries naturally take
the processing frame's marker because they surface inside that frame's
record (HT07). No change needed in `application::Delivery`,
`application::Event`, `TcpSources`, DNS, or `Session`. TLS precedent for a
timestamp-carrying private call: `live.note_frame(Some(record.timestamp))`
at `analysis/tls.rs:250` (`note_frame` at `analysis/tls/session.rs:458`).

**`response_started` subtlety:** the marker must be captured when the first
head byte is *consumed*, before `parse_head` knows it is a response — store
the marker on `Live` when `live.header` receives its first bytes (or when
`Live` is created and `take > 0`); spec: "Do not mark a delivery that
consumes zero bytes" (`take` can be 0 when `room == 0` or `bare == Some(0)`
… actually `take` floors at `run.len().min(room).min(bare+1)`; zero only if
`room == 0` — verify when implementing). `request_headers_available` /
`response_headers_available` = current observation's marker at `parse_head`
success (line 343).

## 3. `protocol/application/http/` — the parser

Module root `protocol/application/http.rs` (65 lines):

- Re-exports: `pub use codec::{BodyDecoder, Progress, parse_head};`
  `pub use model::{Body, Head, Header, Http, StartLine};` (17–18). Add
  `ConsumeError` to the codec re-export for `consume_with`.
- `MAX_HEADER_BYTES = 65_536`, `MAX_HEADERS = 256`, `MAX_START_LINE = 8_192`
  (20–22).
- `Error` (25–32): `Invalid(&'static str) | Limit(Limit)`; `Limit` (34–43):
  `StartLine, HeaderBytes, HeaderCount, ChunkLine, BodyBytes, TrailerBytes`.
  Classified: `Invalid → packet.http`/`Kind::Packet`; `Limit →
  policy.http_limit`/`Kind::Policy` (58–64).

`codec.rs` (408 lines):

- `parse_head(input: &Bytes) -> Result<Option<(Head, usize)>, Error>`
  (126–162): finds `\r\n\r\n` within `MAX_HEADER_BYTES`; `Ok(None)` = need
  more bytes; returns `(Head{start, headers, wire: input.slice(..end)},
  end)`. Start line via `parse_start` (204–246): `HTTP/` prefix →
  `StartLine::Response{version, status: u16 (100..600), reason}`; else
  `StartLine::Request{method: String, target: Bytes, version}` (1.0/1.1
  only).
- **`Head::body(&self, request_method: Option<&str>) -> Result<Body, Error>`**
  (48–120): 101 or CONNECT+2xx → `Body::Tunnel`; HEAD/1xx/204/304 →
  `Body::None`; TE+CL both → `Invalid`; TE list → exactly one final
  `chunked` → `Body::Chunked`, non-chunked TE on response → `Body::Close`,
  on request → `Invalid`; CL list → consistent digits → `Body::Length(n)`;
  default → response `Close`, request `None`.

`codec/body.rs` (239 lines) — the `consume_with` seam site:

- `enum State` (8–18, private): `Done, Length(u64 remaining), Close,
  ChunkLine, Chunk(u64 remaining), ChunkCr, ChunkLf, Trailers`.
- `BodyDecoder` (21–29): `state, line: Vec<u8>, trailer_lines: Vec<u8>,
  trailers: Vec<Header>, bytes: u64, maximum: u64`. `new(body,
  max_body_bytes)` (36–50): `None|Tunnel|Length(0) → Done`; `Length(n)`;
  `Close`; `Chunked → ChunkLine`.
- Accessors: `body_bytes()` (51), `buffered_bytes()` (54–62 — `line` +
  `trailer_lines` + trailer name/value lens; entity bytes are never
  buffered), `additional_buffer_bound(input)` (63–69, `pub(crate)` — 0 for
  Done/Length/Close else min(input, MAX_HEADER_BYTES+MAX_START_LINE)),
  `trailers()` (70), `complete()` (73), `close()` (77–82 — `Close→Done` on
  clean FIN only).
- **`consume(&mut self, input: &[u8]) -> Result<Progress, Error>`** (83–184):
  `Progress{consumed: usize, complete: bool}` (30–34). Per state:
  - `Length(rem)|Chunk(rem)`: `take = min(rem, input.len()-offset)`;
    `self.add(take)?` — **entity bytes discarded here** (89–110); Length→Done,
    Chunk→ChunkCr at 0.
  - `Close`: consumes everything via `add` (112–116).
  - `ChunkCr`/`ChunkLf`: expect `\r`/`\n` else `Invalid("chunk data lacks
    CRLF")` (117–130).
  - `ChunkLine`|`Trailers`: byte-at-a-time line assembly; `line.len() >=
    MAX_START_LINE` → `Limit::ChunkLine`; bare CR/LF → `Invalid`; completed
    line: ChunkLine → `parse_size` (hex ≤16 digits, `;` extensions tolerated
    w/ balanced quotes, leading-size-OWS trimmed — 194–238), `length==0 →
    Trailers` else `Chunk(length)`, **`length > maximum - bytes` →
    `Limit::BodyBytes` (152–154)**; Trailers → `line.len()==2` (empty line)
    parses `trailer_lines` via `parse_headers` and rejects
    content-length/transfer-encoding/host trailers → `Done`; else append to
    `trailer_lines` bounded by `MAX_HEADER_BYTES` → `Limit::TrailerBytes`
    (155–175).
  - `add(bytes)` (185–192): `checked_add`, `> maximum →
    Error::Limit(Limit::BodyBytes)` — **the body-byte ceiling gate.**
- **`consume_with` fit:** entity spans are exactly the `add(take)` calls at
  88–110 (`Length`, `Chunk`) and 112–116 (`Close`). The seam: pass `emit:
  &mut impl FnMut(&[u8]) -> Result<(), E>`; where `take > 0`, call
  `emit(&input[offset..offset+take])` and map `Err(e) →
  ConsumeError::Sink(e)`, `http::Error → ConsumeError::Framing`. Charge via
  `add()` *before* invoking the callback (spec: "no byte beyond a ceiling
  reaches the sink"); commit state only after `Ok` from the callback —
  current code already commits state per-iteration, so ordering is:
  bound-check → emit → state transition. `ChunkCr/ChunkLf/ChunkLine/Trailers`
  bytes (sizes, extensions, CRLF, trailers) never reach the callback
  (spec HB02). `consume(input)` = `consume_with(input, &mut |_| Ok::<(),
  Infallible>(()))` unwrap-style delegation keeping `Result<Progress, Error>`.
  Framing can fail after earlier spans were delivered — sink must stage.

## 4. DNS interval representation — the `Interval` template

`analysis/dns/transactions.rs` (300 lines), re-exported at `dns.rs:29`:

```rust
// transactions.rs:29-47
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Latency {
    pub nanoseconds: u128,
    pub negative: bool,
}
impl Latency {
    fn between(query: SystemTime, response: SystemTime) -> Self {
        match response.duration_since(query) {
            Ok(elapsed) => Self { nanoseconds: elapsed.as_nanos(), negative: false },
            Err(error) => Self { nanoseconds: error.duration().as_nanos(), negative: true },
        }
    }
}
```

HTTP `Interval` = same two fields, different name (spec: "without naming it
latency"). Zero is always `negative: false` (duration_since returns Ok(0)).
DNS `Transaction`/`Tracker` (49–300) also shows: per-message retained-byte
charging (`charged += 512 + key material`, lines 150–164 — same
`Error::Limit{field:"max_retained_bytes"}` pattern the HTTP spec's
512/32/512 charges reuse), `finish()` merging pending queues sorted by first
query/response index (268–299 — analogous to HTTP-T's EOF ordering rule),
`Event::Transaction` pushed after `Event::Message` in `emit` (dns.rs:430–466).

## 5. CLI driving of the HTTP collector

`commands/http.rs` (105 lines):

- `Args` in `commands/http/arguments.rs` (41 lines): `path`, `--stream`
  (`Selector<StreamRef>`), `--http-port` (repeatable), `--max-http-body-bytes`
  (default 16 MiB), `application: ApplicationLimitsArgs`, `decode`,
  `limits`. `--transactions`, `--body-message`, `--write` land here.
- `run()` (52–105): `args.application.validate_output()`; ports =
  user list + `[80, 8080]`; **`Collector::new(args.application.core(),
  ports, args.max_http_body_bytes)`** (56); rejects non-TCP `--stream`
  (`Kind::Usage`); calls `inspect(Inspection{path, limits, decode,
  application, selector}, collector, format, stream, publish)`.
- `publish` closure (81–92) matches `Event::Message → output.emit(
  wire::Message::try_from(*message)?, &mut messages, render_message)`;
  `Event::Issue → wire::Issue`. **Exhaustive — new `Event::Transaction` arm
  needed; HTTP-T01 may reject it as an internal invariant until HTTP-T02.**
- Terminal (94–104): `wire::Complete::try_from((&outcome.run,
  outcome.summary, outcome.scopes))`; Json → `emit_aggregate(Command::Http,
  wire::Report{messages, issues, complete}, vec![])`; Ndjson →
  `stream.complete(complete, Vec::new())`; Text → `render_complete`.
  **HTTP-B note: `outcome.summary` moves out here — artifact publication
  must precede the terminal record; BASE-01's `prepare_complete` seam is
  specced but does not exist yet in `output/stream.rs` (checked
  emit_data/complete at 173–216 — no prepare functions).**

`commands/offline_analysis.rs` (302 lines):

- `Inspection` (118–124): `path, limits, decode, application, selector` —
  spec HTTP-B02 removes `application` once `inspect` borrows `&mut
  EventOutput`.
- `inspect` (132–162): `prepare(limits, None, decode)` → `Session::new(
  registry, setup.options(), collector, selector)` → `open_capture` →
  **`let mut output = EventOutput::new(format, stream,
  application.max_application_output_bytes)`** (152) →
  `session.run(&mut reader, ip_event_sink(format, stream), |event|
  publish(&mut output, event).map_err(CliError::into_boundary_error))` →
  `selected_absent` → `Kind::Usage` "selected stream is not present"
  (**precedence over body-absent per spec**). Only other caller:
  `commands/dns_read.rs` (same shape).
- `EventOutput` (`commands/application_output.rs`, 263 lines): fields
  `format, stream, remaining`; `new(format, stream, maximum)`;
  **`emit<T: StreamRecord>(value, retained: &mut Vec<T>, render_text)`**
  (26–51): `bounded_json_len(&value, remaining)` (compact JSON byte count,
  `rendering/machine.rs:32`), `remaining -= bytes`, Json → retain, Ndjson →
  `stream.emit_data`, Text → render. Spec adds `charge(&impl Serialize)`;
  `emit` delegates. `Kind::Policy` "application output exceeds
  --max-application-output-bytes" on overrun; `policy.denied` exit 6 in
  tests.

`output/http.rs` (270 lines) — wire DTOs (CLI-owned, `From`/`TryFrom`):

- `Status` (`published_enum!` 17–30), `Body` (33–58), `StartLine` (60–102),
  `Header` (104–119), **`Message`** (121–175: `index, stream, generation,
  flow, request, status, start, headers, header_wire_hex, framing,
  body_bytes, trailers, error, sources`; `TryFrom<analysis::Message>` may
  fail via `Source::try_from`; `StreamRecord event_name() = "http_message"`),
  `Issue` (176–198, `"http_stream_issue"`), `Summary` (199–222),
  **`Complete`** (223–252: `frames_read, frames_matched, summary, scopes,
  incomplete_datagrams, source_outcomes_omitted, ip_reassembly` — spec adds
  `transaction_summary` + `body_export`), `Report` (253–269 — spec adds
  `transactions: Vec<Transaction>`).
- `output/dns_read.rs` is the template for a transaction DTO: `Latency`
  wire `{nanoseconds: u128, negative: bool}` (50–65), `Transaction` DTO +
  `TryFrom` (121–153), `event_name() = "dns_transaction"`, `Report` carries
  `transactions` vec.
- Wire timestamp: `output/frame.rs:52` `Timestamp{unix_seconds: i64,
  nanoseconds: u32}` `TryFrom<SystemTime>` → `contract::Error::
  TimestampOutOfRange` → `packet.timestamp_range`/`Kind::Packet`
  (contract.rs:271, 299–303) — the "existing checked timestamp DTO" for
  `Availability`. `output/provenance.rs:10` `Source{number, timestamp}` is
  the per-source-frame shape; `Availability` needs `{frame, timestamp}` —
  same `Timestamp` conversion.
- `StagedFile` (`staged_output.rs:21–89`): `stage(&Path)` refuses existing/
  dangling-symlink destinations, temp file in parent dir; `as_file_mut()`;
  `sync()`; `persist()` = `persist_noclobber`, all `io.output_file`/
  `Kind::Io`. Used by rewrite/merge/export/follow.
- `sha2` already a CLI dependency (`crates/packetcraftr-cli/Cargo.toml:40`,
  `sha2.workspace = true`); used at `input/fingerprint.rs:6`.
- NDJSON: `StreamRecord` trait (`output/stream.rs:24–26`), `emit_data`
  (173), `complete` (193); event names reserved: `complete`, `error`.
- Schema: `schemas/packetcraftr.output.v6.schema.json` has `httpMessage`,
  `httpIssue`, `httpSummary`, `httpComplete`, `httpResult` (~lines
  9135–9527). v7 family is BASE-01's job; feature tickets implement variants.
- `ApplicationLimitsArgs` (`command_options/application.rs:7–68`): six
  `--max-application-*` flags + `core() -> application::Limits` +
  `validate_output()` (1..=256 MiB).

## 6. Tests & fixtures

- `crates/packetcraftr-core/tests/http_analysis_contracts.rs` (414 lines):
  `collect_events` (18–42) drives `Collector::new(Limits::default(),
  vec![80], 1024)` through `analysis::run` with
  `Options{track_sources: true, tcp_events: true}` then `finish`.
  `common::tls_capture::{Capture, Stream}` (`tests/common/tls_capture.rs`):
  `Capture::new/open/reopen`, `client(server)_spec`, `client/server(payload)`,
  `client_retransmit`, `server_beyond(hole)` (gap fixtures), `client_fin`,
  `push(spec, payload)`; **`timestamp()` (58–61) = UNIX_EPOCH + tick secs,
  tick += 1 per frame — tests fully control per-frame timestamps**; frames
  mutable (`capture.frames.remove(i)` at line 138). Gap-fill/
  suffix-overlap/sequence-wrap fixtures at 306–381 produce `sources` sets to
  assert against. Generation reuse: `reopen` → generations [0,0,1,1].
  **No negative/regressing timestamp helper — one can push frames with
  arbitrary `SystemTime` via `push`/`tcp_frame` directly** (`common/mod.rs:
  79–108`; `common::timestamp` variant may be added).
- `http_framing_contracts.rs` (181): pure parser tests —
  `http::parse_head`, `Head::body`, `BodyDecoder::consume` incl. byte-at-a-
  time chunk decoding (103–122). `consume_with` belongs here per ticket.
- `tests/common/mod.rs`: `reader(frames)` writes a pcap via `Writer::pcap`
  then `Reader` — arbitrary `Frame` timestamps preserved; `CLIENT`/`SERVER`
  = documentation addresses. `tests/common/ip_fragments.rs`: IPv4 fragment
  fixture builders (`ipv4_fragments`, `ipv4_protocol_fragment_frame`,
  `cascading_vxlan_tcp_frames`) — usable for HT07 fragmented-IP
  availability cases.
- Fuzz: `fuzz/fuzz_targets/http_pipeline.rs` (54) and
  `http_segmentation.rs` (86) — both construct `http::Collector::new(...)`,
  `options.tcp_events/track_sources = true`; `http_pipeline` discards events,
  `http_segmentation` matches `http::Event::Message` via `if let` (33–43) —
  **new Event variant compiles cleanly there but the match arms in
  `commands/http.rs` must be updated**; `composed_support::options()`,
  `tcp(seq, flags, payload)` build fixed-timestamp frames. Spec: "Extend
  existing HTTP pipeline fuzz coverage for segmentation and bounds."
- CLI `tests/http_contracts.rs` (183): runs the binary on
  `examples/captures/http-stream.pcap`; asserts NDJSON event sequence
  `["http_message","http_message","complete"]`, text output exact-match,
  `--max-application-output-bytes` exact/under budget (exit 6,
  `policy.denied`), `--stream udp:0` usage failure. `tests/common` helpers:
  `run`, `run_success`, `parse_json`, `parse_ndjson`, `assert_contiguous`.
- Schema conformance: `crates/packetcraftr-cli/tests/
  aggregate_schema_conformance.rs`, `ndjson_conformance.rs`,
  `published_schema_conformance.rs` — new wire fields need schema cases here
  per spec ("schema cases belong in the current conformance targets").

## 7. Error conventions

- `Classified` trait (`error.rs:199–214`): `classification() ->
  Classification{code: &'static str, kind: Kind, remediation}`; `Kind =
  Usage|Packet|Capability|Io|Policy|Internal` (36–47); exit codes seen in
  tests: usage 2, packet 3, io 5, policy 6, internal 70, cancellation 130.
- `application::Error` classification (application.rs:71–99): `Limit →
  policy.application_limit`; `Sources → internal.application_sources`;
  `Output → delegate to BoundaryError`.
- **`BoundaryError`** (`error/boundary.rs:14–152`): `new(message,
  classification, causes)`, `from_error(E: Classified)`, `with_source`,
  `as_causes()`, `with_context`, `internal_execution`,
  `execution_validation`. `BodySink::write -> Result<(), BoundaryError>`
  means the CLI sink constructs these directly (e.g.
  `CliError::into_boundary_error()`); spec routes sink failures through
  `application::Error::Output` which delegates classification/causes.
- Selection-validation precedent: `analysis/export.rs:77,86` —
  `Error::Selection` → `cli.export_selection`/`Kind::Usage`. HTTP-B's
  `cli.http_body_selection` (zero message) and HTTP-T's
  `cli.http_configuration` (late/duplicate config) follow this pattern;
  both need **new `application::Error` variants** (e.g.
  `Configuration{...}` and an invalid-selection variant — spec names the
  codes only).
- `http::Error` → `Message.error` retains the typed parse failure;
  `failure_status` maps `Limit → Status::Limit` else `Malformed`.

## 8. ADR 0005 — settled decisions (docs/adr/0005-...md)

- Body artifacts remove chunk framing but **preserve content encodings and
  remaining transfer codings byte-exactly** (no decompression; artifact may
  contain gzip); report identifies message and hashes exact bytes.
- Timing = **physical capture observation that made each header boundary
  available to the parser**, NOT earliest/min source-frame timestamp —
  "reassembled delivery provenance cannot establish an exact per-octet wire
  timestamp". Gap-filling packet marks availability; clock regressions stay
  signed intervals.
- Header association and body completeness remain separate evidence.

Parent spec (`.scratch/offline-investigation/spec.md`): HTTP-T01 ← BASE-01
(v7 family + `prepare_complete`/`PreparedAggregate` seams — **not yet
implemented in `output/stream.rs`/`rendering/machine.rs`**); HTTP-B01 ←
HTTP-T01; HTTP-B02 ← HTTP-B01 + HTTP-T02. Spec order: HTTP-T02 precedes
HTTP-B02 to serialize CLI/DTO edits.

## 9. Implementation gotchas distilled

1. `Collector` must grow a `'a` lifetime for `with_body_sink(_, &'a mut dyn
   BodySink)` — ripples to `session::Collector for Collector<'a>` impl,
   `Session<'a, C>` generic usage in CLI (`inspect<C: analysis::Collector>`
   is already generic — OK), and fuzz target construction.
2. `observe` is the configuration-close boundary — set a `configured_closed`
   flag at the top of `observe` (before `tcp.observe`), covering failed
   attempts and non-HTTP frames (HT15).
3. `direction_for`'s `requests.retain` (228–235) and `finish`'s queue-count
   loop (166–170) are the two `unanswered` retirement sites; each `Pending`
   must be emitted exactly once with ascending-index ordering — `retain`
   can't emit into `output` cleanly (closure borrows `self` twice —
   restructure to drain/remove).
4. `Event` enum gains `Transaction(Box<Transaction>)` — exhaustive matches:
   `commands/http.rs:81–92` only (fuzz/tests use `if let`).
5. Issue `number` at EOF is `run.frames_read` (no timestamp) — keep the
   `number` parameter separate from `Option<Availability>`.
6. `Message.index` ordering: assigned on first byte of each message
   (line 273); transaction emission must use it, and EOF merges pending
   queues from `BTreeMap<RequestKey, VecDeque<Pending>>` (multi-stream) into
   one ascending-index emission.
7. `requests` key direction: request queued under `(connection,
   data.flow.clone())` at the request's direction; response looks up
   `(connection, data.flow.reverse())`. Transactions record `flow` =
   request direction when present else observed response direction (spec).
8. `with_transactions`/`with_body_sink` consume `self` → builder-style,
   called between `new` and `inspect`; `inspect` takes `collector` by value.
9. For HTTP-B the sink call site is `live.body...consume(input)` at
   http.rs:439–444 — only fires when `live.index == selected`; `add()`-order
   in `consume_with` guarantees no over-limit byte reaches the sink; sink
   errors map `ConsumeError::Sink(BoundaryError)` →
   `application::Error::Output`, never a `Message` status.
10. Charging order per spec: `+512` pending request before enqueue mutation,
    `+32` per informational index, `+512` per emitted transaction — all
    cumulative on `self.retained` vs `max_retained_bytes`, no refund.
11. `Summary.transaction_summary: Option<TransactionSummary>` — `None` when
    disabled; counters `{transactions, paired, unanswered, orphan_responses,
    negative_header_waits, negative_header_spans}` count emitted rows only.
12. NDJSON order: transaction event appended to `output` **before** the
    message event the same head triggers (spec §Output) — i.e., push
    `Event::Transaction` inside the head-parsed block (360–388) before the
    eventual `flush(...Event::Message)` in the same `data()` call. `paired`
    emits immediately at head parse; `unanswered` at generation-replacement/
    EOF; `orphan_response` immediately incl. orphan informational.
13. `run_with_ip_events`'s sink drops the whole observe-vector on error —
    events queued in `output` before a later same-observation error are
    never published (HT14).
14. Wire shape references for v7 DTOs: `Availability { frame: u64,
    timestamp: Timestamp }` — reuse `output::frame::Timestamp`
    (`TryFrom<SystemTime>`, may fail `TimestampOutOfRange` →
    `packet.timestamp_range`); `Interval` wire = `{nanoseconds: u128,
    negative: bool}` like `output/dns_read.rs:52–65`.
