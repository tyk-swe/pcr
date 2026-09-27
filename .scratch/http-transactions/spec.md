# HTTP header transactions and capture-observed timing

Status: ready-for-agent
Feature ID: HTTP-T
Parent: [offline investigation batch](../offline-investigation/spec.md)
Implementation: not started; this session is specification-only.

## User behavior

```console
packetcraftr --output json http capture.pcapng --transactions
packetcraftr --output ndjson http capture.pcapng --transactions --stream tcp:2
```

Add `--transactions` to the existing `http` command. It defaults to false.
When enabled, keep existing message and stream-issue output and add header
transaction records. This is HTTP/1 over the existing configured cleartext
ports and existing scoped TCP reassembly. Existing stream/epoch/decode/port
selection behavior remains unchanged; there is no new packet display filter.

An HTTP transaction records header association, not completed application
work. Headers can be paired while an upload is still in progress, while a
response body is incomplete, or before body-framing validation later fails.
Message statuses remain the authority for each message's completeness.

## Correlation and lifecycle

Use the existing request queue in `analysis::http::Collector`. Its key is
the request direction's scoped flow plus `(stream, generation)`. Do not create
a second correlator or change existing `Message.request` values.

1. After `parse_head` accepts a request head, enqueue its message index,
   method, and header-availability marker. Preserve the current ordering:
   this occurs before `Head::body` validates body framing.
2. A parsed response head associates with the oldest request in the opposite
   direction of the same connection generation. Status 100–199 except 101
   adds its message index to that request's informational list and keeps the
   request pending. Status 101 or any status at least 200 consumes the request
   and emits one `paired` transaction immediately at header parsing.
3. A response with no pending request emits one `orphan_response` transaction
   immediately, including orphan informational responses. Do not guess which
   orphan 100/103 and later final response belong together. No row is emitted
   for a paired informational response until its request settles.
4. Pending requests settle as `unanswered` on the existing generation-reuse
   cleanup and at EOF. At a generation replacement, emit that old stream's
   pending rows in ascending request-message index before parsing the new
   generation. At EOF, merge pending queues and emit globally in ascending
   request-message index. Existing gap/reset/conflict/eviction issues retain
   their behavior; they do not add another independent request-retirement path.
5. A partial/malformed start line or head rejected by `parse_head` creates no
   transaction. A successfully parsed head with invalid body framing still
   participates in header association, exactly as existing request linking does.
6. Transactions are numbered from 1 in emission order, separate from message
   indices. Message indices remain one-based parse-start order within the
   selected invocation; stream indices remain capture-global. NDJSON transaction
   references may precede the eventual `http_message` body-completion record.

“Emit at header parsing” means append to the collector's per-observation event
vector. The session publishes that vector only if the observation succeeds;
a later error in the same observation can prevent its queued events from being
published. No report is fabricated for that failed observation.

HEAD, pipelining, successful CONNECT, 101, and connection generation reuse
retain existing parser and association rules. A `paired` result for CONNECT or
101 does not make subsequent tunnel bytes an HTTP body.

## Timing

Define `Availability { frame: u64, timestamp: SystemTime }` in core. The marker
uses the `FrameRecord` currently being processed, not a member selected from
`Message.sources` or `Delivery.sources`.

- `response_started`: current observation when the parser consumes the first
  byte of the response head. Do not mark a delivery that consumes zero bytes.
- `request_headers_available`: current observation when the complete request
  head is successfully parsed.
- `response_headers_available`: current observation when the complete response
  head is successfully parsed.
- `response_header_wait`: `response_started - request_headers_available`.
- `response_header_span`: `response_headers_available - response_started`.

Carry the current physical record marker through the HTTP collector's private
`event`/`data` calls; shared DNS/application delivery types do not need changing.
Every header parsed from one delivery may have the same marker. Buffered TCP
bytes released by gap filling use the filling frame. An IP-reassembled delivery
uses the physical frame that completed the datagram. Provenance still records
all contributors separately, and EOF invents no timestamp.

Represent an interval in core as `Interval { nanoseconds: u128, negative: bool }`,
matching the existing DNS interval representation without naming it latency.
Compute from `SystemTime::duration_since` or its error's duration, retaining
negative values. Zero always has `negative: false`. Never use floating point,
clamp a negative value, reorder frames, or infer synchronized capture clocks.

An orphan has no request marker/wait; an unanswered request has no response
markers/intervals. A paired informational response does not determine the final
response's timing. These values are header-availability observations, not RTT,
server processing duration, or full-message duration.

## Core architecture and resource accounting

Current owners: `crates/packetcraftr-core/src/analysis/http.rs`,
`analysis/application.rs`, `analysis/provenance.rs`, and the existing
`protocol/application/http` parser. Extract transaction state/types into
`analysis/http/transaction.rs`; keep that assembly module private and re-export
the capability types only through `analysis::http`.

Public additions at `analysis::http`:

- `Collector::with_transactions(self) -> Result<Self, application::Error>`;
  existing `new` keeps defaults.
- `Availability`, `Interval`, `Transaction`, `TransactionOutcome`,
  `TransactionSummary`, with the data fields specified in Output below
  (core timestamps are `SystemTime`, core flow uses the existing scoped type).
- `Event::Transaction(Box<Transaction>)`.
- `Summary::transaction_summary: Option<TransactionSummary>`: `None` when
  disabled. CLI mirrors this separately from the existing `Summary` DTO.

Configuration closes on the first public `observe` attempt, even if that frame
contains no HTTP data or the attempt fails. After that point, enabling
transactions or configuring a body sink fails with a typed
`application::Error::Configuration`, code `cli.http_configuration`, Kind::Usage.
Before observation, repeated `with_transactions` is idempotent. A second body
target is rejected, as the body-export spec defines. This prevents late enabling
from assigning invented markers to requests collected while timing was disabled.

Retain transaction state only when enabled. The existing message ceiling
(default 4,096; hard ceiling 100,000) bounds request and informational-message
counts. Charge an additional cumulative 512 bytes per pending request,
32 bytes per informational reference, and 512 bytes per emitted transaction
against `application::Limits::max_retained_bytes`, before mutation/emission.
These conservative charges are in addition to current header/message charges;
retirement does not refund a cumulative allowance. Reuse the existing typed
application retained-byte limit error. Source markers contain values, not new
`SourceSet` unions. No bodies or decoded headers are duplicated into a transaction.

The CLI sends transaction records through `EventOutput` in
`commands/application_output.rs`, charging their serialized bytes under the
existing `--max-application-output-bytes` in text, JSON, and NDJSON. No new
resource flags/preset numbers are necessary. `with_transactions` disabled
preserves existing parse work and event order apart from the new v7 empty fields.

## Output

Family is v7. Add CLI-owned types in `src/output/http.rs` and conversions.
Every following field is required; optional values serialize as explicit null.
Counts/indices use nonnegative JSON integers; indices/frame references present
in records are at least 1, while `stream`/`generation` retain existing ranges.

| Transaction field | Exact meaning/type |
| --- | --- |
| `index` | Transaction emission index, u64 |
| `stream`, `generation`, `flow` | Same connection identity/shape as HTTP messages; `flow` is request direction when present, otherwise observed response direction |
| `outcome` | `paired`, `unanswered`, or `orphan_response` |
| `request` | Request message index or null |
| `response` | Final response index for paired; observed response index for orphan; null for unanswered |
| `response_status` | Parsed response status integer in 100..=599, or null for unanswered |
| `informational` | Paired informational message indices, in observed header-parse order; empty for orphan |
| `request_headers_available` | Availability or null |
| `response_started` | Availability or null |
| `response_headers_available` | Availability or null |
| `response_header_wait` | Interval or null |
| `response_header_span` | Interval or null |

Wire Availability is `{ "frame": 7, "timestamp": { "unix_seconds": 1,
"nanoseconds": 125000000 } }`, using the existing checked timestamp DTO.
Wire Interval is `{ "nanoseconds": 125000000, "negative": false }`.
Schema bounds nanoseconds to u128 and enforces canonical nonnegative zero;
availability nanoseconds stay in `0..999999999`. A timestamp outside the
existing DTO's range is the existing classified output-conversion failure.

Add `transactions: [Transaction]` to aggregate HTTP results. Add
`transaction_summary` to aggregate results and NDJSON `complete`: null when
disabled, otherwise `{ transactions, paired, unanswered, orphan_responses,
negative_header_waits, negative_header_spans }`, all u64. `transactions` equals
the sum of the three outcomes; negative counters count only emitted non-null
negative intervals. Existing HTTP message summary counters retain their meaning.
When disabled, `transactions` is empty and no transaction event is emitted.

NDJSON uses `event: "http_transaction"`, `result: Transaction`. On each head
that settles a row, append its transaction to the existing collector event
vector before any message-completion event caused by that head. Existing
message/issue relative order is otherwise unchanged. EOF rows follow existing
trailing message/issue events. All records share the normal sequence and exactly
one terminal record. Text adds one escaped line per transaction containing its
index, outcome, stream/generation, request/response IDs, response status, and
signed integer wait/span in nanoseconds (`none` for null); existing message
lines and headers remain visible. Extend the final text summary with transaction
counts only when enabled.

## Acceptance cases

| ID | Fixture/action | Required observation |
| --- | --- | --- |
| HT01 | Request head available at 1s, final response starts at 1.125s, completes head at 1.130s | One paired row; wait 125,000,000ns; span 5,000,000ns |
| HT02 | Same request with 100, 103, 200 | One paired row, informational indices in order, timings from 200 |
| HT03 | Orphan 100, then orphan 200 | Two orphan rows; no guessed grouping/request/wait |
| HT04 | Pipelined A/B requests and final responses | FIFO pairing on the scoped generation, matching `Message.request` exactly |
| HT05 | Response header arrives before request upload completes | Transaction emits at response header; message completeness stays independent |
| HT06 | HEAD, successful CONNECT, and 101 | Existing framing/upgrade statuses preserved; paired header rows have no tunnel-body claim |
| HT07 | Header bytes arrive out of order or through fragmented IP | Availability uses release/completing frame, not earliest source timestamp |
| HT08 | Response start 2ms before request-head marker; response head ends 1ms before its start | Negative waits/spans preserved, counted, and schema-valid |
| HT09 | Several heads delivered by one frame | Equal markers and canonical zero intervals |
| HT10 | Reused tuple/new generation, then EOF with pending requests in several queues | Each request appears once; retirement ordering as specified |
| HT11 | Rejected partial/malformed head versus parsed head with invalid body framing | First has no row; second follows existing association while message reports failure |
| HT12 | Disabled flag; empty capture; selected stream/time window | No rows when disabled; enabled empty has zero summary; invocation-local IDs documented and respected |
| HT13 | Message, retained-byte, provenance, or serialized-output budget exhausted | Existing classified execution failure; no silently dropped association or completed report |
| HT14 | Sink fails while publishing transaction; EOF trailing findings/messages | Error terminal only if writable; exactly-once retirement and no later complete |
| HT15 | Configure before/after the first observe attempt, including a non-HTTP frame or failed attempt | Pre-observe repeat is idempotent; every late configuration fails without invented timing |

## Tickets and validation

[HTTP-T01](issues/01-core-header-transactions.md) owns core semantics;
[HTTP-T02](issues/02-cli-transactions.md) owns publication and docs.
Existing regressions: `http_analysis_contracts`, `http_framing_contracts`,
CLI `http_contracts`; schema cases belong in the current conformance targets.
Extend existing HTTP pipeline fuzz coverage for segmentation and bounds.

## Comments

This deliberately answers “when could analysis see these headers?” The
repository's current provenance cannot prove exact first-octet wire timestamps.
