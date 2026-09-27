# Export one completed HTTP body artifact

Status: ready-for-agent
Feature ID: HTTP-B
Parent: [offline investigation batch](../offline-investigation/spec.md)
Implementation: not started; this session is specification-only.

## User behavior and byte meaning

```console
packetcraftr http capture.pcapng
packetcraftr --output json http capture.pcapng --body-message 2 --write response.bin
packetcraftr --output ndjson http - --stream tcp:2 --body-message 1 --write body.bin < capture.pcapng
```

`--body-message INDEX` is a positive u64 and requires `--write FILE`; `--write`
also requires `--body-message`. Each appears once. Existing text/JSON/NDJSON
inspection output is preserved; body bytes go only to FILE. `--transactions`
can be combined. Other output formats remain rejected.

The selector is the existing `Message.index`, one-based parse-start order
within the selected invocation. Listing and extraction must use the same
capture, stream, epoch, HTTP-port, and decode settings. It is not a TCP stream
index, capture frame number, or capture-global stable message identifier.
The command parses through EOF even after the selected body completes.

Export only the selected message's entity spans: Content-Length bytes,
close-delimited bytes, or concatenated chunk-data bytes. Exclude headers,
chunk sizes/extensions/CRLF, trailers, pipelined messages, and tunnel bytes.
Preserve content encodings and any remaining transfer codings exactly. The
file may therefore contain gzip-coded bytes. No decompression, media decoding,
filename inference, multi-body directory export, partial-file option, or MIME
filtering is included. A complete empty body creates an empty file.

## Completion and failures

Stage a single destination before reading, using existing `StagedFile` rules:
parent directory must exist; existing paths including dangling symlinks fail;
the input path cannot be overwritten. Use the caller's path literally, never a
header, URL, Content-Disposition, or Content-Type as a path component.

The artifact can publish only after all of the following:

1. Whole-capture inspection reaches normal EOF, with no read, analysis,
   cancellation, deadline, budget, or emitted-record output error.
2. The selected message was observed and its terminal status is `Complete`.
3. Exported byte count equals that message's `body_bytes`. Construct/validate
   the artifact DTO and preflight its report serialization/output charge.
4. Flush the writer, sync staging, recheck cancellation/deadline, then persist
   without clobbering. Recheck the destination race at persistence.

Close-delimited bodies require clean FIN; EOF alone and RST do not complete
them. `Upgrade`, including CONNECT/101, is not `Complete` and cannot publish a
tunnel artifact. HEAD/204/304 or a normal zero-length message with `Complete`
exports zero bytes. A selected complete message stays complete if a later
ordinary HTTP message or stream issue is reported; those are existing analysis
evidence, not execution errors. A later actual analysis/read/limit error blocks
publication. No claim of retroactive wire-byte uniqueness is added: export
uses the existing reassembler's accepted bytes and configured overlap policy.

| Failure | Code/kind/exit | Artifact outcome |
| --- | --- | --- |
| Invalid flag pairing/index, missing values, duplicates, numeric overflow | Existing Clap/startup `cli.error`, usage/2 | No destination |
| Selected message absent at EOF | `cli.http_body_message`, usage/2 | Discard staging |
| Selected status incomplete/malformed/gap/conflict/reset/evicted/upgrade | `packet.http_body_incomplete`, packet/3, include selected index/status and original HTTP cause when present | Discard staging |
| Selected status limit | `policy.http_limit`, policy/6, retain original HTTP limit cause | Discard staging |
| Selected body byte-count mismatch | `internal.http_body_evidence`, internal/70 | Discard staging |
| Existing input/analysis/sink/cancellation/deadline failure | Preserve existing classification and source chain; cancellation stays 130 | Discard staging |
| File write/sync/persist failure | Existing `io.output_file`, I/O/5, original source retained | Discard staging; never overwrite destination |
| Stdout fails after successful persistence | Existing output failure behavior | Published artifact remains intact |

A pre-existing `--stream` selection error takes precedence over an absent body
message. Do not publish a normal terminal `complete` before artifact validation
and persistence. Earlier NDJSON message/transaction events may precede a terminal
error. Aborting drops staging using the existing best-effort temporary-file
cleanup. Normal abort tests require no leftover file; removal is not guaranteed
if the filesystem refuses drop cleanup, and the current helper cannot report
that drop error. This feature adds no stronger cleanup promise. It never reports
an unpublished temporary path as a successful artifact.

## Core API and modules

The parser seam belongs in
`protocol/application/http/codec/body.rs`, re-exported through the existing
`protocol::application::http` public API:

```rust
pub enum ConsumeError<E> {
    Framing(http::Error),
    Sink(E),
}

// Method on BodyDecoder; the exact generic name is not part of the contract.
pub fn consume_with<E>(
    &mut self,
    input: &[u8],
    emit: &mut impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<Progress, ConsumeError<E>>;
```

`consume_with` invokes the synchronous borrowed-slice callback only for
nonempty entity spans in Length/Chunk/Close states, in parse order. Validate the
span's body-byte charge before callback invocation; no byte beyond a ceiling
reaches the sink. After successful callback return, commit decoder counters and
state. Framing can fail after earlier spans were delivered, so callbacks must
stage output and treat any error as terminal; retry/resume after a sink failure
is unsupported. No retained Vec of body chunks is returned. Existing `consume`
delegates to this same implementation with an infallible discard callback,
retaining its current signature and behavior. Preserve distinct framing/sink
errors and their sources.

At `analysis::http`, add a public synchronous trait:

```rust
pub trait BodySink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), BoundaryError>;
}
```

Add `Collector<'a>::with_body_sink(self, message: u64,
sink: &'a mut dyn BodySink) -> Result<Self, application::Error>`.
`Collector::new` remains the construction entry point; zero message is rejected
using a typed invalid-selection variant classified as `cli.http_body_selection`.
That library-only validation is distinct from the CLI's ordinary positive-u64
Clap validation, which publishes `cli.error`. Configuration after the first
observe attempt, or a second pre-observe body target, returns the typed
`application::Error::Configuration`/`cli.http_configuration` specified by HTTP-T.
Store the optional target privately; call it only when the currently parsed
message index matches. Other bodies retain the discard path. Sink failures
propagate through `application::Error::Output`; they must not be converted into
a recoverable Message status. Callbacks finish before analysis consumes more
input, providing bounded memory and backpressure.

Put selected-body state/helpers in private `analysis/http/body.rs` if splitting
the HTTP owner is needed. This API does not add body chunks to `Event` or change
the shared `Session`/application collector protocol. HTTP-B01 follows HTTP-T01
so the final collector owns both optional capabilities coherently.

## CLI assembly and limits

Add private `commands/http/body.rs` with disjoint `BodyWriter` and
`SelectedMessage` state. Keep `StagedFile` in the command; `BodyWriter` borrows
its file through `BufWriter<&mut File>` and owns incremental SHA-256/count only.
The collector borrows only `BodyWriter`; the event callback independently
updates `SelectedMessage` (index/status/stream/generation/body_bytes/HTTP cause).
Use the already-declared `sha2` dependency. Check invocation/cancellation before
each write and hash exactly the bytes written. After inspection consumes the
collector, flush/consume BodyWriter, release its file borrow, then validate,
sync, and publish. Use a 64 KiB buffer and one active artifact; no Arc/Mutex is
needed to work around overlapping mutable borrows.

`--max-http-body-bytes` remains the single-message byte ceiling, default 16 MiB,
valid 1..=256 MiB; it bounds the exported artifact too. No automatic increase
is made for export. Existing source, reassembly, header, application-state,
provenance, duration, and output limits still apply to the whole analysis.
The artifact bytes are not charged as serialized inspection bytes; its serialized
metadata is charged once under `--max-application-output-bytes` before publishing.
No new preset numbers or resource flags are necessary. Heap usage must not grow
with the selected body length beyond the existing bounded reassembly, framing,
provenance, and message-evidence state; body storage is the bounded staged file.

Make this allowance sharing concrete in HTTP-B02: the command owns
`EventOutput`; change private `offline_analysis::inspect` to borrow
`&mut EventOutput` instead of creating it, remove its now-unused
`Inspection.application` field, and mechanically adapt the DNS-read caller.
Keep format/stream arguments for IP event publication. Add
`EventOutput::charge(&impl Serialize) -> Result<(), CliError>` with the current
compact-JSON sizing/error behavior; `emit` delegates its charge to that method.
After inspection, charge **only BodyExport once** against the same remaining
allowance. Do not recharge prior events, grant another full allowance, or charge
artifact bytes as JSON. Exact-fit and one-byte-short combined allowance tests
must include ordinary message/transaction bytes plus artifact metadata.

Then prepare the final success envelope using BASE-01's prepared output seam.
For NDJSON this checks the full envelope, newline, sequence, and captured resource
snapshot against the record ceiling before persistence. For aggregate JSON it
freezes and preflights the decorated envelope without adding a 16 MiB aggregate
limit. Publish that same prepared result only after the artifact commits.

## Output

Family is v7. Aggregate HTTP result and NDJSON `complete` gain required
`body_export: null | BodyExport`; null without extraction. Successful extraction
sets the following CLI-owned record, after publication:

| Field | Type/meaning |
| --- | --- |
| `message` | Positive selected message index |
| `stream`, `generation` | Existing message connection identifiers |
| `path` | Caller destination using the existing path-display convention |
| `bytes` | u64 exact artifact byte count, equal to selected `body_bytes` |
| `sha256` | 64 lowercase hexadecimal characters hashing exactly the artifact |
| `representation` | Fixed string `http_body_after_dechunking` |

No body data is embedded in JSON/NDJSON. There is no artifact event before
`complete`; report conversion must finish before persistence. Text keeps normal
inspection output and adds `body message=<N> bytes=<N> sha256=<HEX> path=<PATH>`
through the existing sanitizing writer, followed by the normal summary.
No success artifact record is present in an execution-error envelope.

## Acceptance cases

| ID | Fixture/action | Required observation |
| --- | --- | --- |
| HB01 | Segmented Content-Length binary body containing NUL/non-UTF8 | File equals exact selected bytes; digest/count agree |
| HB02 | Chunked body split at every framing boundary, chunk extensions, trailers, next pipelined message | File contains only concatenated chunk data, once |
| HB03 | Content-Encoding gzip and remaining non-final transfer coding | Coded bytes are unchanged; no decompression |
| HB04 | Close-delimited body ending in FIN versus EOF/RST | Only clean completion publishes |
| HB05 | Complete empty body, HEAD, 204/304 versus CONNECT/101 Upgrade | Empty complete artifact succeeds; upgrade fails with packet error |
| HB06 | Exact/reordered TCP retransmission and IP reconstruction | Accepted body spans appear once; configured reassembly semantics hold |
| HB07 | Absent selector, zero selector, one missing paired flag, changed stream/window settings | Exact usage failures; no destination; message numbering documented |
| HB08 | Selected malformed/limit/gap/conflict/reset/evicted/incomplete message | Prescribed classified error, no published partial file |
| HB09 | Selected complete message followed by malformed capture/truncated compression | Whole-run error prevents publication |
| HB10 | Selected complete message followed by an ordinary later HTTP/stream issue | Artifact still publishes if inspection itself succeeds |
| HB11 | Existing file/dangling symlink/destination race; write/sync/persist failure; cancellation/deadline at commit | No overwrite; staged data cleaned; sources retained |
| HB12 | Sink rejects after earlier successful chunks | Immediate classified execution failure, no further body callbacks/publication |
| HB13 | Body exceeds limit by one byte; output metadata charge cannot fit | Limit prevents publication; beyond-limit bytes never reach sink |
| HB14 | stdout fails before versus after persistence | Before: no artifact; after: successful file remains, no false complete |
| HB15 | Large body delivered in bounded segments | Sink sees bounded borrowed spans; parser buffer bound independent of body length |
| HB16 | Text/JSON/NDJSON, file/stdin, compressed input, combined --transactions | One identical artifact/digest; v7 fields/events/terminal behavior conform |
| HB17 | Configure zero/repeated body target or configure after any observe attempt | Typed library validation; CLI numeric/pairing errors retain ordinary Clap classification |

HB15 uses an instrumented sink and decoder-buffer observations, not a flaky
wall-clock/RSS assertion. Existing HTTP framing and analysis regressions must
remain passing.

## Tickets

[HTTP-B01](issues/01-core-body-sink.md) implements the parser/collector seam.
[HTTP-B02](issues/02-cli-body-artifact.md) implements staged publication and docs.

## Comments

Single-message extraction is deliberate scope, not deferred design. Batch
extraction, naming policies, content decoding, and partial artifacts are absent.
