# Split captures into faithful bounded parts

Status: ready-for-agent
Feature ID: SPLIT
Parent: [offline investigation batch](../offline-investigation/spec.md)
Implementation: not started; this session is specification-only.

## User behavior

```console
packetcraftr split capture.pcapng --frames-per-file 1000 --write-dir parts
packetcraftr --output json split capture.pcap.gz --frames-per-file 500 --write-dir parts --compression zstd
packetcraftr --output ndjson split - --frames-per-file 100 --write-dir parts < capture.pcapng
```

Add `split INPUT --frames-per-file N --write-dir DIR`. N is required and in
`1..=u64::MAX`; DIR must already exist and be a directory. Input `-`, gzip, and
Zstd follow existing capture-reader behavior, including terminal-stdin rejection.
Output report formats are text, JSON, NDJSON (`ToolFormat`), default text.
`--compression none|gzip|zstd` applies independently to each saved capture;
default none, irrespective of input compression.

Fixed filenames use one-based six-digit zero-padded indices:
`part-000001.pcap` or `part-000001.pcapng`, with `.gz` or `.zst` when selected.
The detected container format determines the extension, not the source filename.
All generated names are basenames under DIR, never capture-controlled paths.
There is no prefix option, overwrite flag, binary stdout, interval/byte-sized
part mode, filter, epoch window, decoder, stream selection, or format conversion.

Each physical packet belongs to exactly one contiguous part in original order.
Non-final parts have N packets; the final part has 1..N. An empty valid capture
produces one metadata-only part. Zero-byte input remains an invalid capture.
Streams and IP datagrams may span parts; `export` remains the command for
dependency-complete extraction.

A reader numbers frames within each part from 1. Recover a source frame number
as `first_frame + part_local_frame - 1` from the part report. Conversation and
HTTP message indices are recomputed for each independent part; they are not
preserved identifiers from an analysis of the full source.

## Fidelity contract

For each source frame range, the decoded container bytes of a part must equal
the result of `capture_file::select` selecting that range from the source.
This is the authoritative byte-level oracle, including empty selection.

- Preserve source format, classic headers, packet block kind, exact packet
  bytes, captured/original lengths, timestamps including absent timestamps,
  interface IDs/options, packet options, unknown metadata, and section order.
- Copy **all** source metadata into **every** part, even metadata belonging
  to unselected interfaces or appearing after the last packet. Reused section
  local interface IDs retain their sections and capture-global numbering.
- As in `select`, change each PCAPNG SHB's section length to unknown. This is
  the only byte modification. Interface statistics still describe the source;
  document their meaning rather than recalculating or presenting them as part
  statistics. Mixed endian sections and unknown options remain raw.
- Use raw `CaptureHeader::raw()`/`CaptureRecord::raw_bytes()` and existing
  private `write_selected_section`; `Writer` reconstructs packet records and
  is not the correct mechanism. No protocol dissection or native I/O occurs.

## Core API and algorithm

Add public `capture_file::split`, implemented at `capture_file/split.rs` with
private responsibility modules if needed. Its only public entry points are:

```rust
pub struct Options { pub frames_per_file: u64, pub limits: Limits }
pub struct Limits {
    pub input: capture_file::Limits,
    pub max_files: usize,
    pub max_metadata_records: usize,
    pub max_metadata_bytes: usize,
    pub max_output_bytes: u64,
}
pub struct Plan { /* private validated state */ }
pub fn plan<R: Read + Seek>(reader: &mut Reader<R>, options: Options) -> Result<Plan, Error>;
impl Plan { pub fn report(&self) -> &Report; }
pub trait Sink {
    fn begin(&mut self, index: u64, format: Format) -> Result<(), BoundaryError>;
    fn write(&mut self, bytes: &[u8]) -> Result<(), BoundaryError>;
    fn finish(&mut self, part: &Part) -> Result<(), BoundaryError>;
}
pub fn write<R: Read + Seek>(
    reader: &mut Reader<R>, plan: Plan, sink: &mut impl Sink,
) -> Result<Report, Error>;
```

These declarations show signatures/field shape, not code to paste into a single
module; use the actual existing imported types. `Limits::default` uses the table
below and `capture_file::Limits::default`; `Limits::validate` and options
validation run before source consumption or sink callbacks. `Plan` retains all
bounds and is consumed by `write`. No equivalent root re-exports or alternate
splitting entry point are added.

1. CLI first obtains a validated seekable snapshot with existing
   `input::snapshot_capture`, for files and stdin alike. Input snapshot bytes
   are bounded by the existing encoded/decoded limits. The snapshot is an
   additional sequential validation/copy pass, not memory retention of frames.
2. Core `plan` rewinds the seekable reader to its initial header, including
   when the caller has previously consumed records. It consumes
   through EOF and charges physical frames/captured bytes. Retain the original
   header and each raw metadata record with an `after_frame` anchor: the number
   of physical packet records preceding it. Retain metadata in source order.
   Count packet-record raw bytes separately from captured payload bytes.
3. Compute `parts = max(1, frames / N + (frames % N != 0))` using checked
   arithmetic. Preflight the file ceiling and exact decoded output size:
   `packet_record_bytes + parts * (header_bytes + metadata_record_bytes)`.
   Build bounded Part descriptions (range, frame/payload/container counts).
   Hash the source's raw header/records with SHA-256 during this pass.
4. CLI reads the immutable plan report, derives every destination, and checks
   all collisions before generating staged outputs. Core `write` rewinds the
   snapshot once, then consumes all packet records sequentially once.
5. For a part [a,b], write the patched/raw initial header, then cached metadata
   whose anchor is less than a. For each selected packet j, write its raw record
   followed by metadata anchored at j when j < b. After b, append all remaining
   metadata anchored at or after b. Iterate metadata in original order. For an
   empty source, write the header and every metadata record once.
6. Second-pass source metadata is validated/read but not independently emitted;
   the ordered cache controls replay. Hash every second-pass raw source record
   including skipped metadata. Reject any changed header/count/metadata/packet
   digest before returning success. The CLI never publishes a partial run.
7. Sink callbacks are synchronous: exactly one begin, ordered writes, and one
   finish per successfully generated part. Abort on the first sink/read/budget
   error; there is no sink rollback callback. The caller owns staging cleanup.
   EOF-only metadata must be read/digest-checked before final success, even
   when the final packet has already been written.

Expose the reader's existing interruption check only within `capture_file`
(`pub(super)`), and invoke it before/after each sink callback and between cached
metadata records. Cached replay is bounded but can run without source reads;
the reader's ordinary next-record checks alone are insufficient. The input
deadline/cancellation remains cooperative around blocking sink calls.

This performs two core source passes, plus CLI snapshotting, and metadata replay
proportional to actual output. It never rescans the entire input once per part,
retains packet payloads for all parts, or opens compressors for all parts.
`write` rechecks physical/output ceilings and the planned shape; source changes
cannot turn preflight into an unchecked write.

## Limits and resource diagnostics

The CLI flattens `OfflineCaptureLimitsArgs`, `MaxDurationArgs`, and a saved-
capture compression group. It is `Spec::OFFLINE = true`, cancellation enabled,
and declares its run duration. It does not expose analysis/reassembly bounds.
Existing frozen input preset values and explicit-override precedence are kept.
`--max-duration-ms` defaults to 3,600,000 and permits 1..=3,600,000. Add a local
`SplitRunTime` marker whose `RunTime::PARSED` is exactly that range; invalid
values therefore fail as ordinary `cli.error` before startup installs a deadline
or opens input. Retain the shared duration group's existing preset values
(30,000 ms for ci-v1, 300,000 ms for workstation-v1). Other split semantic
option ranges are validated by the command before source I/O; malformed or
overflowing numeric tokens remain ordinary `cli.error` parse failures.

| New flag / core field | Default | Valid range | ci-v1 / workstation-v1 | Accounting |
| --- | --- | --- | --- | --- |
| `--max-files` / max_files | 256 | 1..=4096 | 64 / 256 | All parts, including metadata-only part; report/staged-path count |
| `--max-split-metadata-records` / max_metadata_records | 4096 | 1..=4096 | 1024 / 4096 | Initial header plus all retained metadata records, cumulative |
| `--max-split-metadata-bytes` / max_metadata_bytes | 16777216 | 1..=67108864 | 2097152 / 16777216 | Raw retained header/metadata length plus 128 bytes per cache entry, cumulative |
| `--max-split-output-bytes` / max_output_bytes | 268435456 | 1..=u64::MAX | 33554432 / 536870912 | Separate cumulative decoded-container and encoded-file byte counts, each bounded by this same ceiling |

The metadata ceilings are intentionally no larger than default per-gap reader
ceilings: removing packet records can coalesce metadata runs. Thus any part
meets those ceilings even when all source metadata becomes adjacent. These are
cumulative cache limits; source reader per-frame limits do not replace them.
Apply allocation checks before cache growth. Part descriptors are bounded by
4,096 files. Source frames/payload bytes count once in reported totals, not once
per snapshot/planning/writing pass. Re-reading may revalidate each pass against
the same ceiling; do not multiply the user's physical-input allowance.

Decoded output is exact-preflighted and charged before sink writes. CLI wraps
the destination below the compressor in a shared encoded-byte counter and
checks before each underlying write, including finish/trailer writes; equality
with the ceiling succeeds. No counter uses saturating arithmetic to conceal an
overflow. Both counts include headers, metadata, padding, and compression
framing in their respective domains. The temporary snapshot has its separate
input bound; staged outputs share the output bound. One active 64 KiB output
buffer/compressor is used. Retained closed paths and report rows are finite.
For a partial underlying write, the encoded counter advances by the actual
successful byte count, not the requested slice length; final file lengths must
agree with the accumulated encoded counts.

The below-compressor encoded writer stores a typed refusal in its shared
counter state before returning `io::Error` for an exceeded limit/overflow.
If compression write or finish fails, first inspect that refusal and return
the original `policy.capture_split_limit` failure; do not let gzip/Zstd wrapping
reclassify it as `io.capture_compression`. Otherwise map destination write or
finalization failures to `io.output_file`, retaining the compression/I/O source
chain. Abort on the first error, so a latched refusal cannot affect later work.

Declare each new bound via `Spec::resources`: file count in ResultRetention,
metadata bounds in IndexedMetadata, output bytes in Operation. Explain the two
output counters in resource docs; this is not an RSS ceiling.

## Publication, error precedence, and cleanup

Add `StagedFile::seal(self) -> Result<SealedFile, CliError>` in
`src/staged_output.rs`: check/sync as existing staging does, close the handle via
`NamedTempFile::into_temp_path`, and retain a private no-clobber-publishable path.
`SealedFile::persist` checks cancellation/deadline and uses `persist_noclobber`;
drop cleans up an unpublished path. Finish compression/flush before sealing.
Only one staged output descriptor/compressor remains open while generating.

Extract the existing small ordered-publication/rollback behavior from
`commands/follow/write.rs` into `staged_output.rs`; use it for sealed split
files and adapt follow without changing its externally observed behavior.
The helper accepts only this invocation's staged files, publishes in provided
order, and tracks precisely which destinations it successfully created.

After all parts are generated, compressor-finalized, synced and closed, build
and validate every report field and prepare the success envelope through
BASE-01's prepared-output seam before the first publication. NDJSON checks the
actual decorated envelope plus newline against its 16 MiB record bound;
aggregate JSON preflights the frozen decorated envelope without a new global
16 MiB cap. Publish files in numerical
order, checking interruption before each commit. On commit failure or
interruption, attempt removal of already-published files from this invocation
in numerical order; never delete a destination whose persist failed. Keep the
primary classification, append cleanup errors with remaining paths and their
causes, and drop all unpublished staging. This is not a multi-file transaction.
Do not claim that all files were removed if cleanup fails. Unpublished
temporary-path drop cleanup remains best effort as in existing staged files;
there is no guarantee of removal when the filesystem refuses it. Explicit
rollback failures for previously published destinations are always reported.

After every file successfully publishes, a stdout/report error leaves the files
intact, matching existing export/rewrite semantics; the same applies to a
deadline or cancellation arriving after the final successful commit. No progress/part report is
published before the whole artifact set is committed. A malformed late input,
source-digest mismatch, deadline, or generation error before commits produces no
new final destinations. A partial commit failure has no final destinations only
when all rollback removals succeed. No destination directory is created or removed.

| New failure | Classification |
| --- | --- |
| Semantically invalid zero/range split option after successful numeric parsing, excluding duration's parser range | `cli.capture_split`, Kind::Usage, exit 2 |
| Missing/duplicate/unrecognized flag, missing value, malformed/overflowing numeric token, out-of-range duration | Existing `cli.error`, Kind::Usage, exit 2 |
| File/metadata/decoded-or-encoded-output ceiling or checked counter overflow | `policy.capture_split_limit`, Kind::Policy, exit 6; name bound/attempted/limit |
| Source changes between core passes | `packet.capture_split_source_changed`, Kind::Packet, exit 3 |
| Sink failure | Preserve `BoundaryError` classification/sources through typed split error |

Wrap existing capture/I/O/allocation errors with original sources/classification;
CLI path/write/finalize/sync/persist errors use existing `io.output_file` for
artifact I/O. Existing compression structural/input errors retain their own
classification. Cancellation remains exit 130. No completed report accompanies
an execution failure.

## Output

Family v7 adds command `split`. NDJSON has exactly one terminal `complete`
result on success, no data events; failures follow the usual terminal error
contract. JSON publishes the same result. All fields below are required.

| Result field | Exact meaning/type |
| --- | --- |
| `format` | `pcap` or `pcapng`, detected source and output container |
| `compression` | `none`, `gzip`, or `zstd` |
| `directory` | User destination directory, existing path-display convention |
| `frames_per_file` | Positive u64 requested boundary |
| `frames_read` | u64 physical source packets |
| `captured_bytes_read` | u64 source captured payload bytes |
| `metadata_records` | u64 initial header plus retained non-packet records |
| `metadata_bytes` | u64 raw header/metadata bytes, excludes in-memory overhead charge |
| `decoded_bytes_written` | u64 sum of complete uncompressed part lengths |
| `encoded_bytes_written` | u64 sum of complete saved file lengths |
| `files` | Ordered array of Part records below |

Each Part has `index` (positive u64), `file` (fixed ASCII basename),
`first_frame`/`last_frame` (nullable one-based u64, both null only for empty
source), `frames` (u64), `captured_bytes` (u64), `decoded_bytes` (u64), and
`encoded_bytes` (u64). Core `Part` owns only index/range/frames/captured_bytes/
decoded_bytes; core `Report` owns format/frames_per_file/source totals/raw
metadata totals/decoded output total/parts. The CLI adds names, directory,
compression and encoded byte facts through explicit DTO conversion.

The files array length is 1..4096. Frame/payload sums equal source totals;
decoded/encoded sums equal their result totals. No timestamps are synthesized
for summaries. Text prints one sanitized part line containing filename, source
range, frames, and decoded/encoded bytes, then the totals and the literal note
`metadata describes the source capture`. No per-file absolute directory string
is repeated in machine output, keeping the report bounded by file count.

## Acceptance cases

| ID | Fixture/action | Required observation |
| --- | --- | --- |
| SP01 | 0, N, N+1, 2N packets; N=1; N greater than total | Exact part counts/ranges; one metadata-only part for valid empty input |
| SP02 | Classic PCAP both endiannesses and precisions, unusual global header fields | Every part equals source-format `select` for its range |
| SP03 | Mixed-endian PCAPNG, repeated local interface IDs, interleaved IDBs, unknown blocks/options before/between/after packets | All metadata/sections preserved in each part; IDs and record bytes faithful |
| SP04 | Enhanced, Simple, and obsolete packet blocks; absent/regressing timestamps | Raw packet blocks preserved; no timestamp requirement/correction |
| SP05 | Concatenate only packet records from all decoded parts | Exactly the original packet-record sequence, no omission/duplication |
| SP06 | Metadata-only source, zero-byte source, malformed final block, truncated gzip/Zstd trailer | Valid empty succeeds; invalid input leaves no destinations |
| SP07 | Each new limit at equality and one unit over; many packet-separated metadata blocks | Equality accepted; cumulative coalesced-metadata limits and amplification preflight enforced |
| SP08 | Small decoded output but encoded output crosses limit on compressor finish | No publication; counter includes final bytes; exact `policy.capture_split_limit`, exit 6 |
| SP09 | Source modified after plan, including same-sized changed packet bytes | Digest mismatch blocks success/publication |
| SP10 | Existing destination/dangling symlink/missing directory/late destination race | No overwrite; all predicted names checked before generation; commit race rechecked |
| SP11 | Write/compressor-finish/sync/commit failure; interruption before a later commit | Unpublished staging cleans; earlier publications roll back; remaining paths reported on cleanup failure |
| SP12 | 256 small parts under instrumented staging | At most one output handle/compressor active; closed paths remain bounded |
| SP13 | stdout breaks only after all commits | Files remain; reporting fails honestly without false terminal success |
| SP14 | File/stdin and gzip/Zstd input/output; portable build; text/JSON/NDJSON | Same decoded parts, proper names/totals, schema-valid reports and terminal behavior |
| SP15 | Attempt --filter, time splitting, output pcap, or conversion | Explicit invalid invocation; no implicit alternate semantics |
| SP16 | Reread every part under same reader max-size/interface settings and default metadata-run ceilings | Valid independently readable parts, even when selection coalesces metadata |
| SP17 | Cancel/expire while cached metadata is replaying without source reads; invalid duration bounds | Replay stops at next check; invalid duration fails before source I/O with specified classification |

Use existing `select` as a public observable equivalence oracle and a separate
raw packet-sequence assertion. Do not duplicate split's algorithm in tests.

## Tickets

[SPLIT-01](issues/01-core-split.md) owns planning/raw copying.
[SPLIT-02](issues/02-cli-split.md) owns snapshots/staging/CLI and reporting.

## Comments

Full metadata replication is intentional and bounded. Time-based/byte-sized
part modes and dependency-complete parts are outside this decided feature.
