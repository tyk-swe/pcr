# Core capture-file research for `capture_file::split`

Research for implementing `.scratch/capture-split/spec.md` ("Fidelity contract"
and "Core API and algorithm" sections are authoritative). All paths relative to
repo root `/home/ubuntu/code/pcr/1/pcr`; crate roots are
`crates/packetcraftr-core` and `crates/packetcraftr-cli`.

## 1. Module map: `crates/packetcraftr-core/src/capture_file/`

```
capture_file.rs            root: decls + re-exports (41 lines)
classic.rs                 `mod decode; mod encode;`
classic/decode.rs          read_pcap_header, read_next_pcap_record
classic/encode.rs          write_pcap_header, write_pcap_frame
compression.rs             pub mod: Input/Output gzip+Zstd, compression::{Limits,Error,Format}
error.rs                   capture_file::Error + Classified impl
link_type.rs               LinkType knowledge
map.rs                     map_frames (normalize-to-PCAPNG mapper)
merge.rs                   merge, MergeLimits, MergeSource, MergeReport
model.rs                   ALL public data types (Limits, ReaderLimits, CaptureHeader,
                           CaptureRecord, RecordKind, Budget, Section, PcapHeader, ...)
pcapng.rs                  re-export hub (all items `pub(super)`/`pub(in crate::capture_file)`)
pcapng/decode.rs           PcapNgState, read_next_pcapng_record, read_section_record
pcapng/decode/framing.rs   FramedBlock, packet_block_kind(), block read+raw retention
pcapng/decode/record.rs    block_type -> RecordKind dispatch
pcapng/encode.rs           write_section_header, write_interface_description,
                           write_enhanced_packet, validate_new_interface, select_interface
pcapng/interface.rs        parse_interface_description (if_tsresol/if_tsoffset)
pcapng/options.rs          visit_options/parse_options (strict eoo/zero-tail rules)
pcapng/packet.rs           parse_enhanced/obsolete/simple_packet, ParsedPacket
pcapng/section.rs          SectionHeader, SHB readers, write_selected_section  <-- KEY
reader.rs                  Reader<R>
rewrite.rs                 rewrite, select, copy_records
wire.rs                    `mod primitives; mod timestamp;` re-exports `pub(in crate::capture_file)`
wire/primitives.rs         block-type/magic consts, int codecs, read_exact_* helpers
wire/timestamp.rs          timestamp_from_ticks/to_ticks, resolution validation
writer.rs                  Writer<W> (generates NEW captures)
```

Root `capture_file.rs:16-41` declares `mod`s and re-exports. Note visibility
layers: `model`/`reader`/`rewrite`/`writer`/`error` are private `mod`s whose
items are re-exported; `compression` is `pub mod`; everything under `pcapng` and
`wire` is `pub(in crate::capture_file)` or `pub(super)` — so a new
`capture_file/split.rs` sibling CAN reach `write_selected_section`, the
`Reader::check_interrupted` method (currently private — see §2), and the raw
accessors. `map` and `merge` show the established "module for one public
entry point + Limits/Report types" precedent; `merge` puts `MergeLimits`
etc. in merge.rs itself while shared types live in model.rs. Spec wants
`capture_file::split` with `pub` items `Options/Limits/Plan/Sink/plan/write`
re-exported from the root — follow the `merge` re-export pattern at
`capture_file.rs:31`.

## 2. The Reader (`capture_file/reader.rs`)

### Struct and bounds

```rust
pub struct Reader<R> {                       // reader.rs:31
    inner: R,
    state: ReaderState,                      // pub(super) enum, :18
    header: CaptureHeader,
    interfaces: Vec<Interface>,              // capture-global, cross-section
    limits: ReaderLimits,
    scratch: Vec<u8>,                        // reused per-record buffer
    finished: bool,
    cancellation: Option<Cancellation>,
    deadline: Option<Arc<crate::budget::Deadline>>,
}
```

`ReaderState` (:18-26): `Pcap { endianness, precision, snap_len, link_type }` or
`PcapNg(PcapNgState)`. Construction needs only `R: Read`:
`Reader::new(inner)` (:50) / `Reader::with_limits(inner, ReaderLimits)` (:54)
consume the container header (24-byte pcap global header or first SHB block).
Empty input → `Error::EmptyInput` (:60); bad magic → `Error::UnrecognizedFormat`
(:105).

### Format detection (reader.rs:58-109)

First 4 bytes select format: `d4 c3 b2 a1` pcap LE µs, `a1 b2 c3 d4` pcap BE µs,
`4d 3c b2 a1` pcap LE ns, `a1 b2 3c 4d` pcap BE ns, `0a 0d 0d 0a`
(`PCAPNG_SECTION_HEADER`, wire/primitives.rs:13) → SHB; inside the SHB the BOM
`4d 3c 2b 1a`/`1a 2b 3c 4d` gives per-section endianness
(section.rs:58-66). Classic pcap gets an implicit single `Interface` at index 0
(:111-127). `reader.format()` (:185) delegates to `CaptureHeader::format()`;
`reader.endianness()` (:193) is dynamic — follows the *current* PCAPNG section.
Version checks: pcap must be 2.4 (classic/decode.rs:32); pcapng must be
1.0 or 1.2 (section.rs:115).

### Iteration and what a "record" is

- `pub fn next_record(&mut self) -> Result<Option<CaptureRecord>, Error>` (:214)
  — returns EVERY validated record incl. metadata; `finished` latches on EOF or
  first error (:216-231, error poisons the stream).
- `pub fn next_frame(&mut self) -> Result<Option<Frame>, Error>` (:262) —
  skips records with `frame: None`.
- `Iterator<Item = Result<Frame, Error>>` impl over `next_frame` (:284).

A physical packet record = `record.frame.is_some()` (copy_records at
rewrite.rs:81 counts frames exactly this way, charging
`frame.captured_length()`). For classic pcap every record is a packet
(classic/decode.rs:139-149). For PCAPNG, `record.frame.is_some()` iff
`packet_block_kind(block_type).is_some()` — see §5.

### Rewind / seek (reader.rs:296-312)

```rust
impl<R: Read + Seek> Reader<R> {
    /// Reopens a seekable capture from its first header, resetting all section
    /// and interface state while retaining limits and cancellation.
    pub fn rewind(&mut self) -> Result<(), Error> {
        self.check_interrupted()?;
        self.finished = true;
        self.inner.rewind()?;
        let fresh = Reader::with_limits(&mut self.inner, self.limits)?;
        self.state = fresh.state; self.header = fresh.header;
        self.interfaces = fresh.interfaces; self.scratch = fresh.scratch;
        self.finished = false;
        self.check_interrupted()?;
        Ok(())
    }
}
```

This is exactly the "rewind to initial header" primitive the spec's `plan` and
`write` need — it re-reads the header (revalidating it, i.e. header bytes are
re-checked against limits) and resets finished/interface/section state.
`get_ref/get_mut/into_inner` (:271-281) expose `R` for position checks if
needed (the tests use `get_ref().position()`).

### Interruption check — currently private

```rust
fn check_interrupted(&self) -> Result<(), Error> {      // reader.rs:175
    if let Some(signal) = &self.cancellation { signal.check()?; }
    if let Some(deadline) = &self.deadline { deadline.enforce()?; }
    Ok(())
}
```

Called before AND after every record read (:234,:257) and around `rewind`.
Spec requires exposing it `pub(super)` inside `capture_file` so split can call
it between sink callbacks and cached metadata writes. It returns
`Error::Cancelled` / `Error::DurationLimit` via
`crate::budget::deadline_error_conversions!(Error)` (error.rs:258; macro at
budget.rs:268-287 converts `Interrupted`/`DeadlineExceeded`).
Builders: `.with_cancellation(Cancellation)` (:150),
`.with_deadline(Arc<Deadline>)` (:159); `deadline()`/`replace_deadline` are
`pub(crate)` (:164-173) — used by CLI `invocation::reader` to attach the
invocation deadline.

### Limits

Two distinct structs, both in model.rs:

```rust
pub struct Limits { pub max_frames: u64, pub max_bytes: u64 }   // model.rs:26
```
Default `10_000` frames / `256 MiB` bytes (`DEFAULT_STREAM_FRAMES`,
`DEFAULT_STREAM_BYTES`, model.rs:20-22). `Limits::validate()` (:42) rejects
zero with `Error::InvalidLimit { field, value }` ("cli.capture_limit", Usage).
Charged via `Budget` (:71): `Budget::new(limits)`, `.charge(frame_bytes: u32)`
per frame, `.after()` non-committing preview, `.frames()`/`.captured_bytes()`.
Failures: `Error::FrameLimitExceeded` / `Error::StreamByteLimitExceeded`
("policy.capture_stream_limit", Policy). This is the ceiling the spec calls
`split::Limits::input` — one physical frame + captured-payload-byte accounting.

```rust
pub struct ReaderLimits {                       // model.rs:180
    pub max_size: usize,                        // per packet or PCAPNG block
    pub max_interfaces_per_section: usize,      // 4_096 default
    pub max_total_interfaces: usize,            // 65_536 default
    pub max_metadata_blocks_per_frame: usize,   // 4_096 default
    pub max_metadata_bytes_per_frame: usize,    // 64 MiB default
}
```
Reader per-item bounds. NOTE for split: `max_metadata_*_per_frame` counters
reset on each decoded packet (`PcapNgState::reset_metadata`, decode.rs:96-99;
`account_metadata` :79-94). Spec's metadata ceilings are deliberately no
larger, since removing packets coalesces runs (SP07/SP16).

### Error (`capture_file/error.rs`)

`pub enum Error` (`#[non_exhaustive]`, :11-142). Variants relevant to split:
`DurationLimit { actual, limit }`, `Cancelled(#[from] Cancelled)`,
`AllocationFailed { kind, requested }`, `Io(#[from] io::Error)`, `EmptyInput`,
`UnrecognizedFormat { magic }`, `Truncated { context, expected, actual }`,
`UnsupportedVersion`, `InvalidData { format, reason }`, `SizeLimitExceeded`,
`InvalidBlockLength`, `BlockLengthMismatch`, `BlockCrossesSectionBoundary`,
`SectionEndedEarly`, `SectionHeaderBeforeBoundary`, `SectionRemainderTooSmall`,
`TimestampOutOfRange`, `TimestampUnavailable`, `InvalidTimestampFraction`,
`UndefinedInterface`, `InterfaceLimit`, `TotalInterfaceLimit`,
`MetadataBlockLimit`, `MetadataByteLimit`, `FrameLimitExceeded`,
`StreamByteLimitExceeded`, `InvalidLimit`, `Predicate { number, source:
BoundaryError }`, `Transform{..}`, merge variants. `Classified` impl (:144):
I/O → "io.capture_file" (Io); limit/ceiling → "policy.capture_stream_limit"
(Policy); InvalidLimit/parse-ish → "cli.*" (Usage); everything else falls to
"packet.capture_file" (Packet). Nested `io::Error` carrying a
`compression::Error` re-classifies through it (:180-191). `context()` gives
`Coordinate::SourceFrame` only for Predicate. `causes()` wraps BoundaryError
chains (:250-255). New typed split errors can wrap `Error` and defer
classification (pattern: `MergeSource { source: Box<Self> }` :131-137).

### Timestamps incl. absent

`Frame.timestamp: Option<SystemTime>` (frame.rs:82). Classic pcap always
produces `Some` (seconds+fraction → UNIX_EPOCH offset; invalid fraction rejected
at classic/decode.rs:95-100). PCAPNG EPB/obsolete: `timestamp_from_ticks` with
the interface's `if_tsresol` (Decimal/Binary exponent) + `if_tsoffset`
(packet.rs:123-127, wire/timestamp.rs:24-74). SPB carries NO timestamp →
`try_with_optional_timestamp(None, ...)` (packet.rs:209). So a "packet record"
can have `timestamp: None`; neither `rewrite` nor `select` requires one
(timestamps never inspected — raw bytes copied). Reader permits regressing
timestamps (only `merge` rejects them, merge.rs:316).

## 3. `capture_file::select` — the byte-level oracle (`capture_file/rewrite.rs`)

```rust
pub fn rewrite<R: Read, W: Write>(
    reader: &mut Reader<R>, output: W, limits: Limits,
) -> Result<(W, RewriteReport), Error>                    // :13

pub fn select<R: Read, W: Write, F>(
    reader: &mut Reader<R>, output: W, limits: Limits, mut predicate: F,
) -> Result<(W, SelectionReport), Error>
where F: FnMut(u64, &Frame) -> Result<bool, BoundaryError>  // :42
```

Both delegate to `copy_records` (:56-110), the whole algorithm:

```rust
let mut budget = Budget::new(limits)?;                     // zero-limit check
// report.format = reader.format()
if selecting && reader.format() == Format::PcapNg {
    super::pcapng::write_selected_section(&mut output, reader.header().raw())?;
} else {
    output.write_all(reader.header().raw()).map_err(Error::from)?;
}
while let Some(record) = reader.next_record()? {
    if let Some(frame) = record.frame.as_ref() {
        budget.charge(frame.captured_length())?;           // ALL input packets
        (report.frames_read, report.captured_bytes_read) = //   charged, even
            (budget.frames(), budget.captured_bytes());    //   unselected
        if !predicate(report.frames_read, frame)? { continue; }
        // frames_selected/captured_bytes_selected += 1 / captured_length
    } else {
        report.metadata_records += 1;                      // saturating_add
    }
    if selecting && matches!(record.kind,
            RecordKind::Metadata(MetadataBlockKind::Section(_))) {
        super::pcapng::write_selected_section(&mut output, record.raw_bytes())?;
    } else {
        output.write_all(record.raw_bytes()).map_err(Error::from)?;
    }
}
output.flush().map_err(Error::from)?;
report.interfaces = reader.interfaces().len();
```

Key facts split must replicate:
- ALL metadata records are copied verbatim (`raw_bytes()`), including SHBs of
  later sections, IDBs for unused interfaces, ISB/NRB/custom/unknown blocks,
  AND metadata appearing after the last packet — there is no "before first
  packet" placement logic; order is source order.
- The ONLY byte modification: `write_selected_section` (see below) rewrites
  SHB section length to unknown — applied to the initial header when selecting
  AND to every later `MetadataBlockKind::Section` record. `rewrite` (non-
  selecting) does NOT patch: copies even SHBs verbatim.
- Predicate gets the ORIGINAL one-based frame number = `frames_read`.
- Every input packet charges the stream budget even when rejected; per spec,
  split's `input` Limits account the same way.
- Output may be partial on error; `flush` at the end.
- `SelectionReport` (model.rs:459-468): `format, frames_read, frames_selected,
  captured_bytes_read, captured_bytes_selected, interfaces, metadata_records`
  (metadata count excludes the initial header — spec's split report counts it
  IN: "initial header plus retained non-packet records").
- `RewriteReport` (model.rs:471-477): `format, frames, captured_bytes,
  interfaces, metadata_records`.

For split, the equivalent of "predicate selects range [a,b]" must instead be
driven by the metadata-anchor algorithm in spec §5 — select itself can't be
reused because it can only drop packet records, never relocate metadata, and
its predicate sees frames in a single forward pass while split interleaves
cached metadata replay.

### `write_selected_section` (private) — pcapng/section.rs:180-188

```rust
/// Copies a reader-validated section header with an unknown section length.
// validated section headers contain at least 28 bytes
pub(in crate::capture_file) fn write_selected_section(
    output: &mut impl std::io::Write,
    raw: &[u8],
) -> Result<(), Error> {
    output.write_all(&raw[..16])?;
    output.write_all(&[0xff; 8])?;
    output.write_all(&raw[24..])?;
    Ok(())
}
```

Byte-identical SHB except bytes 16..24 (the i64 section-length field) become
`0xff*8` = -1 = "unknown". Works for both endiannesses since the field is raw.
`pub(in crate::capture_file)` → directly callable from `capture_file/split.rs`
via `super::pcapng::write_selected_section` (re-exported through
pcapng.rs:10). For classic pcap headers write `header().raw()` verbatim.

### Raw accessors

```rust
impl CaptureHeader {
    pub fn format(&self) -> Format;              // model.rs:371
    pub(super) fn raw(&self) -> &[u8];           // model.rs:378 — pub(super)!
}
impl CaptureRecord {
    pub fn format(&self) -> Format;              // model.rs:448
    pub fn raw_bytes(&self) -> &[u8];            // model.rs:452 — public
}
```

`CaptureHeader::raw()` is `pub(super)` — accessible within `capture_file`
(incl. a split submodule) but NOT from the CLI; spec's plan must therefore
retain header bytes in `Plan` internally. `raw` fields: `PcapHeader.raw` /
`Section.raw` are `pub(super) Bytes` (model.rs:347, :360).

`Section` (model.rs:352-361): `index: u64, endianness, major, minor,
length: Option<u64>, options: Vec<PcapNgOption>, raw`. `length` is `None` for
the -1 sentinel (`u64::try_from(section_length).ok()`, section.rs:154);
declared lengths are enforced (`remaining_in_section`, decode.rs:172-184,
`commit_block`, `SectionEndedEarly`/`SectionHeaderBeforeBoundary`/
`BlockCrossesSectionBoundary` errors).

### Record model (model.rs)

```rust
pub enum CaptureHeader { Pcap(PcapHeader), PcapNg(Section) }        // :365
pub struct CaptureRecord {                                          // :440
    pub kind: RecordKind,
    pub frame: Option<Frame>,          // physical packet iff Some
    pub(super) format: Format,
    pub(super) raw: Bytes,             // whole record incl. header+footer
}
pub enum RecordKind {                                                 // :428
    Packet { block: PacketBlockKind, section: Option<u64>,
             interface_id: Option<u32>, options: Vec<PcapNgOption> },
    Metadata(MetadataBlockKind),
}
pub enum PacketBlockKind { Classic, Enhanced, Simple, Obsolete }      // :389
pub enum MetadataBlockKind {                                          // :399
    Section(Section),
    InterfaceDescription { section, local_id, global_id, interface, options },
    NameResolution { section },
    InterfaceStatistics { section, interface_id },
    Custom { section, block_type },
    Unknown { section, block_type },
}
```

Frame counting uses `record.frame.is_some()`, NOT `RecordKind::Packet` —
they coincide today (decode/record.rs:95-104 always sets both), but the
`frame` check is what `copy_records` uses.

## 4. The Writer — why it's the wrong mechanism (`capture_file/writer.rs`)

`Writer<W: Write>` (:137) generates NEW captures from `Frame`s:
`Writer::new/pcap/pcap_with_options/pcapng/pcapng_with_options`,
`add_interface*`, `write_frame`, `encoded_frame_size` (dry-run preview),
`frames_written`/`captured_bytes_written`, `flush`, `into_inner`.

What it emits: pcap → `write_pcap_header` (generated 24-byte header from
endianness+precision+snaplen+linktype; classic/encode.rs:12) + 16-byte record
headers per frame. pcapng → `write_section_header` (a fixed 28-byte SHB, v1.0,
length -1, NO options — pcapng/encode.rs:43) + generated IDBs
(`write_interface_description`, generated tsresol/tsoffset options) + ONLY
Enhanced Packet Blocks (`write_enhanced_packet`). It therefore CANNOT:
- preserve SHB options, non-1.0 section versions, multi-section captures
  (WriterState is single-section), IDB options other than generated ones,
  EPB options other than epb_flags/direction, Simple/obsolete packet blocks,
  classic pcap global-header fields like the high-bit FCS network word
  (rejected: `MetadataNotRepresentable`), or any unknown/custom metadata;
- represent absent timestamps (`TimestampUnavailable`, writer.rs:480,618);
- copy raw records at all — it re-encodes from the normalized `Frame`.

Split must bypass Writer entirely: write `raw()`/`raw_bytes()` +
`write_selected_section` to the sink, exactly like `copy_records` does.
Writer also owns a `Budget` and sticky I/O failure state (`OutputFailure`,
:109-130) that would double-charge limits.

`map_frames`/`merge` are also wrong-shaped (normalize to one PCAPNG section,
Writer-based); `rewrite`/`select` in rewrite.rs are the correct copy
mechanism, and spec mandates reusing their raw approach rather than calling
`select` per part (that would rescan input per part and misplace trailing
metadata).

## 5. Record classification (which blocks are "packets")

`packet_block_kind(block_type)` (decode/framing.rs:27-34):
- `0x0000_0006` EPB → `Enhanced`; `0x0000_0002` → `Obsolete`;
  `0x0000_0003` SPB → `Simple`; everything else → metadata.

Metadata dispatch (decode/record.rs:107-145): `0x0000_0001` IDB →
`InterfaceDescription` (parsed, registered globally — decode_interface
:43-71); `0x0000_0004` NRB → `NameResolution`; `0x0000_0005` ISB →
`InterfaceStatistics` (interface_id validated against section table,
:117-134); `0x0000_0bad`/`0x4000_0bad` custom blocks → `Custom`; all other
block types → `Unknown` — raw preserved either way. SHB `0x0a0d0d0a` is
intercepted before framing (decode.rs:186-188) → `read_section_record` →
`MetadataBlockKind::Section` with full section validation
(`SectionHeaderBeforeBoundary` if prior section unfinished).

Preservation: EVERY block's raw bytes (block header + body + trailing length)
are retained in `FramedBlock.raw` (framing.rs:83,93-103) — unknown blocks and
unknown options survive untouched since validation is structural (length
footer match, size cap, option well-formedness for parsed blocks). Options
are strictly validated when parsed (`visit_options`, options.rs:14-87:
eoo must have length 0, only zero bytes after eoo) but raw block bytes are
what get written, so even exotic option sets round-trip.

Mixed endianness: `PcapNgState.endianness` updates on each SHB
(`start_section`, decode.rs:46-71); blocks are decoded in their section's
endianness; `MetadataBlockKind::*{ section }` carries the section index, and
`interface_base` accumulates global IDs across sections — but all of this is
only decode-time metadata; the raw bytes split copies are endian-agnostic.

Ordering guarantees for split's anchor model: `next_record()` yields records
in exact source order; "after_frame anchor = number of packet records seen so
far" is computable in one pass. ISB/IDB validation means metadata records are
always *validated* even when their semantics are unused.

## 6. CLI input path (`packetcraftr-cli/src/input.rs`)

```rust
pub(crate) fn snapshot_capture<R: Read>(
    input: &mut Reader<R>,
    bounds: CaptureReaderBoundsArgs,
    limits: core::capture_file::Limits,
) -> Result<Reader<File>, CliError>                       // input.rs:347-382
```

- `tempfile::tempfile()` anonymous spool; `capture_file::rewrite` copies the
  ENTIRE decoded source into `BufWriter::with_capacity(64*1024, snapshot)`
  under `limits` (the aggregate frame/byte ceilings — one extra validation
  pass); `into_inner` flushes; `Seek::rewind`; opens `Reader::with_limits`
  with `ReaderLimits { max_size: bounds.max_frame_bytes,
  max_interfaces_per_section: bounds.max_interfaces, ..Default::default() }`;
  attaches `.with_cancellation(...)` + invocation deadline via
  `crate::invocation::reader` (invocation.rs:87-94).
- Returns `Reader<File>` — `File: Read + Seek`, satisfying split's
  `R: Read + Seek` bound. Used by `export` (commands/export.rs:68-77) which
  then calls `reader.rewind()` before `select` — the exact two-pass
  precedent split follows.
- `open_capture(path, bounds) -> Reader<Box<dyn Read>>` (:321): `capture_source`
  (:310-319) rejects terminal stdin via `require_redirected_stdin`
  (`cli.input_source`, Usage; `-` = stdin), then `capture_reader` (:384-413)
  wraps in `compression::Input::new(source, compression::Limits {
  max_decoded_bytes, max_encoded_bytes, ..Default::default() })` —
  gzip (`1f 8b`, MultiGzDecoder) and Zstd (`28 b5 2f fd` or skippable-frame
  magic) detected by magic, bounded decoded+encoded bytes
  (compression.rs:147-259). Errors map through `CliError::classified`.
- `validate_capture_stream_limits(OfflineCaptureLimitsArgs)` (:450-487)
  enforces non-zero max_frames/max_bytes/max_frame_bytes/max_interfaces and
  `max_frame_bytes <= max_bytes` → `cli.capture_limit` Usage.
- `CaptureReaderBoundsArgs` (command_options/offline_limits.rs:65-93):
  `max_encoded_bytes`, `max_decoded_bytes` (default `DEFAULT_STREAM_BYTES`),
  `max_frame_bytes` (`DEFAULT_SIZE_LIMIT`), `max_interfaces` (4096); flattened
  inside `OfflineCaptureLimitsArgs` (:50-60 adds `max_frames`, `max_bytes`).
- `open_capture_hashed` (:330-336) shows the SHA-256 `Fingerprint` wrapper
  pattern (`input/fingerprint.rs`: `Hashed<R: Read>` feeding `Sha256` per
  read; `sha2::Digest` cloneable mid-stream) — relevant to spec's source
  digest requirement, though split hashes raw records inside core instead.

## 7. CLI saved-capture compression writers

The building blocks (core `capture_file/compression.rs:261-320`):

```rust
pub struct Output<W: Write> { encoder, format }     // :268
Output::new(destination, Format::{None,Gzip,Zstd})  // :273
// Gzip = flate2::write::GzEncoder::new(dst, Compression::default())
// Zstd = zstd::stream::write::Encoder::new(dst, 3)
pub fn finish(self) -> Result<W, Error>             // :288 — finalizes
//   checksums/trailers via encoder .finish(), then flush()es inner
```

`compression::Error::Io { format, source }` → "io.capture_compression" (Io,
:94-98); byte/window limits → "packet.capture_compression_limit" (Packet).
`Output` implements `Write` pass-through (:305-319). Spec's below-compressor
encoded-byte counter therefore wraps the staged `File` BEFORE handing it to
`Output::new` — i.e. `Output::new(counted_file)` — so it counts encoded bytes
including trailer bytes emitted by `finish`, which calls through the same
`Write` impl.

Existing saved-capture patterns:

- `commands/merge.rs:44-89`: `StagedFile::stage(&args.write)` →
  `BufWriter::with_capacity(64*1024, staged.as_file_mut())` →
  `args.compression.for_file().writer(inner)` (= `Output::new`) → core op →
  `writer.into_inner().finish()` → `staged.sync()` → `cancellation::check()`
  → `staged.persist()` → then report. 64 KiB buffer is the convention.
- `commands/rewrite.rs:132-149,179-184`: same layering, `dry_run` uses
  `io::sink()`; explicit `BufWriter` 64 KiB.
- `commands/export.rs:78-90`: `select` writes through
  `compression.writer(BufWriter::with_capacity(64*1024, staged.as_file_mut()))`,
  `.finish()`, then builds report BEFORE `sync`+`persist` (comment at :91 —
  "construct all fallible report fields before publishing"), matching spec's
  publish-after-report ordering.
- `commands/capture/files.rs:137-156`: existing `Counted<W>` wrapper —
  `checked_add` byte counter returning `io::Error::other("capture byte
  counter overflow")` on overflow, counting `written` not `bytes.len()`
  (precedes spec's partial-write counting rule); note the bug-shaped double
  count there (adds `bytes.len()` pre-check then `written`) — spec wants
  only actual-written charged, see spec line 178-180. Also `files.rs:366-369`
  shows `Counted { inner: compression::Output::new(handle, fmt), bytes: 0 }`
  — i.e. counter ABOVE compressor counting decoded bytes; spec wants the
  opposite layer (below compressor, counting encoded).
- `staged_output.rs`: `StagedFile::stage(destination)` refuses existing
  destinations incl. dangling symlinks up front (:30-56); `as_file_mut`,
  `sync()` (cancellation-checked `sync_all`), `persist()` =
  `persist_noclobber` after `cancellation::check()` (:79-88); all errors →
  "io.output_file" (Io) via `output()` helper (:91-100) retaining source
  chain. Spec adds `seal()`/`SealedFile`/`persist_noclobber`-retained-path
  here.
- `commands/follow/write.rs:114-171`: the ordered publish+rollback logic the
  spec wants extracted into `staged_output.rs` — `publish_with(sync, remove)`
  syncs ALL staged files first, persists in order, tracks `published`
  destinations, on failure removes published ones in order and appends
  cleanup failures via `CliError::with_secondary`.
- stdout-side compression: `Compression::writer(stdout.lock())` +
  `finish_compressed_output` (commands/read.rs:137-162); error mapping
  helpers `stream_capture_error`/`stdout_error`/`capture_io_error` in
  `rendering/capture_file.rs:85-137` ("io.stdout", "io.capture_file").
- `command_options/compression.rs`: `CompressionArgs<D: Destination>`
  (`--compression none|gzip|zstd`, default None), `.for_file()` →
  `Compression` for saved files; marker impls `CaptureStdout`, `SavedPcapNg`
  (compression.rs:84-97), `SavedCapture` (export/arguments.rs:47-52). Split
  needs its own marker (e.g. "Compression of each saved part").
- `MaxDurationArgs<R: RunTime>` (command_options/duration.rs:42-52):
  `value_parser = clap::value_parser!(u64).range(R::PARSED)`; spec's
  `SplitRunTime` sets `PARSED = 1..=3_600_000` so out-of-range fails as
  ordinary `cli.error` — precedent `Bounded` fixture :229-251. Shared
  presets via `.resources()` (:88-90, `Milliseconds @ Operation
  preset(30000, 300000)`).
- `Spec` trait (commands.rs:77-109): `OFFLINE`, `CANCELLATION`, `run_time`,
  `resources`, `run`; register `Split(split::arguments::Args) = "split"` in
  the `commands!` macro (:228-315) — gives `Command::Split` for the output
  family contract; `emit_aggregate`/`stream.complete` for JSON/NDJSON;
  `resources::declare!` stages: `ResultRetention`, `IndexedMetadata`,
  `PhysicalInput`, `Operation`, `ActiveState` (resources.rs:65-89).

## 8. Tests and fixtures

`crates/packetcraftr-core/tests/`:

- `pcap_fidelity_contracts.rs` — THE fixture source for split tests (no
  shared module; helpers are file-local): `u16_bytes/u32_bytes/i64_bytes`
  (:15-34), `option`/`end_options` (:36-51), `block(endianness,type,body)`
  (:53-62), `section` (:64-77, comment option + BOM), `idb` (:79-100, rich
  options incl. unknown 0x7777 + tsresol), `epb` (:102-120, options incl.
  unknown), `obsolete_packet` (:122-135), `simple_packet` (:137-142),
  `metadata_block` (:144-148), `adversarial_pcapng()` (:150-181: LE section,
  IDB, EPB, SPB, obsolete PB, NRB, ISB, both custom blocks, unknown
  0x12345678, then BE section + IDB + EPB — covers SP03's matrix), `classic`
  (:183-200, arbitrary `network` word incl. FCS high bits, both
  endiannesses; nanosecond magic patch shown :530-535).
  `selection_preserves_raw_packets_and_metadata_across_sections` (:443-485)
  is the oracle-check template: builds `expected` by concatenating header +
  `record.raw_bytes()` of selected packets + ALL metadata. Section-length
  patching verified at :488-522 (finite lengths → -1 across empty/nonempty
  sections, both endians). Proptest at :563-594 generates multi-section
  captures + selection masks — extend for split/part equivalence.
- `pcap_edge_contracts.rs` — second fixture set: `section_header` with
  arbitrary major/minor/length (:40-59), `interface_block` (:61-70),
  `enhanced_packet_block` (:72-102), `obsolete_packet_block` (:104-128),
  `simple_packet_block` (:130-141), `empty_metadata_block` (:143-149),
  `pcapng_stream` (:151-157). Edge coverage incl. `Error::EmptyInput` (:506),
  truncated blocks, version rejection, section boundary violations.
- `pcap_rewrite_contracts.rs` — `FailAfter`/`FlushFailure` writers (:16-36,
  :195-204) for sink-failure simulation; classification checks; predicate
  failure propagation through `Error::Predicate` w/ `Coordinate::SourceFrame`.
- `capture_limit_contracts.rs` — zero-ceiling sweep across every consumer
  (:46-119 — split must join this pattern), `Budget` charge semantics,
  `MergeLimits::validate` precedent (:153-173).
- `capture_merge_contracts.rs`, `capture_compression_contracts.rs` (truncated
  gzip/zstd handling), `pcap_contracts.rs`.
- `common/pcap.rs` — `frame_at`, `pcap_bytes(PcapOptions, frames)` writer-
  built pcap fixtures.
- `reader.rs` in-module tests (:314-397) — cancellation mid-stream kills
  rewrite AND select, cancelled reader consumes nothing (check positions via
  `get_ref().position()`).

Fuzz: `fuzz/fuzz_targets/capture_transform.rs` is the transformation target
to extend — it already asserts `rewrite == input` byte-exact (:20-24),
gzip/zstd round-trip (:25-41), and `select` parity (:74-84); a split↔select
equivalence check fits the same shape. Helpers: `composed_support::reader`
(builds pcap from frames, :103-109). `fuzz/Cargo.toml:117-121` registers it;
corpora live in `fuzz/corpora/`.

## 9. sha2 in workspace

`Cargo.toml:52`: `sha2 = { version = "0.11.0", default-features = false }`
workspace dep; already enabled in `crates/packetcraftr-core/Cargo.toml:28`
and `crates/packetcraftr-cli/Cargo.toml:40`. Usage: `sha2::{Digest, Sha256}`
— core uses `Sha256::digest(...)` for JA4
(protocol/application/tls/model/fingerprint.rs:37,245-247); CLI
`input/fingerprint.rs:6,16` uses incremental `digest.update(...)`. For
split's plan-pass hashing: `Sha256::new()` + `update(header.raw())` /
`update(record.raw_bytes())` per record, `finalize` and compare in `write`'s
second pass — or retain the digest (`Sha256` is `Clone`) and re-hash the
second pass records the same way.

## Implementation notes for the implementer (non-authoritative)

- `Options`/`Limits`/`Plan`/`Report`/`Part`/`Sink`/`Error` for split: put in
  `capture_file/split.rs`; add `mod split;` + `pub use split::{...}` in
  `capture_file.rs` beside the merge re-export (:31). `split::Limits.input`
  is the existing `capture_file::Limits` (model.rs:26).
- `plan`: call `reader.rewind()` (spec: "rewinds ... including when the
  caller has previously consumed records"), then drive `next_record()` to
  EOF; anchor metadata via packet count; charge `Budget` over the
  `input: Limits`; hash header+records with Sha256; compute `parts =
  max(1, frames/N + (frames%N != 0))` checked; preflight decoded size =
  `packet_record_bytes + parts*(header_bytes + metadata_record_bytes)`.
- `write`: `rewind()` once; per part [a,b]: `sink.begin(index,
  reader.format())`; header via `write_selected_section` (pcapng) or raw
  (pcap); metadata anchor `< a` first; for each selected packet j write
  `raw_bytes()` then metadata anchored at j when `j < b`; after b append all
  remaining; `sink.finish(&Part)`; re-hash every second-pass record incl.
  skipped metadata; digest mismatch → the spec's source-changed error.
- Interruption: expose `check_interrupted` as `pub(super)` (reader.rs:175)
  and call it before/after each `sink.*` callback and between cached
  metadata writes; `next_record` alone can't cover sink-only stretches.
- `Sink` errors are `crate::error::BoundaryError` (error/boundary.rs:
  `from_error`, `with_source`, `as_causes`) — wrap in the split Error like
  `Error::Predicate` does (error.rs:111-116, context+causes plumbing).
- Rejected alternative confirmed: do NOT call `select` per part (rescans
  input per part — spec line 134-136 forbids; also can't relocate trailing
  metadata), and do NOT use `Writer` (§4).
