// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `split`: divides a capture into faithful bounded same-format parts.
//!
//! The command plans against a seekable input snapshot, checks every fixed
//! `part-NNNNNN` destination before generating bytes, generates one staged
//! compressed part at a time under a shared encoded-byte ceiling, prepares
//! the complete report before any commit, and publishes the sealed parts in
//! index order with invocation-scoped rollback.

pub(super) mod arguments;
mod rendering;

use std::cell::RefCell;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use packetcraftr_core::capture_file::{self, compression, split};
use packetcraftr_core::error::{BoundaryError, Kind};

use self::arguments::Args;
use crate::command_options::Compression;
use crate::errors::CliError;
use crate::output::{self, contract::ToolFormat};
use crate::rendering::StreamEncoder;
use crate::staged_output::{self, SealedFile, StagedFile};

impl super::Spec for Args {
    type Format = ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.duration)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_files: Count @ ResultRetention preset(64, 256),
            max_split_metadata_records: Count @ IndexedMetadata preset(1024, 4096),
            max_split_metadata_bytes: Bytes @ IndexedMetadata preset(2097152, 16777216),
            max_split_output_bytes: Bytes @ Operation preset(33554432, 536870912),
        ]);
        self.limits.resources(settings);
        self.duration.resources(settings);
    }

    fn run(
        self,
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(crate) fn run(args: Args, format: ToolFormat, stream: &StreamEncoder) -> Result<(), CliError> {
    crate::input::validate_capture_stream_limits(args.limits)?;
    let limits = split::Limits {
        input: capture_file::Limits {
            max_frames: args.limits.max_frames,
            max_bytes: args.limits.max_bytes,
        },
        max_files: args.max_files,
        max_metadata_records: args.max_split_metadata_records,
        max_metadata_bytes: args.max_split_metadata_bytes,
        max_output_bytes: args.max_split_output_bytes,
    };
    limits.validate().map_err(CliError::classified)?;
    if args.frames_per_file == 0 {
        return Err(CliError::classified(split::Error::InvalidOption {
            field: "frames_per_file",
            value: 0,
            reason: "must be non-zero",
        }));
    }
    check_directory(&args.write_dir)?;
    let compression = args.compression.for_file();

    let mut source = crate::input::open_capture(&args.path, args.limits.reader)?;
    let mut reader = crate::input::snapshot_capture(&mut source, args.limits.reader, limits.input)?;

    let plan = split::plan(
        &mut reader,
        split::Options {
            frames_per_file: args.frames_per_file,
            limits,
        },
    )
    .map_err(CliError::classified)?;

    // Fixed basenames come from the detected container format and the part
    // index alone; neither the source filename nor its metadata contributes.
    let extension = output_extension(plan.report().format, compression);
    let destinations = plan
        .report()
        .parts
        .iter()
        .map(|part| {
            args.write_dir
                .join(format!("part-{:06}.{extension}", part.index))
        })
        .collect::<Vec<_>>();
    check_destinations(&destinations)?;

    let mut sink = Parts::new(destinations, compression, limits.max_output_bytes);
    let report = split::write(&mut reader, plan, &mut sink).map_err(CliError::classified)?;
    let Generated { sealed, saved } = sink.generated();

    // The complete report is built, converted, and prepared before the first
    // commit; resource diagnostics are sampled inside the prepared envelope.
    let report = output::split::Report::try_from((
        args.write_dir.display().to_string(),
        compression.as_str(),
        report,
        saved,
    ))
    .map_err(CliError::from)?;
    let files = sealed
        .into_iter()
        .map(|file| (file, ()))
        .collect::<Vec<_>>();

    match format {
        ToolFormat::Json => {
            let prepared = crate::rendering::prepare_aggregate(
                output::contract::Command::Split,
                report,
                Vec::new(),
            )?;
            publish(files)?;
            prepared.publish()
        }
        ToolFormat::Ndjson => {
            let prepared = stream
                .prepare_complete(report, Vec::new())
                .map_err(CliError::from)?;
            publish(files)?;
            stream
                .publish_prepared_complete(prepared)
                .map_err(CliError::from)
        }
        ToolFormat::Text => {
            publish(files)?;
            rendering::render_text(&report)
        }
    }
}

/// Commits the sealed parts in index order, rolling back destinations this
/// invocation already created when a commit or its interruption check fails.
fn publish(files: Vec<(SealedFile, ())>) -> Result<(), CliError> {
    staged_output::publish_ordered(files, "split", SealedFile::persist, |path| {
        std::fs::remove_file(path)
    })?;
    Ok(())
}

/// `--write-dir` must already exist and be a directory; split never creates
/// or removes it.
fn check_directory(directory: &Path) -> Result<(), CliError> {
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(staged_output::invalid_directory(directory)),
        Err(source) => Err(staged_output::output("inspect", directory, source)),
    }
}

/// Every predicted destination must be absent before generation begins, so a
/// collision fails without consuming output budgets; each name is rechecked
/// no-clobber at commit. An input living at a predicted name is refused the
/// same way, because a file input at that path necessarily exists.
fn check_destinations(destinations: &[PathBuf]) -> Result<(), CliError> {
    for destination in destinations {
        staged_output::check_absent(destination)?;
    }
    Ok(())
}

fn output_extension(format: capture_file::Format, compression: Compression) -> &'static str {
    match (format, compression) {
        (capture_file::Format::Pcap, Compression::None) => "pcap",
        (capture_file::Format::PcapNg, Compression::None) => "pcapng",
        (capture_file::Format::Pcap, Compression::Gzip) => "pcap.gz",
        (capture_file::Format::PcapNg, Compression::Gzip) => "pcapng.gz",
        (capture_file::Format::Pcap, Compression::Zstd) => "pcap.zst",
        (capture_file::Format::PcapNg, Compression::Zstd) => "pcapng.zst",
    }
}

/// What a finished split leaves behind: the sealed staged parts and each
/// part's saved-file facts for the report.
struct Generated {
    sealed: Vec<SealedFile>,
    saved: Vec<output::split::File>,
}

/// Generates one staged compressed part at a time. Each `begin` stages the
/// part's fixed destination, wraps it in the shared encoded-byte counter, a
/// 64 KiB buffer, and the compressor — the only output descriptor and codec
/// open at once — and `finish` finalizes the codec, closes the file, and
/// seals it before the next part begins. Sealed paths and report rows stay
/// finite under the `max_files` bound the plan enforced.
struct Parts {
    compression: Compression,
    destinations: Vec<PathBuf>,
    encoded: Rc<RefCell<SharedEncoded>>,
    active: Option<ActivePart>,
    sealed: Vec<SealedFile>,
    saved: Vec<output::split::File>,
}

/// The one part currently open: its compressor and fixed destination.
struct ActivePart {
    output: compression::Output<io::BufWriter<Encoded>>,
    destination: PathBuf,
}

/// The shared encoded-byte state below every part's compressor: one total,
/// one ceiling, and the typed refusal latched before an `io::Error` so a
/// codec's wrapping cannot reclassify the policy refusal.
#[derive(Debug)]
struct SharedEncoded {
    total: u64,
    limit: u64,
    refusal: Option<CliError>,
}

impl Parts {
    fn new(destinations: Vec<PathBuf>, compression: Compression, limit: u64) -> Self {
        Self {
            compression,
            destinations,
            encoded: Rc::new(RefCell::new(SharedEncoded {
                total: 0,
                limit,
                refusal: None,
            })),
            active: None,
            sealed: Vec::new(),
            saved: Vec::new(),
        }
    }

    /// Consumes the finished run into its sealed artifacts and saved-file
    /// facts; called only after a successful split, when no part is open.
    fn generated(self) -> Generated {
        debug_assert!(self.active.is_none(), "finished splits leave no open part");
        Generated {
            sealed: self.sealed,
            saved: self.saved,
        }
    }

    /// The `cli.capture_split` boundary error for a sink callback arriving
    /// out of order; the sink contract is one open part at a time.
    fn incoherent(detail: &'static str) -> BoundaryError {
        CliError::new(Kind::Internal, detail).into_boundary_error()
    }
}

impl split::Sink for Parts {
    fn begin(&mut self, index: u64, _format: capture_file::Format) -> Result<(), BoundaryError> {
        if self.active.is_some() {
            return Err(Self::incoherent(
                "capture split began a part before sealing the previous one",
            ));
        }
        let destination = usize::try_from(index)
            .ok()
            .and_then(|index| index.checked_sub(1))
            .and_then(|index| self.destinations.get(index))
            .ok_or_else(|| Self::incoherent("capture split part index has no destination"))?;
        let staged = StagedFile::stage(destination).map_err(CliError::into_boundary_error)?;
        let output = self
            .compression
            .writer(io::BufWriter::with_capacity(
                64 * 1024,
                Encoded {
                    staged,
                    written: 0,
                    shared: Rc::clone(&self.encoded),
                },
            ))
            .map_err(CliError::into_boundary_error)?;
        self.active = Some(ActivePart {
            output,
            destination: destination.clone(),
        });
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), BoundaryError> {
        let encoded = Rc::clone(&self.encoded);
        let Some(active) = &mut self.active else {
            return Err(Self::incoherent("capture split wrote before begin"));
        };
        active
            .output
            .write_all(bytes)
            .map_err(|source| io_failure(&encoded, "write", &active.destination, source))
    }

    fn finish(&mut self, part: &split::Part) -> Result<(), BoundaryError> {
        let encoded = Rc::clone(&self.encoded);
        let Some(active) = self.active.take() else {
            return Err(Self::incoherent("capture split finished before begin"));
        };
        let buffered = active
            .output
            .finish()
            .map_err(|source| codec_failure(&encoded, &active.destination, source))?;
        let counted = buffered.into_inner().map_err(|error| {
            io_failure(&encoded, "flush", &active.destination, error.into_error())
        })?;
        let (sealed, encoded_bytes) = counted.seal().map_err(CliError::into_boundary_error)?;
        let name = active
            .destination
            .file_name()
            .expect("split destinations always name a file")
            .to_owned()
            .into_string()
            .expect("split destination names are ASCII");
        self.saved.push(output::split::File {
            index: part.index,
            name,
            encoded_bytes,
        });
        self.sealed.push(sealed);
        Ok(())
    }
}

/// A staged file charging every underlying write — including the compressor
/// trailer bytes `Output::finish` emits — against the shared encoded ceiling.
/// The counter advances by the actual written count; a refused write latches
/// the typed `policy.capture_split_limit` refusal before returning `io::Error`.
struct Encoded {
    staged: StagedFile,
    written: u64,
    shared: Rc<RefCell<SharedEncoded>>,
}

impl Encoded {
    /// Refuses `additional` bytes when the shared total plus that many bytes
    /// would cross the ceiling or overflow, latching the typed refusal.
    fn admit(&self, additional: u64) -> io::Result<()> {
        let mut shared = self.shared.borrow_mut();
        if shared.refusal.is_some() {
            return Err(refused());
        }
        match shared.total.checked_add(additional) {
            Some(total) if total <= shared.limit => Ok(()),
            attempted => {
                shared.refusal = Some(refusal(attempted.unwrap_or(u64::MAX), shared.limit));
                Err(refused())
            }
        }
    }

    /// Syncs, closes, and seals the staged part, returning it with its exact
    /// encoded length. The measured file length must agree with the counted
    /// bytes: divergence is an internal invariant failure, not an I/O one.
    fn seal(self) -> Result<(SealedFile, u64), CliError> {
        let Self {
            mut staged,
            written,
            ..
        } = self;
        let destination = staged.destination().to_owned();
        let measured = staged
            .as_file_mut()
            .metadata()
            .map_err(|source| staged_output::output("measure", &destination, source))?
            .len();
        if measured != written {
            return Err(CliError::new(
                Kind::Internal,
                format!(
                    "encoded split part {} counted {written} bytes but measures {measured}",
                    destination.display()
                ),
            ));
        }
        staged.seal().map(|sealed| (sealed, written))
    }
}

impl Write for Encoded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Refuse the whole request when its full length would cross the
        // ceiling, then charge only what the file actually accepted.
        self.admit(u64::try_from(bytes.len()).unwrap_or(u64::MAX))?;
        let written = self.staged.as_file_mut().write(bytes)?;
        self.written += u64::try_from(written).unwrap_or(u64::MAX);
        let mut shared = self.shared.borrow_mut();
        // `written <= bytes.len()`, admitted above, so this charge is never
        // worse than the admitted one; only an overflow at u64 itself trips,
        // which is the same encoded-output refusal.
        match shared
            .total
            .checked_add(u64::try_from(written).unwrap_or(u64::MAX))
        {
            Some(total) if total <= shared.limit => {
                shared.total = total;
                Ok(written)
            }
            attempted => {
                shared.refusal = Some(refusal(attempted.unwrap_or(u64::MAX), shared.limit));
                Err(refused())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.staged.as_file_mut().flush()
    }
}

/// The typed refusal stored in the shared counter before the `io::Error` a
/// codec sees, keeping the policy classification authoritative.
fn refusal(attempted: u64, limit: u64) -> CliError {
    CliError::classified(split::Error::LimitExceeded {
        bound: "max_output_bytes",
        attempted,
        limit,
    })
}

/// The opaque I/O failure a compressor observes for a refused write; the
/// latched typed refusal replaces it on the error path.
fn refused() -> io::Error {
    io::Error::other("encoded split output exceeds --max-split-output-bytes")
}

/// The latched shared encoded-byte refusal, or the I/O failure with its
/// source chain under `io.output_file`.
fn io_failure(
    encoded: &Rc<RefCell<SharedEncoded>>,
    action: &'static str,
    destination: &Path,
    source: io::Error,
) -> BoundaryError {
    if let Some(refusal) = encoded.borrow_mut().refusal.take() {
        return refusal.into_boundary_error();
    }
    staged_output::output(action, destination, source).into_boundary_error()
}

/// The latched shared encoded-byte refusal, or the compressor finalization
/// failure with its compression/I/O source chain under `io.output_file`.
fn codec_failure(
    encoded: &Rc<RefCell<SharedEncoded>>,
    destination: &Path,
    source: compression::Error,
) -> BoundaryError {
    if let Some(refusal) = encoded.borrow_mut().refusal.take() {
        return refusal.into_boundary_error();
    }
    staged_output::output("finalize", destination, source).into_boundary_error()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use packetcraftr_core::capture_file::{Reader, Writer};
    use packetcraftr_core::error::Classified;
    use packetcraftr_core::frame::{Frame, LinkType};
    use std::io::Cursor;

    /// The real argument surface, including the flattened private groups.
    #[derive(Debug, Parser)]
    struct Fixture {
        #[command(flatten)]
        args: Args,
    }

    fn parse(argv: &[&str]) -> Args {
        Fixture::try_parse_from(std::iter::once("split").chain(argv.iter().copied()))
            .map(|fixture| fixture.args)
            .expect("arguments parse")
    }

    /// A valid little-endian PCAPNG holding `frames` distinct 64-byte packets.
    fn pcapng(frames: u64) -> Vec<u8> {
        use std::time::{Duration, UNIX_EPOCH};
        let mut writer = Writer::pcapng(Vec::new()).unwrap();
        writer.add_interface(LinkType::ETHERNET).unwrap();
        for index in 0..frames {
            let frame = Frame::new(
                UNIX_EPOCH + Duration::from_secs(index),
                LinkType::ETHERNET,
                vec![index as u8; 64],
            )
            .expect("frame within limits");
            writer.write_frame(&frame).unwrap();
        }
        writer.into_inner()
    }

    fn options(frames_per_file: u64) -> split::Options {
        split::Options {
            frames_per_file,
            limits: split::Limits::default(),
        }
    }

    fn destinations(
        directory: &Path,
        plan: &split::Plan,
        compression: Compression,
    ) -> Vec<PathBuf> {
        let extension = output_extension(plan.report().format, compression);
        plan.report()
            .parts
            .iter()
            .map(|part| directory.join(format!("part-{:06}.{extension}", part.index)))
            .collect()
    }

    /// Plans and writes `pcapng(frames)` through a `Parts` sink, returning the
    /// core report and the sealed artifacts/saved-file facts it produced.
    fn split_parts(
        directory: &Path,
        frames: u64,
        frames_per_file: u64,
        compression: Compression,
        limit: u64,
    ) -> (split::Report, Generated) {
        let mut reader = Reader::new(Cursor::new(pcapng(frames))).unwrap();
        let plan = split::plan(&mut reader, options(frames_per_file)).unwrap();
        let destinations = destinations(directory, &plan, compression);
        let mut sink = Parts::new(destinations, compression, limit);
        let report = split::write(&mut reader, plan, &mut sink).unwrap();
        (report, sink.generated())
    }

    #[test]
    fn invalid_split_options_fail_before_the_source_is_opened() {
        let directory = tempfile::tempdir().unwrap();
        let directory = directory.path().to_str().unwrap().to_owned();
        let (stream, _) = crate::test_support::stream(crate::output::contract::Command::Split);
        let mut cases: Vec<Vec<String>> = vec![
            vec!["--frames-per-file".to_owned(), "0".to_owned()],
            vec!["--frames-per-file".to_owned(), "1".to_owned()],
            vec!["--frames-per-file".to_owned(), "1".to_owned()],
            vec!["--frames-per-file".to_owned(), "1".to_owned()],
            vec!["--frames-per-file".to_owned(), "1".to_owned()],
            vec!["--frames-per-file".to_owned(), "1".to_owned()],
        ];
        cases[1].extend(["--max-files".to_owned(), "0".to_owned()]);
        cases[2].extend(["--max-files".to_owned(), "4097".to_owned()]);
        cases[3].extend(["--max-split-metadata-records".to_owned(), "0".to_owned()]);
        cases[4].extend(["--max-split-metadata-bytes".to_owned(), "0".to_owned()]);
        cases[5].extend(["--max-split-output-bytes".to_owned(), "0".to_owned()]);
        for case in cases {
            // The source never exists: a usage refusal must still fire first.
            let argv: Vec<String> = ["missing-input.pcapng".to_owned()]
                .into_iter()
                .chain(case)
                .chain(["--write-dir".to_owned(), directory.clone()])
                .collect();
            let args = parse(&argv.iter().map(String::as_str).collect::<Vec<_>>());
            let error = run(args, ToolFormat::Text, &stream).unwrap_err();
            assert_eq!(
                error.classification.code, "cli.capture_split",
                "{argv:?} must fail semantically before source I/O"
            );
            assert_eq!(error.exit_code(), 2);
        }
    }

    #[test]
    fn the_output_directory_must_exist_and_be_a_directory() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let capture = root.path().join("source.pcapng");
        std::fs::write(&capture, pcapng(2)).unwrap();
        let (stream, _) = crate::test_support::stream(crate::output::contract::Command::Split);
        let args = parse(&[
            capture.to_str().unwrap(),
            "--frames-per-file",
            "1",
            "--write-dir",
            missing.to_str().unwrap(),
        ]);
        let error = run(args, ToolFormat::Text, &stream).unwrap_err();
        assert_eq!(error.classification.code, "io.output_file");
        assert_eq!(error.exit_code(), 5);

        let not_a_directory = root.path().join("file");
        std::fs::write(&not_a_directory, b"occupied").unwrap();
        let args = parse(&[
            capture.to_str().unwrap(),
            "--frames-per-file",
            "1",
            "--write-dir",
            not_a_directory.to_str().unwrap(),
        ]);
        let error = run(args, ToolFormat::Text, &stream).unwrap_err();
        assert_eq!(error.classification.code, "io.output_file");
        assert!(error.message.contains("not a directory"));
    }

    #[test]
    fn every_predicted_destination_is_checked_before_any_generation() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("parts");
        std::fs::create_dir(&directory).unwrap();
        let capture = root.path().join("source.pcapng");
        std::fs::write(&capture, pcapng(5)).unwrap();
        // A collision at the SECOND predicted name must still leave the
        // directory untouched: the first part was never generated.
        let occupied = directory.join("part-000002.pcapng");
        std::fs::write(&occupied, b"mine").unwrap();
        let (stream, _) = crate::test_support::stream(crate::output::contract::Command::Split);
        let args = parse(&[
            capture.to_str().unwrap(),
            "--frames-per-file",
            "2",
            "--write-dir",
            directory.to_str().unwrap(),
        ]);
        let error = run(args, ToolFormat::Text, &stream).unwrap_err();
        assert_eq!(error.classification.code, "io.output_file");
        assert!(error.message.contains("part-000002.pcapng"));
        assert_eq!(std::fs::read(&occupied).unwrap(), b"mine");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_at_a_predicted_name_is_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("parts");
        std::fs::create_dir(&directory).unwrap();
        let capture = root.path().join("source.pcapng");
        std::fs::write(&capture, pcapng(3)).unwrap();
        let dangling = directory.join("part-000001.pcapng");
        std::os::unix::fs::symlink("missing-target", &dangling).unwrap();
        let (stream, _) = crate::test_support::stream(crate::output::contract::Command::Split);
        let args = parse(&[
            capture.to_str().unwrap(),
            "--frames-per-file",
            "1",
            "--write-dir",
            directory.to_str().unwrap(),
        ]);
        let error = run(args, ToolFormat::Text, &stream).unwrap_err();
        assert_eq!(error.classification.code, "io.output_file");
        assert_eq!(
            std::fs::read_link(&dangling).unwrap(),
            std::path::PathBuf::from("missing-target")
        );
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    }

    #[test]
    fn a_source_at_a_predicted_name_is_never_used_as_output() {
        let directory = tempfile::tempdir().unwrap();
        let capture = directory.path().join("part-000001.pcapng");
        std::fs::write(&capture, pcapng(3)).unwrap();
        let original = std::fs::read(&capture).unwrap();
        let (stream, _) = crate::test_support::stream(crate::output::contract::Command::Split);
        let args = parse(&[
            capture.to_str().unwrap(),
            "--frames-per-file",
            "1",
            "--write-dir",
            directory.path().to_str().unwrap(),
        ]);
        let error = run(args, ToolFormat::Text, &stream).unwrap_err();
        assert_eq!(error.classification.code, "io.output_file");
        assert_eq!(std::fs::read(&capture).unwrap(), original);
    }

    #[test]
    fn plain_parts_have_fixed_names_and_exact_file_lengths() {
        let directory = tempfile::tempdir().unwrap();
        let (report, generated) = split_parts(directory.path(), 5, 2, Compression::None, u64::MAX);
        let Generated { sealed, saved } = generated;
        assert_eq!(
            saved
                .iter()
                .map(|file| file.name.as_str())
                .collect::<Vec<_>>(),
            [
                "part-000001.pcapng",
                "part-000002.pcapng",
                "part-000003.pcapng"
            ]
        );
        publish(sealed.into_iter().map(|file| (file, ())).collect()).unwrap();
        for (part, file) in report.parts.iter().zip(&saved) {
            let size = std::fs::metadata(directory.path().join(&file.name))
                .unwrap()
                .len();
            assert_eq!(file.encoded_bytes, size);
            assert_eq!(
                file.encoded_bytes, part.decoded_bytes,
                "uncompressed parts count decoded bytes exactly"
            );
        }
        let total: u64 = saved.iter().map(|file| file.encoded_bytes).sum();
        assert_eq!(total, report.decoded_bytes_written);
    }

    #[test]
    fn compressor_finish_and_trailer_bytes_are_counted_below_the_codec() {
        let directory = tempfile::tempdir().unwrap();
        let (report, generated) = split_parts(directory.path(), 5, 2, Compression::Gzip, u64::MAX);
        let Generated { sealed, saved } = generated;
        publish(sealed.into_iter().map(|file| (file, ())).collect()).unwrap();
        for file in &saved {
            assert!(file.name.ends_with(".pcapng.gz"));
            // The encoded length is the closed file's exact size, including
            // the gzip header and trailer written at finish.
            assert_eq!(
                file.encoded_bytes,
                std::fs::metadata(directory.path().join(&file.name))
                    .unwrap()
                    .len()
            );
        }
        assert_eq!(
            report
                .parts
                .iter()
                .map(|part| part.index)
                .collect::<Vec<_>>(),
            saved.iter().map(|file| file.index).collect::<Vec<_>>()
        );
    }

    #[test]
    fn encoded_limit_refusal_keeps_its_policy_classification_through_codec_errors() {
        let measured_dir = tempfile::tempdir().unwrap();
        let (_, generated) = split_parts(measured_dir.path(), 5, 2, Compression::Gzip, u64::MAX);
        let measured: u64 = generated.saved.iter().map(|file| file.encoded_bytes).sum();
        drop(generated);

        let directory = tempfile::tempdir().unwrap();
        let mut reader = Reader::new(Cursor::new(pcapng(5))).unwrap();
        let plan = split::plan(&mut reader, options(2)).unwrap();
        let destinations = destinations(directory.path(), &plan, Compression::Gzip);
        let mut sink = Parts::new(destinations, Compression::Gzip, measured - 1);
        let error = split::write(&mut reader, plan, &mut sink).unwrap_err();
        let error = CliError::classified(error);
        assert_eq!(error.classification.code, "policy.capture_split_limit");
        assert_eq!(error.exit_code(), 6);
        // The live sink still owns the sealed staging paths; dropping it must
        // remove them, and nothing was committed under a destination name.
        drop(sink);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn the_shared_refusal_latches_the_typed_policy_error() {
        let directory = tempfile::tempdir().unwrap();
        let shared = Rc::new(RefCell::new(SharedEncoded {
            total: 0,
            limit: 4,
            refusal: None,
        }));
        let staged = StagedFile::stage(&directory.path().join("part-000001.pcap")).unwrap();
        let mut counted = Encoded {
            staged,
            written: 0,
            shared: Rc::clone(&shared),
        };
        counted.write(b"abcde").unwrap_err();
        let boundary = io_failure(
            &shared,
            "write",
            Path::new("ignored"),
            io::Error::other("codec"),
        );
        assert_eq!(boundary.classification().code, "policy.capture_split_limit");
        drop(counted);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn equality_with_the_encoded_ceiling_is_accepted() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("part-000001.pcap");
        let staged = StagedFile::stage(&destination).unwrap();
        let shared = Rc::new(RefCell::new(SharedEncoded {
            total: 0,
            limit: 4,
            refusal: None,
        }));
        let mut counted = Encoded {
            staged,
            written: 0,
            shared,
        };
        assert_eq!(counted.write(b"abcd").unwrap(), 4);
    }

    #[test]
    fn generation_opens_one_output_descriptor_at_a_time() {
        /// Instruments the staging directory between the sink's callbacks.
        struct Instrumented {
            inner: Parts,
            directory: PathBuf,
            peak_staged: usize,
        }

        impl split::Sink for Instrumented {
            fn begin(
                &mut self,
                index: u64,
                format: capture_file::Format,
            ) -> Result<(), BoundaryError> {
                assert!(
                    self.inner.active.is_none(),
                    "no output is open between parts"
                );
                self.inner.begin(index, format)
            }

            fn write(&mut self, bytes: &[u8]) -> Result<(), BoundaryError> {
                assert!(self.inner.active.is_some(), "the part's only open output");
                let staged = std::fs::read_dir(&self.directory).unwrap().count();
                assert_eq!(
                    staged,
                    self.inner.sealed.len() + 1,
                    "one active staging file beside the sealed paths"
                );
                self.peak_staged = self.peak_staged.max(staged);
                self.inner.write(bytes)
            }

            fn finish(&mut self, part: &split::Part) -> Result<(), BoundaryError> {
                self.inner.finish(part)?;
                assert!(
                    self.inner.active.is_none(),
                    "the compressor and descriptor closed at finish"
                );
                assert_eq!(
                    std::fs::read_dir(&self.directory).unwrap().count(),
                    self.inner.sealed.len(),
                    "a finished part keeps only a closed path"
                );
                Ok(())
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let mut reader = Reader::new(Cursor::new(pcapng(256))).unwrap();
        let plan = split::plan(&mut reader, options(1)).unwrap();
        let mut sink = Instrumented {
            inner: Parts::new(
                destinations(directory.path(), &plan, Compression::None),
                Compression::None,
                u64::MAX,
            ),
            directory: directory.path().to_owned(),
            peak_staged: 0,
        };
        split::write(&mut reader, plan, &mut sink).unwrap();
        assert_eq!(sink.inner.sealed.len(), 256);
        // The last part saw 255 sealed paths plus its own staging file: one
        // output descriptor and compressor were ever open at a time.
        assert_eq!(sink.peak_staged, 256);
    }

    #[test]
    fn a_deadline_during_generation_stops_before_any_commit() {
        use packetcraftr_core::budget::Deadline;
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };
        use std::time::{Duration, Instant};

        let ticks = Arc::new(AtomicU64::new(0));
        let observed = ticks.clone();
        let start = Instant::now();
        let deadline = Arc::new(Deadline::with_time_source(
            Duration::from_millis(5),
            move || start + Duration::from_millis(observed.load(Ordering::SeqCst)),
        ));
        let _scope = crate::invocation::enter_deadline(Some(deadline));
        // The clock starts at construction; advancing it past the limit makes
        // the next staging check expire inside the first part's `begin`.
        ticks.store(6, Ordering::SeqCst);
        let directory = tempfile::tempdir().unwrap();
        let mut reader = Reader::new(Cursor::new(pcapng(5))).unwrap();
        let plan = split::plan(&mut reader, options(2)).unwrap();
        let mut sink = Parts::new(
            destinations(directory.path(), &plan, Compression::None),
            Compression::None,
            u64::MAX,
        );
        let error = split::write(&mut reader, plan, &mut sink).unwrap_err();
        let error = CliError::classified(error);
        assert_eq!(error.classification.code, "policy.duration_limit");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn run_prepares_one_frozen_ndjson_report_and_commits_every_part() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("parts");
        std::fs::create_dir(&directory).unwrap();
        let capture = root.path().join("source.pcapng");
        std::fs::write(&capture, pcapng(5)).unwrap();
        let (stream, buffer) = crate::test_support::stream(crate::output::contract::Command::Split);
        let args = parse(&[
            capture.to_str().unwrap(),
            "--frames-per-file",
            "2",
            "--write-dir",
            directory.to_str().unwrap(),
        ]);
        run(args, ToolFormat::Ndjson, &stream).unwrap();
        for name in [
            "part-000001.pcapng",
            "part-000002.pcapng",
            "part-000003.pcapng",
        ] {
            assert!(directory.join(name).is_file(), "{name} committed");
        }
        let records = crate::test_support::parse_ndjson(&buffer.bytes());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["event"], "complete");
        let result = &records[0]["result"];
        assert_eq!(result["format"], "pcapng");
        assert_eq!(result["compression"], "none");
        assert_eq!(result["frames_read"], 5);
        assert_eq!(result["files"].as_array().unwrap().len(), 3);
        assert_eq!(result["files"][0]["file"], "part-000001.pcapng");
        assert_eq!(result["files"][0]["first_frame"], 1);
        assert_eq!(result["files"][0]["last_frame"], 2);
        assert_eq!(result["files"][2]["first_frame"], 5);
        let decoded: u64 = result["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|part| part["decoded_bytes"].as_u64().unwrap())
            .sum();
        assert_eq!(decoded, result["decoded_bytes_written"].as_u64().unwrap());
        let encoded: u64 = result["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|part| part["encoded_bytes"].as_u64().unwrap())
            .sum();
        assert_eq!(encoded, result["encoded_bytes_written"].as_u64().unwrap());
        // Every committed part independently rereads as a valid capture.
        for file in result["files"].as_array().unwrap() {
            let path = directory.join(file["file"].as_str().unwrap());
            let mut reader = Reader::new(std::fs::File::open(&path).unwrap()).unwrap();
            let frames = file["frames"].as_u64().unwrap();
            let mut read = 0_u64;
            while reader.next_frame().unwrap().is_some() {
                read += 1;
            }
            assert_eq!(read, frames);
        }
    }
}
