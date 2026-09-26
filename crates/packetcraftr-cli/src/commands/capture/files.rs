// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Frame-boundary rotation. Slots retain owned file handles so explicit ring
//! reuse never opens or truncates an unrelated pre-existing pathname.

use crate::command_options::Compression;
use crate::output::capture::{File as FileReport, Files as FilesReport, Retention};
use packetcraftr_core::{
    analysis::pcap::{self, compression},
    error::{Classification, Classified, Kind},
    frame::Frame,
};
use packetcraftr_netio::capture::group::Source;
use std::{
    fs::File,
    io::{self, Seek, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub(super) const MAX_FILES: usize = 64;
#[derive(Clone, Debug)]
pub(super) struct Options {
    pub(super) path: PathBuf,
    pub(super) compression: Compression,
    pub(super) rotate_bytes: Option<u64>,
    pub(super) rotate_after: Option<Duration>,
    pub(super) max_files: usize,
    pub(super) retention: Retention,
}
impl Options {
    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.max_files == 0
            || self.max_files > MAX_FILES
            || self.rotate_bytes == Some(0)
            || self
                .rotate_after
                .is_some_and(|duration| duration.is_zero() || duration > Duration::from_secs(3600))
        {
            return Err(Error::Invalid(
                "rotation requires positive byte/time limits and 1..=64 files",
            ));
        }
        if !self.rotating() && (self.max_files != 1 || self.retention == Retention::Ring) {
            return Err(Error::Invalid(
                "multiple files or ring retention require a rotation threshold",
            ));
        }
        let parent = parent(&self.path);
        if !parent.is_dir() {
            return Err(Error::Invalid(
                "capture output parent must be an existing directory",
            ));
        }
        for slot in 0..self.max_files {
            let path = self.slot_path(slot)?;
            if path.try_exists().map_err(|source| Error::Io {
                path: path.clone(),
                source,
            })? {
                return Err(Error::Exists(path));
            }
        }
        Ok(())
    }
    fn rotating(&self) -> bool {
        self.rotate_bytes.is_some() || self.rotate_after.is_some()
    }
    fn slot_path(&self, slot: usize) -> Result<PathBuf, Error> {
        if !self.rotating() {
            return Ok(self.path.clone());
        }
        let mut name = self
            .path
            .file_stem()
            .ok_or(Error::Invalid("capture output needs a file name"))?
            .to_os_string();
        name.push(format!(".{:06}", slot + 1));
        if let Some(extension) = self.path.extension() {
            name.push(".");
            name.push(extension);
        }
        Ok(parent(&self.path).join(name))
    }
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("invalid capture files: {0}")]
    Invalid(&'static str),
    #[error("capture output already exists: {}",.0.display())]
    Exists(PathBuf),
    #[error("capture file {}: {source}",.path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Capture(#[from] pcap::Error),
    #[error(transparent)]
    Compression(#[from] compression::Error),
    #[error(
        "one capture frame with file metadata needs {required} bytes, above --rotate-bytes {limit}"
    )]
    FrameTooLarge { required: u64, limit: u64 },
    #[error("capture rotation counters overflowed")]
    Counters,
    #[error("capture rotation elapsed time regressed")]
    ElapsedRegressed,
    #[error("capture file sink has no initialized source metadata")]
    State,
}
impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Capture(source) => source.classification(),
            Self::Compression(source) => source.classification(),
            Self::Io { .. } | Self::Exists(_) => {
                Classification::new("io.capture_file", Kind::Io, None)
            }
            Self::Invalid(_) => Classification::new("cli.capture_files", Kind::Cli, None),
            Self::FrameTooLarge { .. } => {
                Classification::new("policy.capture_file_bytes", Kind::Policy, None)
            }
            Self::State | Self::Counters | Self::ElapsedRegressed => {
                Classification::new("internal.capture_files", Kind::Internal, None)
            }
        }
    }
}
struct Counted<W> {
    inner: W,
    bytes: u64,
}
impl<W: Write> Write for Counted<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("capture byte counter overflow"))?;
        let written = self.inner.write(bytes)?;
        self.bytes = self
            .bytes
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::other("capture byte counter overflow"))?;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
struct Slot {
    handle: File,
    report: FileReport,
}
struct Active {
    failed: bool,
    writer: pcap::Writer<Counted<compression::Output<File>>>,
    slot: usize,
    opened_at: Duration,
}
pub(super) struct Files {
    options: Options,
    limits: pcap::Limits,
    sources: Vec<Source>,
    slots: Vec<Slot>,
    active: Option<Active>,
    header_bytes: u64,
    generation: u64,
    total_frames: u64,
    total_bytes: u64,
    discarded_files: u64,
    discarded_frames: u64,
    discarded_bytes: u64,
    last_elapsed: Duration,
    stopped: bool,
}
impl Files {
    pub(super) fn new(options: Options, limits: pcap::Limits) -> Result<Self, Error> {
        options.validate()?;
        Ok(Self {
            options,
            limits,
            sources: Vec::new(),
            slots: Vec::new(),
            active: None,
            header_bytes: 0,
            generation: 0,
            total_frames: 0,
            total_bytes: 0,
            discarded_files: 0,
            discarded_frames: 0,
            discarded_bytes: 0,
            last_elapsed: Duration::ZERO,
            stopped: false,
        })
    }
    pub(super) fn initialize(&mut self, sources: Vec<Source>) -> Result<(), Error> {
        if self.active.is_some() || !self.sources.is_empty() || sources.is_empty() {
            return Err(Error::State);
        }
        self.sources = sources;
        let preview = super::writer::initialize(
            Counted {
                inner: io::sink(),
                bytes: 0,
            },
            pcap::Format::PcapNg,
            &self.sources,
            self.limits,
        )?;
        self.header_bytes = preview.into_inner().bytes;
        if let Some(limit) = self.options.rotate_bytes
            && self.header_bytes > limit
        {
            return Err(Error::FrameTooLarge {
                required: self.header_bytes,
                limit,
            });
        }
        self.open(0, Duration::ZERO)
    }
    pub(super) fn write(
        &mut self,
        frame: &Frame,
        source_frame: u64,
        elapsed: Duration,
    ) -> Result<packetcraftr::capture::Control, Error> {
        let source_frame =
            crate::output::frame::SourceFrame::try_from(source_frame).map_err(|_| Error::State)?;
        if self.stopped {
            return Ok(packetcraftr::capture::Control::StopBefore);
        }
        if elapsed < self.last_elapsed {
            return Err(Error::ElapsedRegressed);
        }
        self.last_elapsed = elapsed;
        let (next_frames, next_bytes) =
            self.limits
                .advance(self.total_frames, self.total_bytes, frame.captured_length())?;
        let active = self.active.as_ref().ok_or(Error::State)?;
        let frame_bytes = active.writer.encoded_frame_size(frame)? as u64;
        let required = self
            .header_bytes
            .checked_add(frame_bytes)
            .ok_or(Error::FrameTooLarge {
                required: u64::MAX,
                limit: self.options.rotate_bytes.unwrap_or(u64::MAX),
            })?;
        if let Some(limit) = self.options.rotate_bytes
            && required > limit
        {
            return Err(Error::FrameTooLarge { required, limit });
        }
        let size_boundary = self
            .options
            .rotate_bytes
            .is_some_and(|limit| active.writer.get_ref().bytes.saturating_add(frame_bytes) > limit);
        let time_boundary = self
            .options
            .rotate_after
            .is_some_and(|interval| elapsed.saturating_sub(active.opened_at) >= interval);
        if active.writer.frames_written() > 0 && (size_boundary || time_boundary) {
            self.finish_active()?;
            let slot = if self.slots.len() < self.options.max_files {
                self.slots.len()
            } else if self.options.retention == Retention::Ring {
                (self.generation % self.options.max_files as u64) as usize
            } else {
                self.stopped = true;
                return Ok(packetcraftr::capture::Control::StopBefore);
            };
            self.open(slot, elapsed)?;
        }
        let active = self.active.as_mut().ok_or(Error::State)?;
        if let Err(error) = active.writer.write_frame(frame) {
            active.failed = matches!(error, pcap::Error::Io(_));
            return Err(error.into());
        }
        let report = &mut self.slots[active.slot].report;
        report.frames = active.writer.frames_written();
        report.capture_bytes = active.writer.get_ref().bytes;
        report.first_source_frame.get_or_insert(source_frame);
        report.last_source_frame = Some(source_frame);
        let capture_bytes = report.capture_bytes;
        self.total_frames = next_frames;
        self.total_bytes = next_bytes;
        // Stop exactly at a full final slot when possible; otherwise a later
        // boundary reports its one matched but unpublished frame explicitly.
        if self.options.retention == Retention::Stop
            && self.slots.len() == self.options.max_files
            && self
                .options
                .rotate_bytes
                .is_some_and(|limit| capture_bytes == limit)
        {
            self.stopped = true;
            Ok(packetcraftr::capture::Control::StopAfter)
        } else {
            Ok(packetcraftr::capture::Control::Continue)
        }
    }
    fn open(&mut self, slot: usize, elapsed: Duration) -> Result<(), Error> {
        if slot == self.slots.len() {
            let path = self.options.slot_path(slot)?;
            let temporary =
                tempfile::NamedTempFile::new_in(parent(&path)).map_err(|source| Error::Io {
                    path: path.clone(),
                    source,
                })?;
            let handle = temporary
                .persist_noclobber(&path)
                .map_err(|error| Error::Io {
                    path: path.clone(),
                    source: error.error,
                })?;
            self.slots.push(Slot {
                handle,
                report: FileReport {
                    path: path.display().to_string(),
                    slot: slot as u32,
                    generation: 0,
                    frames: 0,
                    capture_bytes: 0,
                    encoded_bytes: None,
                    first_source_frame: None,
                    last_source_frame: None,
                    finalized: false,
                },
            });
        } else {
            let previous = &self.slots[slot].report;
            self.discarded_files = self.discarded_files.checked_add(1).ok_or(Error::Counters)?;
            self.discarded_frames = self
                .discarded_frames
                .checked_add(previous.frames)
                .ok_or(Error::Counters)?;
            self.discarded_bytes = self
                .discarded_bytes
                .checked_add(previous.capture_bytes)
                .ok_or(Error::Counters)?;
            let file = &mut self.slots[slot];
            file.handle.set_len(0).map_err(|source| Error::Io {
                path: PathBuf::from(&file.report.path),
                source,
            })?;
            file.handle.rewind().map_err(|source| Error::Io {
                path: PathBuf::from(&file.report.path),
                source,
            })?;
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::Invalid("capture generation counter overflow"))?;
        let file = &mut self.slots[slot];
        file.report.generation = self.generation;
        file.report.frames = 0;
        file.report.capture_bytes = 0;
        file.report.encoded_bytes = None;
        file.report.first_source_frame = None;
        file.report.last_source_frame = None;
        file.report.finalized = false;
        let handle = file.handle.try_clone().map_err(|source| Error::Io {
            path: PathBuf::from(&file.report.path),
            source,
        })?;
        let output = Counted {
            inner: compression::Output::new(handle, self.options.compression.format())?,
            bytes: 0,
        };
        let writer =
            super::writer::initialize(output, pcap::Format::PcapNg, &self.sources, self.limits)?;
        self.header_bytes = writer.get_ref().bytes;
        file.report.capture_bytes = self.header_bytes;
        self.active = Some(Active {
            failed: false,
            writer,
            slot,
            opened_at: elapsed,
        });
        if let Some(limit) = self.options.rotate_bytes
            && self.header_bytes > limit
        {
            return Err(Error::FrameTooLarge {
                required: self.header_bytes,
                limit,
            });
        }
        Ok(())
    }
    pub(super) fn finish(&mut self) -> Result<(), Error> {
        self.finish_active()
    }
    fn finish_active(&mut self) -> Result<(), Error> {
        let Some(active) = self.active.take() else {
            return Ok(());
        };
        let slot = &mut self.slots[active.slot];
        slot.report.capture_bytes = active.writer.get_ref().bytes;
        let output = active.writer.into_inner();
        let finalized = output.inner.finish();
        if let Ok(handle) = &finalized {
            handle.sync_all().map_err(|source| Error::Io {
                path: PathBuf::from(&slot.report.path),
                source,
            })?;
        }
        slot.report.encoded_bytes = Some(
            slot.handle
                .metadata()
                .map_err(|source| Error::Io {
                    path: PathBuf::from(&slot.report.path),
                    source,
                })?
                .len(),
        );
        finalized?;
        slot.report.finalized = !active.failed;
        Ok(())
    }
    pub(super) fn report(&self) -> FilesReport {
        let mut files: Vec<_> = self
            .slots
            .iter()
            .map(|slot| {
                let mut report = slot.report.clone();
                if let Ok(metadata) = slot.handle.metadata() {
                    report.encoded_bytes = Some(metadata.len());
                }
                report
            })
            .collect();
        files.sort_by_key(|file| file.generation);
        FilesReport {
            retention: self.options.retention,
            compression: match self.options.compression {
                Compression::None => "none",
                Compression::Gzip => "gzip",
                Compression::Zstd => "zstd",
            }
            .to_owned(),
            rotate_bytes: self.options.rotate_bytes,
            rotate_interval_ms: self
                .options
                .rotate_after
                .map(|duration| duration.as_millis() as u64),
            maximum_files: self.options.max_files,
            files,
            frames_written: self.total_frames,
            captured_bytes_written: self.total_bytes,
            discarded_files: self.discarded_files,
            discarded_frames: self.discarded_frames,
            discarded_capture_bytes: self.discarded_bytes,
            stopped_at_retention_limit: self.stopped,
        }
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        let _ = self.finish_active();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::{
        analysis::pcap::Reader,
        frame::{Frame, LinkType},
    };
    use packetcraftr_netio::{
        capture::{Limits, Metadata, Statistics},
        interface::Id,
    };
    use std::time::UNIX_EPOCH;
    fn sources() -> Vec<Source> {
        vec![Source {
            index: 0,
            metadata: Metadata {
                interface: Id {
                    name: "fixture0".to_owned(),
                    index: 7,
                },
                link_type: LinkType::RAW,
                snap_length: 64,
                native: Default::default(),
            },
            limits: Limits {
                snap_length: 64,
                ..Default::default()
            },
            metadata_valid: true,
            ready: true,
            shutdown_confirmed: false,
            statistics_valid: true,
            statistics: Statistics::default(),
            delivered_frames: 0,
            delivered_bytes: 0,
        }]
    }
    fn frame(value: u8) -> Frame {
        let mut frame = Frame::new(
            UNIX_EPOCH + Duration::from_millis(u64::from(value)),
            LinkType::RAW,
            vec![value; 32],
        )
        .unwrap();
        frame.interface = Some(0);
        frame
    }
    fn limits() -> pcap::Limits {
        pcap::Limits {
            max_frames: 10,
            max_bytes: 1024,
        }
    }
    fn options(path: PathBuf, compression: Compression) -> Options {
        Options {
            path,
            compression,
            rotate_bytes: None,
            rotate_after: None,
            max_files: 1,
            retention: Retention::Stop,
        }
    }
    fn read_file(file: &FileReport) -> Vec<Frame> {
        let source = std::fs::File::open(&file.path).unwrap();
        let mut reader =
            Reader::new(compression::Input::new(source, Default::default()).unwrap()).unwrap();
        let mut frames = Vec::new();
        while let Some(frame) = reader.next_frame().unwrap() {
            frames.push(frame);
        }
        frames
    }
    #[test]
    fn exact_frame_boundaries_produce_complete_files_for_every_compression() {
        for compression in [Compression::None, Compression::Gzip, Compression::Zstd] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("trace.pcapng");
            let mut reference = super::super::writer::initialize(
                Vec::new(),
                pcap::Format::PcapNg,
                &sources(),
                limits(),
            )
            .unwrap();
            reference.write_frame(&frame(1)).unwrap();
            let one_frame_size = reference.into_inner().len() as u64;
            let mut options = options(path, compression);
            options.rotate_bytes = Some(one_frame_size);
            options.max_files = 2;
            let mut files = Files::new(options, limits()).unwrap();
            files.initialize(sources()).unwrap();
            assert_eq!(
                files.write(&frame(1), 1, Duration::ZERO).unwrap(),
                packetcraftr::capture::Control::Continue
            );
            assert_eq!(
                files.write(&frame(2), 2, Duration::from_millis(1)).unwrap(),
                packetcraftr::capture::Control::StopAfter
            );
            files.finish().unwrap();
            let report = files.report();
            assert_eq!(report.frames_written, 2);
            assert_eq!(report.files.len(), 2);
            assert!(report.stopped_at_retention_limit);
            for (index, file) in report.files.iter().enumerate() {
                assert!(file.finalized);
                assert_eq!(file.capture_bytes, one_frame_size);
                assert!(file.encoded_bytes.unwrap() > 0);
                let frames = read_file(file);
                assert_eq!(frames.len(), 1);
                assert_eq!(frames[0].bytes(), frame(index as u8 + 1).bytes());
            }
        }
    }
    #[test]
    fn time_rotation_reuses_only_owned_handles_and_reports_retired_generations() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ring.pcapng");
        let mut options = options(path, Compression::Gzip);
        options.rotate_after = Some(Duration::from_millis(10));
        options.max_files = 2;
        options.retention = Retention::Ring;
        let mut files = Files::new(options, limits()).unwrap();
        files.initialize(sources()).unwrap();
        for (index, millis) in [0, 5, 11, 21].into_iter().enumerate() {
            files
                .write(
                    &frame(index as u8 + 1),
                    index as u64 + 1,
                    Duration::from_millis(millis),
                )
                .unwrap();
        }
        files.finish().unwrap();
        let report = files.report();
        assert_eq!(report.files.len(), 2);
        assert_eq!(report.frames_written, 4);
        assert_eq!(report.discarded_files, 1);
        assert_eq!(report.discarded_frames, 2);
        assert_eq!(
            report
                .files
                .iter()
                .map(|file| file.generation)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        assert_eq!(read_file(&report.files[0])[0].bytes(), frame(3).bytes());
        assert_eq!(read_file(&report.files[1])[0].bytes(), frame(4).bytes());
    }
    /// Elapsed time comes from the capture engine's monotonic clock, so a
    /// regression is a broken invariant rather than a usage error.
    #[test]
    fn elapsed_time_regression_is_an_internal_failure() {
        let directory = tempfile::tempdir().unwrap();
        let mut options = options(directory.path().join("clock.pcapng"), Compression::None);
        options.rotate_after = Some(Duration::from_millis(10));
        let mut files = Files::new(options, limits()).unwrap();
        files.initialize(sources()).unwrap();
        files.write(&frame(1), 1, Duration::from_millis(5)).unwrap();
        let error = files
            .write(&frame(2), 2, Duration::from_millis(4))
            .expect_err("elapsed time regressed");
        assert_eq!(error.classification().code, "internal.capture_files");
        assert_eq!(error.classification().kind, Kind::Internal);
    }
    #[test]
    fn preexisting_files_and_impossible_metadata_budgets_are_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("existing.pcapng");
        std::fs::write(&path, b"unrelated").unwrap();
        assert!(Files::new(options(path.clone(), Compression::None), limits()).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"unrelated");
        let path = directory.path().join("small.pcapng");
        let mut settings = options(path, Compression::None);
        settings.rotate_bytes = Some(1);
        let mut files = Files::new(settings, limits()).unwrap();
        assert!(files.initialize(sources()).is_err());
        assert!(files.report().files.is_empty());
    }
}
