// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    command_options::{MaxDurationArgs, OfflineCaptureLimitsArgs, RunTime},
    errors::CliError,
    output::{
        self,
        contract::{Command, ToolFormat},
    },
    rendering::{StreamEncoder, emit_aggregate, write_summary_line},
    staged_output::{StagedDirectory, StagedFile},
};
use packetcraftr_core::capture_file;
use std::{
    io::{BufWriter, Write},
    path::PathBuf,
    time::Duration,
};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TransformRunTime;
impl RunTime for TransformRunTime {
    const HELP: &'static str = "Maximum offline transformation run time in milliseconds";
}

#[derive(Debug, clap::Args)]
pub(crate) struct DedupArgs {
    /// Source PCAP/PCAPNG capture; - reads stdin.
    pub(crate) path: PathBuf,
    /// New capture destination, preserving the source format and raw records.
    #[arg(long)]
    pub(crate) write: PathBuf,
    /// Number of preceding input frames compared by exact bytes and capture identity.
    #[arg(long, default_value_t = 1024, value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) window_frames: u64,
    /// Maximum exact frame bytes retained by deduplication.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    pub(crate) max_dedup_bytes: usize,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs<TransformRunTime>,
}

#[derive(Debug, clap::Args)]
#[command(group(clap::ArgGroup::new("split_selector").required(true).multiple(false).args(["packets", "bytes", "interval_ms"])))]
pub(crate) struct SplitArgs {
    /// Source PCAP/PCAPNG capture; - reads stdin.
    pub(crate) path: PathBuf,
    /// New directory for independently readable, numbered capture files.
    #[arg(long)]
    pub(crate) write: PathBuf,
    /// Maximum packet count per output file.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) packets: Option<u64>,
    /// Maximum captured payload bytes per file; packets remain indivisible.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) bytes: Option<u64>,
    /// Capture timestamp interval per file, in milliseconds.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) interval_ms: Option<u64>,
    /// Maximum files published by this operation.
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u64).range(1..=64))]
    pub(crate) max_files: u64,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs<TransformRunTime>,
}

#[derive(Debug, clap::Args)]
pub(crate) struct ShiftArgs {
    /// Source PCAP/PCAPNG capture; - reads stdin.
    pub(crate) path: PathBuf,
    /// Exact signed decimal seconds; shifts unrepresentable at source precision fail.
    #[arg(long, allow_hyphen_values = true, value_name = "SIGNED_DECIMAL")]
    pub(crate) seconds: capture_file::TimeShift,
    /// New capture destination, preserving raw records and source precision.
    #[arg(long)]
    pub(crate) write: PathBuf,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs<TransformRunTime>,
}

fn publish<T: serde::Serialize>(
    format: ToolFormat,
    stream: &StreamEncoder,
    command: Command,
    report: T,
    message: String,
) -> Result<super::CommandExit, CliError> {
    match format {
        ToolFormat::Text => write_summary_line(format_args!("{message}"))?,
        ToolFormat::Json => emit_aggregate(command, report, Vec::new())?,
        ToolFormat::Ndjson => stream.complete(report, Vec::new())?,
    }
    Ok(super::CommandExit::SUCCESS)
}

impl super::Spec for DedupArgs {
    type Format = ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;
    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.duration)
    }
    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [window_frames: Count @ ActiveState, max_dedup_bytes: Bytes @ ActiveState]);
        self.limits.resources(settings);
        self.duration.resources(settings);
    }
    fn run(
        self,
        format: ToolFormat,
        stream: &StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        self.limits.validate()?;
        let window_frames = usize::try_from(self.window_frames).map_err(|_| {
            CliError::new(
                packetcraftr_core::error::Kind::Usage,
                "dedup window exceeds platform size",
            )
        })?;
        let mut staged = StagedFile::stage(&self.write)?;
        let mut reader = crate::input::open_capture(&self.path, self.limits.reader)?;
        let (mut writer, report) = capture_file::dedup(
            &mut reader,
            BufWriter::new(staged.as_file_mut()),
            self.limits.stream_limits(),
            capture_file::DedupLimits {
                window_frames,
                max_retained_bytes: self.max_dedup_bytes,
            },
        )
        .map_err(CliError::classified)?;
        writer
            .flush()
            .map_err(|error| CliError::caused(packetcraftr_core::error::Kind::Io, &error))?;
        drop(writer);
        staged.sync()?;
        staged.persist()?;
        let message = format!(
            "kept {} of {} frames; {} duplicates removed into {}",
            report.selection.frames_selected,
            report.selection.frames_read,
            report.duplicates,
            self.write.display()
        );
        publish(
            format,
            stream,
            Command::Dedup,
            output::capture_transform::Dedup::from((self.write.display().to_string(), report)),
            message,
        )
    }
}

impl super::Spec for SplitArgs {
    type Format = ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;
    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.duration)
    }
    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [max_files: Count @ CaptureStorage]);
        self.limits.resources(settings);
        self.duration.resources(settings);
    }
    fn run(
        self,
        format: ToolFormat,
        stream: &StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        self.limits.validate()?;
        let selector = if let Some(packets) = self.packets {
            capture_file::SplitSelector::Packets(packets)
        } else if let Some(bytes) = self.bytes {
            capture_file::SplitSelector::Bytes(bytes)
        } else {
            capture_file::SplitSelector::Interval(Duration::from_millis(
                self.interval_ms.expect("required split selector"),
            ))
        };
        let staged = StagedDirectory::stage(&self.write)?;
        let mut reader = crate::input::open_capture(&self.path, self.limits.reader)?;
        let extension = reader.format().as_str();
        let (writers, report) = capture_file::split(
            &mut reader,
            self.limits.stream_limits(),
            selector,
            capture_file::SplitLimits {
                max_files: self.max_files as usize,
            },
            |index| {
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(
                        staged
                            .path()
                            .join(format!("capture-{index:04}.{extension}")),
                    )?;
                Ok(BufWriter::new(file))
            },
        )
        .map_err(CliError::classified)?;
        drop(writers);
        staged.persist()?;
        let message = format!(
            "split {} frames into {} files under {}",
            report.frames,
            report.files,
            self.write.display()
        );
        publish(
            format,
            stream,
            Command::Split,
            output::capture_transform::Split::from((self.write.display().to_string(), report)),
            message,
        )
    }
}

impl super::Spec for ShiftArgs {
    type Format = ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;
    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.duration)
    }
    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.limits.resources(settings);
        self.duration.resources(settings);
    }
    fn run(
        self,
        format: ToolFormat,
        stream: &StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        self.limits.validate()?;
        let mut staged = StagedFile::stage(&self.write)?;
        let mut reader = crate::input::open_capture(&self.path, self.limits.reader)?;
        let (mut writer, report) = capture_file::shift_time(
            &mut reader,
            BufWriter::new(staged.as_file_mut()),
            self.limits.stream_limits(),
            self.seconds,
        )
        .map_err(CliError::classified)?;
        writer
            .flush()
            .map_err(|error| CliError::caused(packetcraftr_core::error::Kind::Io, &error))?;
        drop(writer);
        staged.sync()?;
        staged.persist()?;
        let message = format!(
            "shifted {} packets and {} statistics records into {}",
            report.shifted_packets,
            report.shifted_statistics,
            self.write.display()
        );
        publish(
            format,
            stream,
            Command::ShiftTime,
            output::capture_transform::Shift::from((self.write.display().to_string(), report)),
            message,
        )
    }
}
