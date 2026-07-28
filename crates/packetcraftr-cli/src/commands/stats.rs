// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Offline capture-statistics command.

use std::fs::File;
use std::net::SocketAddr;
use std::time::Duration;

use packetcraftr::{
    analysis,
    capture::{Reader, ReaderOptions},
    output,
};

use super::super::arguments::{CliStatsTable, StatsArgs};
use super::super::errors::{CliError, analysis_cli_error};
use super::super::filtering::{self, Capabilities};
use super::super::rendering::{emit_json, write_stdout_line};
use super::super::runtime::default_registry_arc;
use super::offline::validate_capture_stream_limits;

pub(crate) fn run_stats(
    arguments: StatsArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    // The format contract is enforced before any input is read, so asking
    // for an unsupported encoding never pays for a full analysis pass.
    output::contract::Command::Stats
        .require_format(output)
        .map_err(CliError::classified)?;
    validate_capture_stream_limits(
        arguments.max_frames,
        arguments.max_bytes,
        arguments.max_frame_bytes,
        arguments.max_interfaces,
    )?;
    let registry = default_registry_arc()?;
    // Stats assigns conversation indices, so stream-aware filters like
    // `tcp.stream == 7` are supported here.
    let filter = match arguments.filter.as_deref() {
        Some(source) => Some(filtering::compile(
            source,
            &registry,
            Capabilities::stream_capable(),
        )?),
        None => None,
    };
    let limits = analysis::Limits {
        max_frames: arguments.max_frames,
        max_bytes: arguments.max_bytes,
        max_frame_bytes: arguments.max_frame_bytes,
        max_flows: arguments.max_flows,
        max_duration: Duration::from_millis(arguments.max_duration_ms),
    };
    // Every limit is refused before the capture is opened, so an invalid
    // invocation never reports an unrelated I/O or header error instead.
    limits.validate().map_err(analysis_cli_error)?;
    let mut collector =
        analysis::stats::StatsCollector::new(Duration::from_millis(arguments.interval_ms))
            .map_err(analysis_cli_error)?;

    let file = File::open(&arguments.path).map_err(|source| {
        CliError::new(
            5,
            format!("open {} failed: {source}", arguments.path.display()),
        )
    })?;
    let mut reader = Reader::with_options(
        file,
        ReaderOptions {
            max_size: arguments.max_frame_bytes,
            max_interfaces_per_section: arguments.max_interfaces,
            ..ReaderOptions::default()
        },
    )
    .map_err(CliError::classified)?;

    let options = analysis::Options {
        filter: filter.as_ref(),
        tcp_events: false,
        limits,
    };
    let summary = analysis::run(&mut reader, registry, &options, |record| {
        collector.observe(&record);
        Ok(())
    })
    .map_err(analysis_cli_error)?;
    let report = collector.finish();

    match output {
        output::contract::Format::Text => render_text(arguments.table, &report, &summary),
        output::contract::Format::Json => {
            let result = output::stats::Result::try_from_report(
                stats_table(arguments.table),
                &report,
                summary.frames_read,
            )
            .map_err(CliError::classified)?;
            emit_json(&output::envelope::Aggregate::success(
                output::contract::Command::Stats,
                result,
                Vec::new(),
            ))
        }
        _ => unreachable!("the format contract admits only text and json"),
    }
}

pub(crate) fn stats_table(table: CliStatsTable) -> output::stats::Table {
    match table {
        CliStatsTable::Conversations => output::stats::Table::Conversations,
        CliStatsTable::Endpoints => output::stats::Table::Endpoints,
        CliStatsTable::Protocols => output::stats::Table::Protocols,
        CliStatsTable::Ports => output::stats::Table::Ports,
        CliStatsTable::Io => output::stats::Table::Io,
    }
}

fn render_text(
    table: CliStatsTable,
    report: &analysis::stats::StatsReport,
    summary: &analysis::Summary,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "matched {} of {} frame(s), {} byte(s)",
        report.frames, summary.frames_read, report.bytes
    ))?;
    match table {
        CliStatsTable::Conversations => {
            for row in &report.conversations {
                write_stdout_line(format_args!(
                    "{} stream {}: {} <-> {} frames {} ({} fwd / {} rev) bytes {} ({} fwd / {} rev) duration {:?}",
                    row.transport.as_str(),
                    row.stream,
                    SocketAddr::new(row.address_a, row.port_a),
                    SocketAddr::new(row.address_b, row.port_b),
                    row.frames_a_to_b + row.frames_b_to_a,
                    row.frames_a_to_b,
                    row.frames_b_to_a,
                    row.bytes_a_to_b + row.bytes_b_to_a,
                    row.bytes_a_to_b,
                    row.bytes_b_to_a,
                    row.duration(),
                ))?;
            }
        }
        CliStatsTable::Endpoints => {
            for row in &report.endpoints {
                write_stdout_line(format_args!(
                    "{}: tx {} frame(s) {} byte(s), rx {} frame(s) {} byte(s)",
                    row.address, row.tx_frames, row.tx_bytes, row.rx_frames, row.rx_bytes,
                ))?;
            }
        }
        CliStatsTable::Protocols => {
            for row in &report.protocols {
                write_stdout_line(format_args!(
                    "{}: frames {} ({:.1}%) bytes {}",
                    row.protocol,
                    row.frames,
                    percent(row.frames, report.frames),
                    row.bytes,
                ))?;
            }
        }
        CliStatsTable::Ports => {
            for row in &report.ports {
                write_stdout_line(format_args!(
                    "{} {}: frames {} bytes {}",
                    row.transport.as_str(),
                    row.port,
                    row.frames,
                    row.bytes,
                ))?;
            }
        }
        CliStatsTable::Io => {
            for row in &report.io {
                write_stdout_line(format_args!(
                    "+{:?}: frames {} bytes {}",
                    row.offset, row.frames, row.bytes,
                ))?;
            }
        }
    }
    Ok(())
}

#[expect(
    clippy::cast_precision_loss,
    reason = "counter magnitudes that exceed the f64 mantissa are far beyond any capture this \
              renders, and the result is a display percentage"
)]
fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64 / whole as f64) * 100.0
    }
}
