// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use std::net::SocketAddr;
use std::time::Duration;

use packetcraftr::{analysis, output};

use self::arguments::{CliStatsTable, StatsArgs};
use super::super::errors::CliError;
use super::super::rendering::{emit_json, write_stdout_line};
use super::offline_analysis::{
    PreparedOfflineAnalysis, open_offline_reader, prepare_offline_analysis,
};

pub(super) fn run(arguments: StatsArgs, output: output::contract::Format) -> Result<(), CliError> {
    // The format contract is enforced before any input is read, so asking
    // for an unsupported encoding never pays for a full analysis pass.
    output::contract::Command::Stats
        .require_format(output)
        .map_err(CliError::classified)?;
    // Stats assigns conversation indices, so stream-aware filters like
    // `tcp.stream == 7` are supported here.
    let PreparedOfflineAnalysis {
        registry,
        filter,
        limits,
    } = prepare_offline_analysis(arguments.limits, arguments.filter.as_deref())?;
    let mut collector =
        analysis::stats::StatsCollector::new(Duration::from_millis(arguments.interval_ms))
            .map_err(CliError::classified)?;

    let mut reader = open_offline_reader(&arguments.path, arguments.limits.capture)?;

    let options = analysis::Options {
        filter: filter.as_ref(),
        tcp_events: false,
        limits,
    };
    let summary = analysis::run(&mut reader, registry, &options, |record| {
        collector
            .observe(&record)
            .expect("the analysis pipeline supplies timestamped statistics records");
        Ok(())
    })
    .map_err(CliError::classified)?;
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

fn stats_table(table: CliStatsTable) -> output::stats::Table {
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
