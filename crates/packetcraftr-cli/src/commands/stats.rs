// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::time::Duration;

use packetcraftr::{analysis, output};

use super::super::arguments::{CliStatsTable, StatsArgs};
use super::super::errors::{CliError, analysis_cli_error};
use super::super::rendering::{emit_json, write_stdout_line};
use super::offline_analysis::{
    PreparedOfflineAnalysis, open_offline_reader, prepare_offline_analysis,
};

pub(crate) fn run_stats(
    arguments: StatsArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    output::contract::Command::Stats
        .require_format(output)
        .map_err(CliError::classified)?;
    let PreparedOfflineAnalysis {
        registry,
        filter,
        limits,
    } = prepare_offline_analysis(arguments.limits, arguments.filter.as_deref())?;
    let mut collector =
        analysis::stats::StatsCollector::new(Duration::from_millis(arguments.interval_ms))
            .map_err(analysis_cli_error)?;
    let mut reader = open_offline_reader(&arguments.path, arguments.limits.capture)?;
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
        CliStatsTable::ServiceResponseTime => output::stats::Table::ServiceResponseTime,
        CliStatsTable::Lengths => output::stats::Table::Lengths,
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
                    row.frames_a_to_b.saturating_add(row.frames_b_to_a),
                    row.frames_a_to_b,
                    row.frames_b_to_a,
                    row.bytes_a_to_b.saturating_add(row.bytes_b_to_a),
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
        CliStatsTable::Lengths => {
            let lengths = &report.lengths;
            write_stdout_line(format_args!(
                "lengths: frames {} minimum {:?} maximum {:?} mean {:?}",
                lengths.frames, lengths.minimum, lengths.maximum, lengths.mean
            ))?;
            for bucket in &lengths.buckets {
                let upper = bucket
                    .upper_bound
                    .map_or_else(|| "+inf".to_owned(), |upper| upper.to_string());
                write_stdout_line(format_args!(
                    "  [{}, {}): frames {} ({:.1}%)",
                    bucket.lower_bound,
                    upper,
                    bucket.frames,
                    percent(bucket.frames, lengths.frames)
                ))?;
            }
        }
        CliStatsTable::ServiceResponseTime => {
            for row in &report.service_response_time {
                write_stdout_line(format_args!(
                    "{} service port {}: request bursts {} samples {} unanswered {} orphan {} regressions {}",
                    row.transport.as_str(),
                    row.service_port,
                    row.request_bursts,
                    row.samples,
                    row.unanswered_requests,
                    row.orphan_responses,
                    row.timestamp_regressions
                ))?;
                write_stdout_line(format_args!(
                    "  minimum {} maximum {} mean {}",
                    format_optional_duration(row.minimum, "-"),
                    format_optional_duration(row.maximum, "-"),
                    format_optional_duration(row.mean, "-")
                ))?;
                for bucket in &row.buckets {
                    write_stdout_line(format_args!(
                        "  [{:?}, {}): samples {} ({:.1}%)",
                        bucket.lower_bound,
                        format_optional_duration(bucket.upper_bound, "+inf"),
                        bucket.samples,
                        percent(bucket.samples, row.samples)
                    ))?;
                }
            }
        }
    }
    Ok(())
}

fn format_optional_duration(duration: Option<Duration>, absent: &str) -> String {
    duration.map_or_else(|| absent.to_owned(), |duration| format!("{duration:?}"))
}

#[expect(
    clippy::cast_precision_loss,
    reason = "counter magnitudes that exceed the f64 mantissa are far beyond any capture this renders, and the result is a display percentage"
)]
fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64 / whole as f64) * 100.0
    }
}
