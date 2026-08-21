// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use std::net::SocketAddr;
use std::time::Duration;

use packetcraftr::{analysis, output};

use self::arguments::{Args, Table};
use super::super::errors::CliError;
use super::super::input::open_capture;
use super::super::rendering::{emit_aggregate, write_stdout_line};
use super::offline_analysis::{Prepared, prepare};

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    // Stats assigns conversation indices, so stream-aware filters like
    // `tcp.stream == 7` are supported here.
    let Prepared {
        registry,
        filter,
        limits,
    } = prepare(arguments.limits, arguments.filter.as_deref())?;
    let mut collector =
        analysis::stats::Collector::new(Duration::from_millis(arguments.interval_ms))
            .map_err(CliError::classified)?;

    let mut reader = open_capture(&arguments.path, arguments.limits.capture)?;

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

    match format {
        output::contract::Format::Text => render_text(arguments.table, &report, &summary),
        output::contract::Format::Json => {
            let result = output::stats::Result::try_from_report(
                arguments.table.into(),
                &report,
                summary.frames_read,
            )
            .map_err(CliError::classified)?;
            emit_aggregate(output::contract::Command::Stats, result, Vec::new())
        }
        _ => unreachable!("the format contract admits only text and json"),
    }
}

fn render_text(
    table: Table,
    report: &analysis::stats::Report,
    summary: &analysis::Summary,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "matched {} of {} frame(s), {} byte(s)",
        report.frames, summary.frames_read, report.bytes
    ))?;
    match table {
        Table::Conversations => {
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
        Table::Endpoints => {
            for row in &report.endpoints {
                write_stdout_line(format_args!(
                    "{}: tx {} frame(s) {} byte(s), rx {} frame(s) {} byte(s)",
                    row.address, row.tx_frames, row.tx_bytes, row.rx_frames, row.rx_bytes,
                ))?;
            }
        }
        Table::Protocols => {
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
        Table::Ports => {
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
        Table::Io => {
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
