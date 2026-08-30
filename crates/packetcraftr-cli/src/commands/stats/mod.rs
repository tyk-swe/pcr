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
use super::format::AggregateFormat;
use super::offline_analysis::prepare;

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    let format = AggregateFormat::narrow(output::contract::Command::Stats, format)?;
    // Stats assigns conversation indices, so stream-aware filters like
    // `tcp.stream == 7` are supported here.
    let prepared = prepare(arguments.limits, arguments.filter.as_deref())?;
    let mut collector =
        analysis::stats::Collector::new(Duration::from_millis(arguments.interval_ms))
            .map_err(CliError::classified)?;

    let mut reader = open_capture(&arguments.path, arguments.limits.capture)?;

    let options = prepared.options(false);
    let summary = analysis::run(&mut reader, prepared.registry.clone(), &options, |record| {
        collector
            .observe(&record)
            .expect("the analysis pipeline supplies timestamped statistics records");
        Ok(())
    })
    .map_err(CliError::classified)?;
    let frames_read = summary.frames_read;
    let report = collector.finish(summary.ip_reassembly);

    match format {
        AggregateFormat::Text => render_text(arguments.table, &report, frames_read),
        AggregateFormat::Json => {
            let result = output::stats::Result::try_from_report(
                arguments.table.into(),
                &report,
                frames_read,
            )
            .map_err(CliError::classified)?;
            emit_aggregate(output::contract::Command::Stats, result, Vec::new())
        }
    }
}

fn render_text(
    table: Table,
    report: &analysis::stats::Report,
    frames_read: u64,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "matched {} of {} frame(s), {} byte(s)",
        report.frames, frames_read, report.bytes
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
        Table::Fragments => render_fragments(&report.ip_reassembly)?,
    }
    Ok(())
}

fn render_fragments(report: &analysis::IpReassemblyReport) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "fragment accounting is capture-global; display filters apply only downstream, and derived bytes are excluded from physical matched totals"
    ))?;
    for (family, counters) in [
        ("ipv4", &report.counters.ipv4),
        ("ipv6", &report.counters.ipv6),
    ] {
        write_stdout_line(format_args!(
            "{family}: physical fragments {} (atomic {}, admitted {}, duplicate {}, overlap-resolved {}, completing {}), datagrams {} complete / {} incomplete ({} idle-expired / {} end-of-capture), overlap bytes {}, derived datagram bytes {}, derived payload bytes {}",
            counters.physical_fragments,
            counters.atomic_fragments,
            counters.admitted_fragments,
            counters.duplicate_fragments,
            counters.overlap_resolved_fragments,
            counters.completing_fragments,
            counters.completed_datagrams,
            counters.incomplete_datagrams,
            counters.idle_expired_datagrams,
            counters.end_of_capture_datagrams,
            counters.overlap_bytes,
            counters.derived_datagram_bytes,
            counters.derived_payload_bytes,
        ))?;
    }
    for outcome in &report.outcomes {
        match outcome {
            analysis::IpDatagramOutcome::Completed {
                key,
                fragment_count,
                unique_bytes,
                final_payload_length,
                datagram_bytes,
                duplicate_fragments,
                overlap_bytes,
            } => write_stdout_line(format_args!(
                "{}: complete, fragments {}, unique bytes {}, final payload bytes {}, datagram bytes {}, duplicate fragments {}, overlap bytes {}",
                output::reassembly::DatagramKey::from(key),
                fragment_count,
                unique_bytes,
                final_payload_length,
                datagram_bytes,
                duplicate_fragments,
                overlap_bytes,
            ))?,
            analysis::IpDatagramOutcome::Incomplete {
                key,
                reason,
                fragment_count,
                unique_bytes,
                known_final_length,
                duplicate_fragments,
                overlap_bytes,
            } => write_stdout_line(format_args!(
                "{}: incomplete ({}), fragments {}, unique bytes {}, known final payload bytes {}, duplicate fragments {}, overlap bytes {}",
                output::reassembly::DatagramKey::from(key),
                output::reassembly::IncompleteReason::from(*reason),
                fragment_count,
                unique_bytes,
                known_final_length
                    .map_or_else(|| "unknown".to_owned(), |length| length.to_string()),
                duplicate_fragments,
                overlap_bytes,
            ))?,
        }
    }
    if report.outcomes_omitted != 0 {
        write_stdout_line(format_args!(
            "{} additional datagram outcome(s) omitted by the retention ceiling",
            report.outcomes_omitted
        ))?;
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
