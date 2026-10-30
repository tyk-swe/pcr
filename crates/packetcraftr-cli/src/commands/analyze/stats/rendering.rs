// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;

use packetcraftr_core as core;
use packetcraftr_core::analysis;

use crate::errors::CliError;
use crate::output::stats::Table;
use crate::rendering::{
    duration_text, render_diagnostics_text, render_optional, write_stdout_line, write_summary_line,
};

pub(super) fn render_text(
    invocation: &crate::invocation::Invocation,
    table: Table,
    report: &analysis::stats::Report,
    frames_read: u64,
    diagnostics: &[core::diagnostic::Diagnostic],
    presentation: crate::invocation::Presentation,
) -> Result<(), CliError> {
    write_summary_line(
        invocation,
        format_args!(
            "matched {} of {} frame(s), {} byte(s)",
            report.frames, frames_read, report.bytes
        ),
    )?;
    if let Some(duration) = report.duration() {
        let average = report.average_packet_size().unwrap_or_default();
        match report.packet_rate().zip(report.byte_rate()) {
            Some((packets, bytes)) => write_stdout_line(
                invocation,
                format_args!(
                    "duration {}; {packets:.3} frame(s)/s, {bytes:.3} byte(s)/s; average packet size {average:.3} byte(s)",
                    duration_text(duration)
                ),
            )?,
            None => write_stdout_line(
                invocation,
                format_args!(
                    "duration {}; rates unavailable (zero span); average packet size {average:.3} byte(s)",
                    duration_text(duration)
                ),
            )?,
        }
    }
    if presentation.verbose {
        for (id, interface) in report.interfaces.iter().enumerate() {
            write_stdout_line(
                invocation,
                format_args!(
                    "interface {id}: link-type {} snaplen {}",
                    interface.link_type.0, interface.snap_len,
                ),
            )?;
        }
        crate::rendering::render_clock(invocation, &report.clock)?;
    } else if report.clock.regressions > 0 {
        crate::rendering::render_clock(invocation, &report.clock)?;
    }
    match table {
        Table::Conversations => {
            for row in &report.conversations {
                crate::rendering::render_scope(invocation, &row.scope)?;
                write_stdout_line(
                    invocation,
                    format_args!(
                        "{} stream {}: {} <-> {} frames {} ({} fwd / {} rev) bytes {} ({} fwd / {} rev) duration {}",
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
                        duration_text(row.duration()),
                    ),
                )?;
            }
        }
        Table::Endpoints => {
            crate::rendering::table_row(
                invocation,
                &[
                    ("ADDRESS", 39),
                    ("TX FRAMES", 12),
                    ("TX BYTES", 12),
                    ("RX FRAMES", 12),
                    ("RX BYTES", 12),
                ],
            )?;
            for row in &report.endpoints {
                crate::rendering::table_row(
                    invocation,
                    &[
                        (&row.address.to_string(), 39),
                        (&row.tx_frames.to_string(), 12),
                        (&row.tx_bytes.to_string(), 12),
                        (&row.rx_frames.to_string(), 12),
                        (&row.rx_bytes.to_string(), 12),
                    ],
                )?;
            }
        }
        Table::Protocols => {
            crate::rendering::table_row(
                invocation,
                &[
                    ("PROTOCOL", 16),
                    ("FRAMES", 12),
                    ("SHARE", 8),
                    ("BYTES", 12),
                ],
            )?;
            for row in &report.protocols {
                crate::rendering::table_row(
                    invocation,
                    &[
                        (&row.protocol.to_string(), 16),
                        (&row.frames.to_string(), 12),
                        (&format!("{:.1}%", percent(row.frames, report.frames)), 8),
                        (&row.bytes.to_string(), 12),
                    ],
                )?;
            }
        }
        Table::Ports => {
            for row in &report.ports {
                write_stdout_line(
                    invocation,
                    format_args!(
                        "{} {}: frames {} bytes {}",
                        row.transport.as_str(),
                        row.port,
                        row.frames,
                        row.bytes,
                    ),
                )?;
            }
        }
        Table::Io => {
            write_stdout_line(
                invocation,
                format_args!(
                    "bucket origin {}; {} earlier frame(s) clamped to bucket zero",
                    render_optional(
                        report
                            .io_origin
                            .map(crate::output::frame::Timestamp::try_from)
                            .transpose()?,
                        |value| value.to_string()
                    ),
                    report.io_underflow_frames
                ),
            )?;
            for row in &report.io {
                write_stdout_line(
                    invocation,
                    format_args!(
                        "+{}: frames {} bytes {}",
                        duration_text(row.offset),
                        row.frames,
                        row.bytes,
                    ),
                )?;
            }
        }
        Table::Fragments => render_fragments(invocation, &report.ip_reassembly)?,
        Table::Overview => {
            write_stdout_line(
                invocation,
                format_args!(
                    "timestamps {} to {}; {} interface(s)",
                    render_optional(
                        report
                            .first_timestamp
                            .map(crate::output::frame::Timestamp::try_from)
                            .transpose()?,
                        |value| value.to_string()
                    ),
                    render_optional(
                        report
                            .last_timestamp
                            .map(crate::output::frame::Timestamp::try_from)
                            .transpose()?,
                        |value| value.to_string()
                    ),
                    report.interfaces.len(),
                ),
            )?;
            write_stdout_line(
                invocation,
                format_args!(
                    "{} protocol(s), {} endpoint(s), {} conversation(s)",
                    report.protocol_count, report.endpoint_count, report.conversation_count,
                ),
            )?;
            for row in &report.protocols {
                write_stdout_line(
                    invocation,
                    format_args!(
                        "protocol {}: frames {} bytes {}",
                        row.protocol, row.frames, row.bytes
                    ),
                )?;
            }
            for row in &report.endpoints {
                write_stdout_line(
                    invocation,
                    format_args!(
                        "endpoint {}: frames {} bytes {}",
                        row.address,
                        row.tx_frames.saturating_add(row.rx_frames),
                        row.tx_bytes.saturating_add(row.rx_bytes)
                    ),
                )?;
            }
            for row in &report.conversations {
                crate::rendering::render_scope(invocation, &row.scope)?;
                write_stdout_line(
                    invocation,
                    format_args!(
                        "conversation {} stream {}: {} <-> {} frames {} bytes {}",
                        row.transport.as_str(),
                        row.stream,
                        SocketAddr::new(row.address_a, row.port_a),
                        SocketAddr::new(row.address_b, row.port_b),
                        row.frames_a_to_b.saturating_add(row.frames_b_to_a),
                        row.bytes_a_to_b.saturating_add(row.bytes_b_to_a)
                    ),
                )?;
            }
        }
    }
    render_diagnostics_text(invocation, diagnostics)
}

fn render_fragments(
    invocation: &crate::invocation::Invocation,
    report: &analysis::IpReassemblyReport,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
            "fragment accounting is capture-global; display filters apply only downstream, and derived bytes are excluded from physical matched totals"
        ),
    )?;
    for (family, counters) in [
        ("ipv4", &report.counters.ipv4),
        ("ipv6", &report.counters.ipv6),
    ] {
        write_stdout_line(
            invocation,
            format_args!(
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
            ),
        )?;
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
            } => write_stdout_line(
                invocation,
                format_args!(
                    "{}: complete, fragments {}, unique bytes {}, final payload bytes {}, datagram bytes {}, duplicate fragments {}, overlap bytes {}",
                    key,
                    fragment_count,
                    unique_bytes,
                    final_payload_length,
                    datagram_bytes,
                    duplicate_fragments,
                    overlap_bytes,
                ),
            )?,
            analysis::IpDatagramOutcome::Incomplete(datagram) => write_stdout_line(
                invocation,
                format_args!(
                    "{}: incomplete ({}), fragments {}, unique bytes {}, known final payload bytes {}, duplicate fragments {}, overlap bytes {}",
                    datagram.key,
                    datagram.reason,
                    datagram.fragment_count,
                    datagram.unique_bytes,
                    datagram
                        .known_final_length
                        .map_or_else(|| "unknown".to_owned(), |length| length.to_string()),
                    datagram.duplicate_fragments,
                    datagram.overlap_bytes,
                ),
            )?,
        }
    }
    if report.outcomes_omitted != 0 {
        write_stdout_line(
            invocation,
            format_args!(
                "{} additional datagram outcome(s) omitted by the retention ceiling",
                report.outcomes_omitted
            ),
        )?;
    }
    Ok(())
}

fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64 / whole as f64) * 100.0
    }
}
