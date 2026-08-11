// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{core, output};

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, comma_separated, emit_stream_record, emit_stream_with_stats,
    optional_display, output_timestamp_text, render_diagnostics_text, render_optional,
    write_stdout_line,
};

pub(super) fn render_scan_text(
    result: output::scan::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "target={} resolved={}",
        result.target,
        comma_separated(&result.resolved_addresses)
    ))?;
    for port in &result.ports {
        let destination = port
            .evidence
            .first()
            .map(|evidence| evidence.destination)
            .ok_or_else(|| CliError::new(70, "scan endpoint has no attempt evidence"))?;
        let endpoint = if port.transport == "icmp" {
            "icmp".to_owned()
        } else {
            format!("{}/{}", port.transport, port.port)
        };
        write_stdout_line(format_args!(
            "{} {} classification={}",
            destination,
            endpoint,
            scan_classification_name(port.classification)
        ))?;
        for evidence in &port.evidence {
            write_stdout_line(format_args!(
                "  attempt={} status={} classification={} sent={} received={} responder={} latency={} reason={}",
                evidence.attempt,
                scan_probe_status_name(evidence.status),
                scan_classification_name(evidence.classification),
                output_timestamp_text(evidence.sent_at),
                render_optional(evidence.received_at, output_timestamp_text),
                optional_display(evidence.responder),
                render_optional(evidence.latency, |value| format!("{value:?}")),
                evidence.reason,
            ))?;
            if let Some(frame) = &evidence.frame {
                write_stdout_line(format_args!("    frame {}", captured_frame_text(frame)))?;
            }
        }
    }
    for frame in &result.undecoded {
        write_stdout_line(format_args!("undecoded {}", captured_frame_text(frame)))?;
    }
    write_stdout_line(format_args!(
        "scanned {} endpoint(s) with {} completed probe(s), {} byte(s)",
        result.ports.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

pub(super) fn scan_classification_name(value: output::scan::Classification) -> &'static str {
    match value {
        output::scan::Classification::Open => "open",
        output::scan::Classification::Closed => "closed",
        output::scan::Classification::Filtered => "filtered",
        output::scan::Classification::Unreachable => "unreachable",
        output::scan::Classification::Unknown => "unknown",
        output::scan::Classification::Timeout => "timeout",
    }
}

pub(super) fn scan_probe_status_name(value: output::scan::ProbeStatus) -> &'static str {
    match value {
        output::scan::ProbeStatus::Response => "response",
        output::scan::ProbeStatus::Timeout => "timeout",
    }
}

pub(super) fn render_scan_stream(
    result: output::scan::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    let output::scan::Result {
        target,
        resolved_addresses,
        ports,
        undecoded,
    } = result;
    let mut sequence = 0_u64;
    for port in ports {
        let resolved_address = port
            .evidence
            .first()
            .map(|evidence| evidence.destination)
            .ok_or_else(|| {
                CliError::new(70, "scan endpoint has no attempt evidence").at_sequence(sequence)
            })?;
        emit_stream_record(
            output::contract::Command::Scan,
            &mut sequence,
            output::scan::Event::Port {
                target: target.clone(),
                resolved_address,
                port,
            },
        )?;
    }
    for frame in undecoded {
        emit_stream_record(
            output::contract::Command::Scan,
            &mut sequence,
            output::scan::Event::Undecoded { frame },
        )?;
    }
    emit_stream_with_stats(
        output::contract::Command::Scan,
        sequence,
        output::scan::Event::Complete {
            target,
            resolved_addresses,
        },
        diagnostics,
        stats,
    )
}
