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
    for endpoint in &result.endpoints {
        let endpoint_name = if endpoint.transport == "icmp" {
            "icmp".to_owned()
        } else {
            format!("{}/{}", endpoint.transport, optional_display(endpoint.port))
        };
        write_stdout_line(format_args!(
            "{} {} classification={}",
            endpoint.address,
            endpoint_name,
            scan_classification_name(endpoint.classification)
        ))?;
        for evidence in &endpoint.evidence {
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
        result.endpoints.len(),
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
        endpoints,
        undecoded,
    } = result;
    let mut sequence = 0_u64;
    for endpoint in endpoints {
        emit_stream_record(
            output::contract::Command::Scan,
            &mut sequence,
            output::scan::Event::Endpoint {
                target: target.clone(),
                endpoint,
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
