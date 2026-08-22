// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{core, output};

use crate::errors::CliError;
use crate::rendering::{
    NdjsonStream, captured_frame_text, comma_separated, emit_aggregate_with_stats,
    optional_display, output_timestamp_text, render_diagnostics_text, render_optional,
    write_stdout_line,
};

pub(super) fn render_aggregate(
    result: output::scan::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    emit_aggregate_with_stats(output::contract::Command::Scan, result, diagnostics, stats)
}

pub(super) fn render_text(
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
            classification_name(endpoint.classification)
        ))?;
        for evidence in &endpoint.probes {
            write_stdout_line(format_args!(
                "  sequence={} attempt={} status={} classification={} sent={} received={} responder={} latency={} reason={}",
                evidence.sequence,
                evidence.attempt,
                probe_status_name(evidence.status),
                classification_name(evidence.classification),
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

fn classification_name(value: output::scan::Classification) -> &'static str {
    match value {
        output::scan::Classification::Open => "open",
        output::scan::Classification::Closed => "closed",
        output::scan::Classification::Filtered => "filtered",
        output::scan::Classification::Unreachable => "unreachable",
        output::scan::Classification::Unknown => "unknown",
        output::scan::Classification::Timeout => "timeout",
    }
}

fn probe_status_name(value: output::scan::ProbeStatus) -> &'static str {
    match value {
        output::scan::ProbeStatus::Response => "response",
        output::scan::ProbeStatus::Timeout => "timeout",
    }
}

pub(super) fn render_event(
    event: packetcraftr::scan::Event,
    stream: &NdjsonStream,
) -> Result<(), CliError> {
    let (event, diagnostics) =
        output::scan::Event::try_from_scan(event).map_err(CliError::classified)?;
    stream.emit_data(event, diagnostics)
}

pub(super) fn render_complete(
    summary: packetcraftr::scan::Summary,
    stream: &NdjsonStream,
) -> Result<(), CliError> {
    let (event, diagnostics, stats) = output::scan::Event::complete_from_scan(summary);
    stream.complete_with_stats(event, diagnostics, stats)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::UNIX_EPOCH;

    use packetcraftr::scan;

    use super::*;
    use crate::rendering::ndjson_test_support::{assert_contiguous, stream};

    fn probe_event(sequence: u64, port: u16) -> scan::Event {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        scan::Event::Probe {
            target: address.to_string().into(),
            probe: scan::ProbeEvidence {
                sequence,
                address,
                transport: scan::Transport::Tcp,
                port: Some(port),
                attempt: 1,
                status: scan::ProbeStatus::Timeout,
                classification: scan::Classification::Timeout,
                responder: None,
                sent_at: UNIX_EPOCH,
                received_at: None,
                latency: None,
                response: None,
                reason: "timeout".to_owned(),
            },
        }
    }

    fn summary() -> scan::Summary {
        scan::Summary {
            target: "192.0.2.10".to_owned(),
            resolved_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))],
            diagnostics: Vec::new(),
            stats: packetcraftr::Stats::default(),
        }
    }

    #[test]
    fn scan_stream_positions_ignore_probe_ids_and_end_once() {
        let (sink, output) = stream(output::contract::Command::Scan);
        render_event(probe_event(70_000, 80), &sink).unwrap();
        render_event(probe_event(9, 81), &sink).unwrap();
        render_complete(summary(), &sink).unwrap();

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["result"]["probe"]["sequence"], 70_000);
        assert_eq!(records[1]["result"]["probe"]["sequence"], 9);
        assert_eq!(records[2]["result"]["event"], "complete");
        assert_eq!(
            records
                .iter()
                .filter(|record| record["result"]["event"] == "complete")
                .count(),
            1
        );
    }
}
