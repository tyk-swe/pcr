// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::rendering::StreamEncoder;

use packetcraftr_core as core;

use packetcraftr_cli::output;

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, comma_separated, optional_debug, optional_display,
    render_diagnostics_text, render_undecoded, write_stdout_line, write_summary_line,
};

pub(super) fn render_text(
    result: output::scan::Report,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: packetcraftr::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "target={} resolved={}",
        result.target,
        comma_separated(&result.resolved_addresses)
    ))?;
    write_stdout_line(format_args!(
        "planned timeout+pacing {:?}; achieved {:.2} probes/s over {:?}",
        result.planned_duration,
        if stats.elapsed.is_zero() {
            0.0
        } else {
            stats.packets_completed as f64 / stats.elapsed.as_secs_f64()
        },
        stats.elapsed
    ))?;
    for endpoint in &result.endpoints {
        // ICMP has no port, so it names itself; the port-bearing transports
        // name the endpoint they probed.
        let endpoint_name = match endpoint.transport {
            packetcraftr::scan::Transport::Icmp => endpoint.transport.to_string(),
            packetcraftr::scan::Transport::Tcp | packetcraftr::scan::Transport::Udp => {
                format!("{}/{}", endpoint.transport, optional_display(endpoint.port))
            }
        };
        write_stdout_line(format_args!(
            "{} {} classification={}",
            endpoint.address,
            endpoint_name,
            endpoint.classification.as_str()
        ))?;
        for evidence in &endpoint.probes {
            write_stdout_line(format_args!(
                "  sequence={} attempt={} status={} classification={} sent={} received={} responder={} latency={} reason={}",
                evidence.sequence,
                evidence.attempt,
                evidence.status.as_str(),
                evidence.classification.as_str(),
                evidence.sent_at,
                optional_display(evidence.received_at),
                optional_display(evidence.responder),
                optional_debug(evidence.latency),
                evidence.reason,
            ))?;
            if let Some(frame) = &evidence.frame {
                write_stdout_line(format_args!("    frame {}", captured_frame_text(frame)))?;
            }
        }
    }
    render_undecoded(result.undecoded.iter().map(|frame| (None, frame)))?;
    write_summary_line(format_args!(
        "scanned {} endpoint(s) with {} completed probe(s), {} byte(s)",
        result.endpoints.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

/// Converts and writes one final workflow event at its publication boundary.
pub(super) fn emit_event(
    event: packetcraftr::scan::Event,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let (record, diagnostics) =
        output::scan::Event::try_from_scan(event).map_err(CliError::classified)?;
    Ok(stream.emit_data(record, diagnostics)?)
}

pub(super) fn emit_complete(
    summary: packetcraftr::scan::Summary,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let (record, diagnostics, stats) = output::scan::Event::complete_from_scan(summary);
    Ok(stream.complete_with_stats(record, diagnostics, stats)?)
}

#[cfg(test)]
mod tests {

    use std::net::{IpAddr, Ipv4Addr};
    use std::time::UNIX_EPOCH;

    use packetcraftr::scan;

    use super::*;
    use crate::rendering::ndjson_test_support::{assert_contiguous, stream};
    use crate::test_support::assert_single_complete;

    fn probe_event(sequence: u64, port: u16) -> scan::Event {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        scan::Event::Probe {
            target: address.to_string().into(),
            probe: scan::ProbeEvidence {
                sequence,
                address,
                transport: packetcraftr::scan::Transport::Tcp,
                port: Some(port),
                attempt: 1,
                status: packetcraftr::scan::ProbeStatus::Timeout,
                classification: packetcraftr::scan::Classification::Timeout,
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
            planned_duration: std::time::Duration::ZERO,
            target: "192.0.2.10".to_owned(),
            resolved_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))],
            counts: packetcraftr::scan::ClassificationCounts {
                timeout: 2,
                ..packetcraftr::scan::ClassificationCounts::default()
            },
            stats: packetcraftr::Stats::default(),
        }
    }

    #[test]
    fn scan_stream_positions_ignore_probe_ids_and_end_once() {
        let (sink, output) = stream(output::contract::Command::Scan);
        emit_event(probe_event(70_000, 80), &sink).unwrap();
        emit_event(probe_event(9, 81), &sink).unwrap();
        emit_complete(summary(), &sink).unwrap();

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["result"]["probe"]["sequence"], 70_000);
        assert_eq!(records[1]["result"]["probe"]["sequence"], 9);
        assert_eq!(records[2]["event"], "complete");
        assert_eq!(records[2]["result"]["counts"]["timeout"], 2);
        assert_single_complete(&records);
    }
}
