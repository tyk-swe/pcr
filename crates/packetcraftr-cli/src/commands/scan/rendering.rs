// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{output, packet};

use crate::errors::CliError;
use crate::rendering::{
    emit_json_compact, emit_stream_record, output_timestamp_text, render_diagnostics_text,
    spaced_hex, write_stdout_line,
};

pub(super) fn render_scan_text(
    result: output::scan::Result,
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "target={} resolved={}",
        result.target,
        result
            .resolved_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
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
                evidence
                    .received_at
                    .map(output_timestamp_text)
                    .unwrap_or_else(|| "none".to_owned()),
                evidence
                    .responder
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                evidence
                    .latency
                    .map(|value| format!("{value:?}"))
                    .unwrap_or_else(|| "none".to_owned()),
                evidence.reason,
            ))?;
            if let Some(frame) = &evidence.frame {
                write_stdout_line(format_args!(
                    "    frame dlt={} caplen={} wirelen={} {}",
                    frame.link_type,
                    frame.captured_length,
                    frame.original_length,
                    spaced_hex(frame.bytes())
                ))?;
            }
        }
    }
    for frame in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded dlt={} caplen={} wirelen={} {}",
            frame.link_type,
            frame.captured_length,
            frame.original_length,
            spaced_hex(frame.bytes())
        ))?;
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
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
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
    emit_json_compact(
        &output::envelope::Stream::success(
            output::contract::Command::Scan,
            sequence,
            output::scan::Event::Complete {
                target,
                resolved_addresses,
            },
            diagnostics,
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        render_scan_stream, render_scan_text, scan_classification_name, scan_probe_status_name,
    };
    use crate::rendering::capture_stdout;
    use packetcraftr::output::{
        envelope::Stats,
        scan::{Classification, Evidence, Port, ProbeStatus, Result as ScanResult, Timestamp},
    };

    fn evidence() -> Evidence {
        Evidence {
            protocol: "tcp".to_owned(),
            destination: "192.0.2.1".parse().unwrap(),
            destination_port: Some(443),
            attempt: 2,
            status: ProbeStatus::Response,
            classification: Classification::Open,
            responder: Some("192.0.2.1".parse().unwrap()),
            sent_at: Timestamp {
                unix_seconds: -1,
                nanoseconds: 500_000_000,
            },
            received_at: Some(Timestamp {
                unix_seconds: 0,
                nanoseconds: 0,
            }),
            latency: Some(Duration::from_millis(5)),
            frame: None,
            reason: "SYN-ACK".to_owned(),
        }
    }

    fn result() -> ScanResult {
        ScanResult {
            target: "example.test".to_owned(),
            resolved_addresses: vec!["192.0.2.1".parse().unwrap()],
            ports: vec![
                Port {
                    port: 443,
                    transport: "tcp".to_owned(),
                    classification: Classification::Open,
                    evidence: vec![evidence()],
                },
                Port {
                    port: 0,
                    transport: "icmp".to_owned(),
                    classification: Classification::Timeout,
                    evidence: vec![Evidence {
                        protocol: "icmpv4".to_owned(),
                        destination_port: None,
                        status: ProbeStatus::Timeout,
                        classification: Classification::Timeout,
                        responder: None,
                        received_at: None,
                        latency: None,
                        reason: "timeout".to_owned(),
                        ..evidence()
                    }],
                },
            ],
            undecoded: Vec::new(),
        }
    }

    #[test]
    fn scan_text_names_cover_every_public_enum_variant() {
        for (value, expected) in [
            (Classification::Open, "open"),
            (Classification::Closed, "closed"),
            (Classification::Filtered, "filtered"),
            (Classification::Unreachable, "unreachable"),
            (Classification::Unknown, "unknown"),
            (Classification::Timeout, "timeout"),
        ] {
            assert_eq!(scan_classification_name(value), expected);
        }
        assert_eq!(scan_probe_status_name(ProbeStatus::Response), "response");
        assert_eq!(scan_probe_status_name(ProbeStatus::Timeout), "timeout");
    }

    #[test]
    fn scan_text_and_stream_render_all_optional_evidence_shapes() {
        let stats = Stats {
            packets_completed: 2,
            bytes: 64,
            ..Stats::default()
        };
        let ((text, stream), rendered) = capture_stdout(|| {
            (
                render_scan_text(result(), Vec::new(), stats.clone()),
                render_scan_stream(result(), Vec::new(), stats),
            )
        });
        assert!(text.is_ok());
        assert!(stream.is_ok());
        let rendered = crate::rendering::terminal_document(&rendered);
        assert!(rendered.contains("icmp classification=timeout"));
        assert!(rendered.contains("\"sequence\":2"));
    }

    #[test]
    fn scan_renderers_reject_endpoints_without_evidence() {
        let result = ScanResult {
            target: "example.test".to_owned(),
            resolved_addresses: vec!["192.0.2.1".parse().unwrap()],
            ports: vec![Port {
                port: 80,
                transport: "tcp".to_owned(),
                classification: Classification::Unknown,
                evidence: Vec::new(),
            }],
            undecoded: Vec::new(),
        };
        let ((text, stream), _) = capture_stdout(|| {
            (
                render_scan_text(result.clone(), Vec::new(), Stats::default()),
                render_scan_stream(result, Vec::new(), Stats::default()),
            )
        });
        let text_error = text.unwrap_err();
        assert_eq!(text_error.exit_code, 70);
        let stream_error = stream.unwrap_err();
        assert_eq!(stream_error.sequence, Some(0));
    }
}
