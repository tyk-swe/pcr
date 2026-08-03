// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{output, packet};

use crate::errors::CliError;
use crate::rendering::{
    emit_json_compact, emit_stream_record, output_timestamp_text, render_diagnostics_text,
    spaced_hex, write_stdout_line,
};

pub(super) fn render_traceroute_text(
    result: output::traceroute::Result,
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "target={} resolved={} destination={} strategy={} port={}",
        result.target,
        result
            .resolved_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        result.destination,
        result.strategy,
        result
            .destination_port
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
    ))?;
    for hop in &result.hops {
        write_stdout_line(format_args!("hop={}", hop.hop_limit))?;
        for probe in &hop.probes {
            write_stdout_line(format_args!(
                "  sequence={} attempt={} status={} response={} sent={} received={} responder={} latency={} port={} reason={}",
                probe.sequence,
                probe.attempt,
                trace_probe_status_name(probe.status),
                probe
                    .response_kind
                    .map(trace_response_kind_name)
                    .unwrap_or("none"),
                output_timestamp_text(probe.sent_at),
                probe
                    .received_at
                    .map(output_timestamp_text)
                    .unwrap_or_else(|| "none".to_owned()),
                probe
                    .responder
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                probe
                    .latency
                    .map(|value| format!("{value:?}"))
                    .unwrap_or_else(|| "none".to_owned()),
                probe
                    .destination_port
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                probe.reason,
            ))?;
            if let Some(frame) = &probe.frame {
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
    for evidence in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded hop={} dlt={} caplen={} wirelen={} {}",
            evidence.hop_limit,
            evidence.frame.link_type,
            evidence.frame.captured_length,
            evidence.frame.original_length,
            spaced_hex(evidence.frame.bytes())
        ))?;
    }
    write_stdout_line(format_args!(
        "trace completion={} hops={} probes={} bytes={}",
        trace_completion_name(result.completion),
        result.hops.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

pub(super) fn trace_probe_status_name(value: output::traceroute::ProbeStatus) -> &'static str {
    match value {
        output::traceroute::ProbeStatus::Response => "response",
        output::traceroute::ProbeStatus::Timeout => "timeout",
    }
}

pub(super) fn trace_response_kind_name(value: output::traceroute::ResponseKind) -> &'static str {
    match value {
        output::traceroute::ResponseKind::Intermediate => "intermediate",
        output::traceroute::ResponseKind::DestinationReached => "destination_reached",
        output::traceroute::ResponseKind::Unreachable => "unreachable",
    }
}

pub(super) fn trace_completion_name(value: output::traceroute::Completion) -> &'static str {
    match value {
        output::traceroute::Completion::DestinationReached => "destination_reached",
        output::traceroute::Completion::Unreachable => "unreachable",
        output::traceroute::Completion::MaximumHops => "maximum_hops",
        output::traceroute::Completion::Timeout => "timeout",
    }
}

pub(super) fn render_traceroute_stream(
    result: output::traceroute::Result,
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    let output::traceroute::Result {
        target,
        resolved_addresses,
        destination,
        strategy,
        destination_port,
        hops,
        undecoded,
        completion,
    } = result;
    let mut sequence = 0_u64;
    for hop in hops {
        emit_stream_record(
            output::contract::Command::Traceroute,
            &mut sequence,
            output::traceroute::Event::Hop {
                target: target.clone(),
                destination,
                hop,
            },
        )?;
    }
    for evidence in undecoded {
        emit_stream_record(
            output::contract::Command::Traceroute,
            &mut sequence,
            output::traceroute::Event::Undecoded {
                hop_limit: evidence.hop_limit,
                frame: evidence.frame,
            },
        )?;
    }
    emit_json_compact(
        &output::envelope::Stream::success(
            output::contract::Command::Traceroute,
            sequence,
            output::traceroute::Event::Complete {
                target,
                resolved_addresses,
                destination,
                strategy,
                destination_port,
                completion,
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
        render_traceroute_stream, render_traceroute_text, trace_completion_name,
        trace_probe_status_name, trace_response_kind_name,
    };
    use crate::rendering::capture_stdout;
    use packetcraftr::output::{
        envelope::Stats,
        traceroute::{
            Completion, Hop, Probe, ProbeStatus, ResponseKind, Result as TracerouteResult,
            Timestamp,
        },
    };

    fn result() -> TracerouteResult {
        TracerouteResult {
            target: "example.test".to_owned(),
            resolved_addresses: vec!["192.0.2.9".parse().unwrap()],
            destination: "192.0.2.9".parse().unwrap(),
            strategy: "udp".to_owned(),
            destination_port: Some(33434),
            hops: vec![
                Hop {
                    hop_limit: 1,
                    probes: vec![Probe {
                        sequence: 4,
                        hop_limit: 1,
                        attempt: 1,
                        strategy: "udp".to_owned(),
                        destination: "192.0.2.9".parse().unwrap(),
                        destination_port: Some(33434),
                        status: ProbeStatus::Response,
                        response_kind: Some(ResponseKind::Intermediate),
                        responder: Some("192.0.2.1".parse().unwrap()),
                        sent_at: Timestamp {
                            unix_seconds: 1,
                            nanoseconds: 0,
                        },
                        received_at: Some(Timestamp {
                            unix_seconds: 1,
                            nanoseconds: 2,
                        }),
                        latency: Some(Duration::from_nanos(2)),
                        frame: None,
                        reason: "time exceeded".to_owned(),
                    }],
                },
                Hop {
                    hop_limit: 2,
                    probes: vec![Probe {
                        sequence: 5,
                        hop_limit: 2,
                        attempt: 1,
                        strategy: "udp".to_owned(),
                        destination: "192.0.2.9".parse().unwrap(),
                        destination_port: None,
                        status: ProbeStatus::Timeout,
                        response_kind: None,
                        responder: None,
                        sent_at: Timestamp {
                            unix_seconds: 2,
                            nanoseconds: 0,
                        },
                        received_at: None,
                        latency: None,
                        frame: None,
                        reason: "timeout".to_owned(),
                    }],
                },
            ],
            undecoded: Vec::new(),
            completion: Completion::MaximumHops,
        }
    }

    #[test]
    fn traceroute_text_names_cover_every_public_enum_variant() {
        assert_eq!(trace_probe_status_name(ProbeStatus::Response), "response");
        assert_eq!(trace_probe_status_name(ProbeStatus::Timeout), "timeout");
        for (value, expected) in [
            (ResponseKind::Intermediate, "intermediate"),
            (ResponseKind::DestinationReached, "destination_reached"),
            (ResponseKind::Unreachable, "unreachable"),
        ] {
            assert_eq!(trace_response_kind_name(value), expected);
        }
        for (value, expected) in [
            (Completion::DestinationReached, "destination_reached"),
            (Completion::Unreachable, "unreachable"),
            (Completion::MaximumHops, "maximum_hops"),
            (Completion::Timeout, "timeout"),
        ] {
            assert_eq!(trace_completion_name(value), expected);
        }
    }

    #[test]
    fn traceroute_text_and_stream_render_present_and_absent_evidence() {
        let stats = Stats {
            packets_completed: 2,
            bytes: 96,
            ..Stats::default()
        };
        let ((text, stream), rendered) = capture_stdout(|| {
            (
                render_traceroute_text(result(), Vec::new(), stats.clone()),
                render_traceroute_stream(result(), Vec::new(), stats),
            )
        });
        assert!(text.is_ok());
        assert!(stream.is_ok());
        let rendered = crate::rendering::terminal_document(&rendered);
        assert!(rendered.contains("response=intermediate"));
        assert!(rendered.contains("\"sequence\":2"));
    }
}
