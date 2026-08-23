// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{core, output};

use crate::rendering::{
    NdjsonStream, captured_frame_text, comma_separated, optional_display, output_timestamp_text,
    render_diagnostics_text, render_optional, write_stdout_line,
};
use packetcraftr::BoundaryError;

pub(super) fn render_text(
    result: output::traceroute::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), BoundaryError> {
    write_stdout_line(format_args!(
        "target={} resolved={} destination={} strategy={} port={}",
        result.target,
        comma_separated(&result.resolved_addresses),
        result.destination,
        result.strategy,
        optional_display(result.destination_port),
    ))?;
    for hop in &result.hops {
        write_stdout_line(format_args!("hop={}", hop.hop_limit))?;
        for probe in &hop.probes {
            write_stdout_line(format_args!(
                "  sequence={} attempt={} status={} response={} sent={} received={} responder={} latency={} port={} reason={}",
                probe.sequence,
                probe.attempt,
                probe_status_name(probe.status),
                probe
                    .response_kind
                    .map(response_kind_name)
                    .unwrap_or("none"),
                output_timestamp_text(probe.sent_at),
                render_optional(probe.received_at, output_timestamp_text),
                optional_display(probe.responder),
                render_optional(probe.latency, |value| format!("{value:?}")),
                optional_display(probe.destination_port),
                probe.reason,
            ))?;
            if let Some(frame) = &probe.frame {
                write_stdout_line(format_args!("    frame {}", captured_frame_text(frame)))?;
            }
        }
    }
    for evidence in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded hop={} {}",
            evidence.hop_limit,
            captured_frame_text(&evidence.frame)
        ))?;
    }
    write_stdout_line(format_args!(
        "trace completion={} hops={} probes={} bytes={}",
        completion_name(result.completion),
        result.hops.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn probe_status_name(value: output::traceroute::ProbeStatus) -> &'static str {
    match value {
        output::traceroute::ProbeStatus::Response => "response",
        output::traceroute::ProbeStatus::Timeout => "timeout",
    }
}

fn response_kind_name(value: output::traceroute::ResponseKind) -> &'static str {
    match value {
        output::traceroute::ResponseKind::Intermediate => "intermediate",
        output::traceroute::ResponseKind::DestinationReached => "destination_reached",
        output::traceroute::ResponseKind::Unreachable => "unreachable",
    }
}

fn completion_name(value: output::traceroute::Completion) -> &'static str {
    match value {
        output::traceroute::Completion::DestinationReached => "destination_reached",
        output::traceroute::Completion::Unreachable => "unreachable",
        output::traceroute::Completion::MaximumHops => "maximum_hops",
        output::traceroute::Completion::Timeout => "timeout",
    }
}

pub(super) fn render_event(
    event: packetcraftr::traceroute::Event,
    stream: &NdjsonStream,
) -> Result<(), BoundaryError> {
    let (event, diagnostics) =
        output::traceroute::Event::try_from_traceroute(event).map_err(BoundaryError::from_error)?;
    stream.emit_data(event, diagnostics)
}

pub(super) fn render_complete(
    summary: packetcraftr::traceroute::Summary,
    stream: &NdjsonStream,
) -> Result<(), BoundaryError> {
    let (event, diagnostics, stats) = output::traceroute::Event::complete_from_traceroute(summary);
    stream.complete_with_stats(event, diagnostics, stats)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::UNIX_EPOCH;

    use packetcraftr::traceroute;

    use super::*;
    use crate::rendering::ndjson_test_support::{assert_contiguous, stream};

    fn probe_event(sequence: u64, hop_limit: u8) -> traceroute::Event {
        let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
        traceroute::Event::Probe {
            target: destination.to_string().into(),
            probe: traceroute::ProbeEvidence {
                sequence,
                hop_limit,
                attempt: 1,
                destination,
                strategy: traceroute::Strategy::Udp,
                destination_port: Some(33_434),
                status: traceroute::ProbeStatus::Timeout,
                response_kind: None,
                responder: None,
                sent_at: UNIX_EPOCH,
                received_at: None,
                latency: None,
                response: None,
                reason: "timeout".to_owned(),
            },
        }
    }

    fn summary() -> traceroute::Summary {
        let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
        traceroute::Summary {
            target: destination.to_string(),
            resolved_addresses: vec![destination],
            destination,
            strategy: traceroute::Strategy::Udp,
            destination_port: Some(33_434),
            completion: traceroute::Completion::Timeout,
            diagnostics: Vec::new(),
            stats: packetcraftr::Stats::default(),
        }
    }

    #[test]
    fn traceroute_stream_positions_ignore_probe_and_hop_ids() {
        let (sink, output) = stream(output::contract::Command::Traceroute);
        render_event(probe_event(4_000_000_000, 200), &sink).unwrap();
        render_event(probe_event(3, 2), &sink).unwrap();
        render_complete(summary(), &sink).unwrap();

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records[0]["result"]["probe"]["sequence"], 4_000_000_000_u64);
        assert_eq!(records[0]["result"]["probe"]["hop_limit"], 200);
        assert_eq!(records[1]["result"]["probe"]["sequence"], 3);
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
