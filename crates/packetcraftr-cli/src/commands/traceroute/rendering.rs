// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{core, output};

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, comma_separated, optional_debug, optional_display,
    render_diagnostics_text, write_stdout_line,
};

pub(super) fn render_text(
    result: output::traceroute::Report,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
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
                probe.status.as_str(),
                probe
                    .response_kind
                    .map_or("none", output::traceroute::ResponseKind::as_str),
                probe.sent_at,
                optional_display(probe.received_at),
                optional_display(probe.responder),
                optional_debug(probe.latency),
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
        result.completion.as_str(),
        result.hops.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use std::net::{IpAddr, Ipv4Addr};
    use std::time::UNIX_EPOCH;

    use packetcraftr::traceroute;

    use super::*;
    use crate::commands::target_workflow::TargetWorkflow as _;
    use crate::commands::traceroute::Traceroute;
    use crate::rendering::ndjson_test_support::{assert_contiguous, stream};
    use crate::test_support::assert_single_complete;

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
            stats: packetcraftr::Stats::default(),
        }
    }

    #[test]
    fn traceroute_stream_positions_ignore_probe_and_hop_ids() {
        let (sink, output) = stream(output::contract::Command::Traceroute);
        Traceroute::emit_event(probe_event(4_000_000_000, 200), &sink).unwrap();
        Traceroute::emit_event(probe_event(3, 2), &sink).unwrap();
        Traceroute::emit_complete(summary(), &sink).unwrap();

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records[0]["result"]["probe"]["sequence"], 4_000_000_000_u64);
        assert_eq!(records[0]["result"]["probe"]["hop_limit"], 200);
        assert_eq!(records[1]["result"]["probe"]["sequence"], 3);
        assert_eq!(records[2]["result"]["event"], "complete");
        assert_single_complete(&records);
    }
}
