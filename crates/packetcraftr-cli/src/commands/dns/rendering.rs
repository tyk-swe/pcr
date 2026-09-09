// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, SocketAddr};

use crate::rendering::StreamEncoder;

use packetcraftr_core::error::Kind;

use packetcraftr_core as core;

use packetcraftr_cli::output;

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, comma_separated, optional_debug, optional_display,
    render_diagnostics_text, render_undecoded, write_stdout_line,
};

pub(super) fn render_text(
    result: output::dns::Report,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: packetcraftr::Stats,
) -> Result<(), CliError> {
    let server = result.server.parse::<IpAddr>().map_or_else(
        |_| format!("{}:{}", result.server, result.server_port),
        |address| SocketAddr::new(address, result.server_port).to_string(),
    );
    write_stdout_line(format_args!(
        "server={} resolved={} query={} type={} id={} fallback_attempted={} accepted_transport={} outcome={}",
        server,
        comma_separated(&result.resolved_addresses),
        result.query_name,
        packetcraftr::dns::QueryType::new(result.query_type),
        result.transaction_id,
        result.fallback_attempted,
        optional_display(result.accepted_transport),
        result.outcome.as_str(),
    ))?;
    for attempt in &result.attempts {
        write_stdout_line(format_args!(
            "attempt={} transport={} server={} source_port={} status={} sent={} received={} latency={} rcode={} reason={}",
            attempt.attempt,
            attempt.transport,
            attempt.server_address,
            optional_display(attempt.source_port),
            attempt.status.as_str(),
            optional_display(attempt.sent_at),
            optional_display(attempt.received_at),
            optional_debug(attempt.latency),
            optional_display(attempt.response_code),
            attempt.reason,
        ))?;
        if let Some(frame) = &attempt.frame {
            write_stdout_line(format_args!("  frame {}", captured_frame_text(frame)))?;
        }
    }
    for (section, records) in [
        (packetcraftr::dns::Section::Answer, &result.answers),
        (packetcraftr::dns::Section::Authority, &result.authorities),
        (packetcraftr::dns::Section::Additional, &result.additionals),
    ] {
        for record in records {
            render_record(section, record)?;
        }
    }
    for record in &result.rejected_records {
        write_stdout_line(format_args!(
            "rejected section={} index={} owner={} type_code={} reason={}",
            record.section, record.index, record.owner, record.type_code, record.reason,
        ))?;
    }
    render_undecoded(result.undecoded.iter().map(|evidence| {
        (
            Some(format!("attempt={}", evidence.attempt)),
            &evidence.frame,
        )
    }))?;
    write_stdout_line(format_args!(
        "{}",
        response_summary(ResponseLine {
            response_code: optional_display(
                result
                    .response
                    .as_ref()
                    .map(|response| response.response_code)
            ),
            response_code_name: result
                .response
                .as_ref()
                .map_or("none", |response| response.response_code_name.as_str()),
            authoritative: optional_display(
                result
                    .response
                    .as_ref()
                    .map(|response| response.authoritative)
            ),
            truncated: optional_display(
                result.response.as_ref().map(|response| response.truncated)
            ),
            accepted: result
                .answers
                .len()
                .saturating_add(result.authorities.len())
                .saturating_add(result.additionals.len()),
            rejected: result.rejected_record_count,
            udp_packets_completed: stats.packets_completed,
            bytes: stats.bytes,
        })
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn render_record(
    section: packetcraftr::dns::Section,
    record: &output::dns::Record,
) -> Result<(), CliError> {
    let data = serde_json::to_string(&record.data).map_err(serialization_failure)?;
    write_stdout_line(format_args!(
        "record section={} owner={} class={} ttl={} data={}",
        section, record.owner, record.class, record.ttl, data,
    ))
}

/// Record data that already survived decoding cannot fail to serialize, so a
/// failure here is an internal fault rather than anything the caller sent.
fn serialization_failure(error: serde_json::Error) -> CliError {
    CliError::new(
        Kind::Internal,
        format!("DNS output serialization failed: {error}"),
    )
}

struct ResponseLine<'a> {
    response_code: String,
    response_code_name: &'a str,
    authoritative: String,
    truncated: String,
    accepted: usize,
    rejected: usize,
    udp_packets_completed: u64,
    bytes: u64,
}

fn response_summary(summary: ResponseLine<'_>) -> String {
    let ResponseLine {
        response_code,
        response_code_name,
        authoritative,
        truncated,
        accepted,
        rejected,
        udp_packets_completed,
        bytes,
    } = summary;
    format!(
        "dns response_code={response_code} response_code_name={response_code_name} authoritative={authoritative} truncated={truncated} accepted={accepted} rejected={rejected} udp_packets_completed={udp_packets_completed} bytes={bytes}"
    )
}

/// Converts and writes one final workflow event at its publication boundary.
pub(super) fn emit_event(
    event: packetcraftr::dns::Event,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let (record, diagnostics) =
        output::dns::Event::try_from_dns(event).map_err(CliError::classified)?;
    Ok(stream.emit_data(record, diagnostics)?)
}

pub(super) fn emit_complete(
    summary: packetcraftr::dns::Summary,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let (record, diagnostics, stats) = output::dns::Event::complete_from_dns(summary);
    Ok(stream.complete_with_stats(record, diagnostics, stats)?)
}

#[cfg(test)]
mod tests {

    use super::{ResponseLine, response_summary, serialization_failure};

    #[test]
    fn response_summary_uses_the_response_code_name_label() {
        let summary = response_summary(ResponseLine {
            response_code: "0".to_owned(),
            response_code_name: "NOERROR",
            authoritative: "true".to_owned(),
            truncated: "false".to_owned(),
            accepted: 1,
            rejected: 0,
            udp_packets_completed: 1,
            bytes: 64,
        });

        assert!(summary.contains("response_code_name=NOERROR"));
        assert!(summary.contains("udp_packets_completed=1"));
        assert!(!summary.contains("transmissions="));
        assert!(!summary.contains(" response_name="));
    }

    #[test]
    fn record_serialization_failure_stays_an_internal_error() {
        let error = serde_json::from_str::<serde_json::Value>("{").expect_err("truncated JSON");
        let rendered = error.to_string();

        let failure = serialization_failure(error);

        assert_eq!(failure.exit_code(), 70);
        assert_eq!(
            failure.message,
            format!("DNS output serialization failed: {rendered}")
        );
    }
}
