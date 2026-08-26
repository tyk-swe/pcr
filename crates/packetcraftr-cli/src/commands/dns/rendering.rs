// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{core, output};

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, comma_separated, optional_display, output_timestamp_text,
    render_diagnostics_text, render_optional, write_stdout_line,
};

pub(super) fn render_text(
    result: output::dns::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "server={}:{} resolved={} query={} type={} id={} transport={} outcome={}",
        result.server,
        result.server_port,
        comma_separated(&result.resolved_addresses),
        result.query_name,
        result.query_type,
        result.transaction_id,
        result.transport,
        result.outcome.as_str(),
    ))?;
    for attempt in &result.attempts {
        write_stdout_line(format_args!(
            "attempt={} server={} source_port={} status={} sent={} received={} latency={} rcode={} reason={}",
            attempt.attempt,
            attempt.server_address,
            attempt.source_port,
            attempt.status.as_str(),
            output_timestamp_text(attempt.sent_at),
            render_optional(attempt.received_at, output_timestamp_text),
            render_optional(attempt.latency, |value| format!("{value:?}")),
            optional_display(attempt.response_code),
            attempt.reason,
        ))?;
        if let Some(frame) = &attempt.frame {
            write_stdout_line(format_args!("  frame {}", captured_frame_text(frame)))?;
        }
    }
    for (section, records) in [
        (output::dns::Section::Answer, &result.answers),
        (output::dns::Section::Authority, &result.authorities),
        (output::dns::Section::Additional, &result.additionals),
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
    for evidence in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded attempt={} {}",
            evidence.attempt,
            captured_frame_text(&evidence.frame)
        ))?;
    }
    write_stdout_line(format_args!(
        "{}",
        response_summary(ResponseLine {
            response_code: optional_display(result.response_code),
            response_code_name: result.response_code_name.as_deref().unwrap_or("none"),
            authoritative: optional_display(result.authoritative),
            truncated: optional_display(result.truncated),
            accepted: result
                .answers
                .len()
                .saturating_add(result.authorities.len())
                .saturating_add(result.additionals.len()),
            rejected: result.rejected_record_count,
            queries: stats.packets_completed,
            bytes: stats.bytes,
        })
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn render_record(
    section: output::dns::Section,
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
    CliError::new(70, format!("DNS output serialization failed: {error}"))
}

struct ResponseLine<'a> {
    response_code: String,
    response_code_name: &'a str,
    authoritative: String,
    truncated: String,
    accepted: usize,
    rejected: usize,
    queries: u64,
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
        queries,
        bytes,
    } = summary;
    format!(
        "dns response_code={response_code} response_code_name={response_code_name} authoritative={authoritative} truncated={truncated} accepted={accepted} rejected={rejected} queries={queries} bytes={bytes}"
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::UNIX_EPOCH;

    use packetcraftr::dns;

    use super::super::Dns;
    use super::{ResponseLine, response_summary, serialization_failure};
    use crate::commands::target_workflow::TargetWorkflow as _;
    use crate::rendering::ndjson_test_support::{assert_contiguous, stream};
    use packetcraftr::output;

    fn attempt_event(attempt: u32) -> dns::Event {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
        dns::Event::Attempt {
            context: Arc::new(dns::EventContext {
                server: Arc::from("resolver.test"),
                server_port: 53,
                query_name: Arc::from("example.test."),
                query_type: dns::QueryType::A,
            }),
            evidence: dns::AttemptEvidence {
                attempt,
                server_address: address,
                source_port: 49_152,
                status: dns::Outcome::Timeout,
                sent_at: UNIX_EPOCH,
                received_at: None,
                latency: None,
                response: None,
                response_code: None,
                reason: "timeout".to_owned(),
            },
        }
    }

    fn summary() -> dns::Summary {
        dns::Summary {
            server: "resolver.test".to_owned(),
            server_port: 53,
            resolved_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
            query_name: "example.test.".to_owned(),
            query_type: dns::QueryType::A,
            transaction_id: u16::MAX,
            outcome: dns::Outcome::Timeout,
            response: None,
            diagnostics: Vec::new(),
            stats: packetcraftr::Stats::default(),
        }
    }

    #[test]
    fn response_summary_uses_the_response_code_name_label() {
        let summary = response_summary(ResponseLine {
            response_code: "0".to_owned(),
            response_code_name: "NOERROR",
            authoritative: "true".to_owned(),
            truncated: "false".to_owned(),
            accepted: 1,
            rejected: 0,
            queries: 1,
            bytes: 64,
        });

        assert!(summary.contains("response_code_name=NOERROR"));
        assert!(!summary.contains(" response_name="));
    }

    #[test]
    fn record_serialization_failure_stays_an_internal_error() {
        let error = serde_json::from_str::<serde_json::Value>("{").expect_err("truncated JSON");
        let rendered = error.to_string();

        let failure = serialization_failure(error);

        assert_eq!(failure.exit_code, 70);
        assert_eq!(
            failure.message,
            format!("DNS output serialization failed: {rendered}")
        );
    }

    #[test]
    fn dns_stream_positions_ignore_noncontiguous_attempt_ids() {
        let (sink, output) = stream(output::contract::Command::Dns);
        Dns::emit_event(attempt_event(31), &sink).unwrap();
        Dns::emit_event(attempt_event(2), &sink).unwrap();
        Dns::emit_complete(summary(), &sink).unwrap();

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records[0]["result"]["evidence"]["attempt"], 31);
        assert_eq!(records[1]["result"]["evidence"]["attempt"], 2);
        assert_eq!(records[2]["result"]["transaction_id"], u16::MAX);
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
