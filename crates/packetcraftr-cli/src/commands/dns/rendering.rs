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
    result: output::dns::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    emit_aggregate_with_stats(output::contract::Command::Dns, result, diagnostics, stats)
}

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
        outcome_name(result.outcome),
    ))?;
    for attempt in &result.attempts {
        write_stdout_line(format_args!(
            "attempt={} server={} source_port={} status={} sent={} received={} latency={} rcode={} reason={}",
            attempt.attempt,
            attempt.server_address,
            attempt.source_port,
            outcome_name(attempt.status),
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
        response_summary(ResponseSummary {
            response_code: optional_display(result.response_code),
            response_code_name: result.response_code_name.as_deref().unwrap_or("none"),
            authoritative: optional_display(result.authoritative),
            truncated: optional_display(result.truncated),
            accepted: result.answers.len() + result.authorities.len() + result.additionals.len(),
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
    let data = serde_json::to_string(&record.data)
        .map_err(|error| CliError::new(4, format!("DNS output serialization failed: {error}")))?;
    write_stdout_line(format_args!(
        "record section={} owner={} class={} ttl={} data={}",
        section, record.owner, record.class, record.ttl, data,
    ))
}

pub(super) fn render_stream(
    result: output::dns::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    let output::dns::Result {
        server,
        server_port,
        resolved_addresses,
        query_name,
        query_type,
        transaction_id,
        transport,
        outcome,
        response_code,
        response_code_name,
        edns,
        authoritative,
        truncated,
        recursion_desired,
        recursion_available,
        authenticated_data,
        checking_disabled,
        answers,
        authorities,
        additionals,
        rejected_records,
        rejected_record_count,
        attempts,
        undecoded,
    } = result;
    let context = StreamContext {
        server: &server,
        server_port,
        query_name: &query_name,
        query_type: &query_type,
    };
    render_attempts(attempts, context, stream)?;
    render_records(answers, authorities, additionals, context, stream)?;
    render_rejected(rejected_records, context, stream)?;
    for evidence in undecoded {
        stream.emit_data(output::dns::Event::Undecoded { evidence }, Vec::new())?;
    }
    stream.complete_with_stats(
        output::dns::Event::Complete {
            server,
            server_port,
            resolved_addresses,
            query_name,
            query_type,
            transaction_id,
            transport,
            outcome,
            response_code,
            response_code_name,
            edns,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            authenticated_data,
            checking_disabled,
            rejected_record_count,
        },
        diagnostics,
        stats,
    )
}

#[derive(Clone, Copy)]
struct StreamContext<'a> {
    server: &'a str,
    server_port: u16,
    query_name: &'a str,
    query_type: &'a str,
}

fn render_attempts(
    attempts: Vec<output::dns::Attempt>,
    context: StreamContext<'_>,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    for evidence in attempts {
        stream.emit_data(
            output::dns::Event::Attempt {
                server: context.server.to_owned(),
                server_port: context.server_port,
                query_name: context.query_name.to_owned(),
                query_type: context.query_type.to_owned(),
                evidence,
            },
            Vec::new(),
        )?;
    }
    Ok(())
}

fn render_records(
    answers: Vec<output::dns::Record>,
    authorities: Vec<output::dns::Record>,
    additionals: Vec<output::dns::Record>,
    context: StreamContext<'_>,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    for (section, records) in [
        (output::dns::Section::Answer, answers),
        (output::dns::Section::Authority, authorities),
        (output::dns::Section::Additional, additionals),
    ] {
        for record in records {
            stream.emit_data(
                output::dns::Event::Record {
                    server: context.server.to_owned(),
                    server_port: context.server_port,
                    query_name: context.query_name.to_owned(),
                    query_type: context.query_type.to_owned(),
                    section,
                    record,
                },
                Vec::new(),
            )?;
        }
    }
    Ok(())
}

fn render_rejected(
    records: Vec<output::dns::RejectedRecord>,
    context: StreamContext<'_>,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    for record in records {
        stream.emit_data(
            output::dns::Event::Rejected {
                server: context.server.to_owned(),
                server_port: context.server_port,
                query_name: context.query_name.to_owned(),
                query_type: context.query_type.to_owned(),
                record,
            },
            Vec::new(),
        )?;
    }
    Ok(())
}

struct ResponseSummary<'a> {
    response_code: String,
    response_code_name: &'a str,
    authoritative: String,
    truncated: String,
    accepted: usize,
    rejected: usize,
    queries: u64,
    bytes: u64,
}

fn response_summary(summary: ResponseSummary<'_>) -> String {
    let ResponseSummary {
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

fn outcome_name(value: output::dns::Outcome) -> &'static str {
    match value {
        output::dns::Outcome::Response => "response",
        output::dns::Outcome::Truncated => "truncated",
        output::dns::Outcome::Timeout => "timeout",
        output::dns::Outcome::Unrelated => "unrelated",
        output::dns::Outcome::DecodeFailure => "decode_failure",
        output::dns::Outcome::NetworkFailure => "network_failure",
    }
}

#[cfg(test)]
mod tests {
    use super::{ResponseSummary, response_summary};

    #[test]
    fn response_summary_uses_the_response_code_name_label() {
        let summary = response_summary(ResponseSummary {
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
}
