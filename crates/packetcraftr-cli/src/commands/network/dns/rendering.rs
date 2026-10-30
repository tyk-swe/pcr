// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, SocketAddr};

use crate::invocation::StreamEncoder;

use packetcraftr_core::error::Kind;

use crate::output;

use crate::errors::CliError;
use crate::rendering::{
    CapturedFrameText, comma_separated, duration_text, render_diagnostics_text, render_dns_record,
    render_optional, render_undecoded, write_stdout_line,
};

pub(super) fn render_batch_text(
    invocation: &crate::invocation::Invocation,
    published: output::envelope::Published<output::dns::BatchResult>,
    presentation: crate::invocation::Presentation,
) -> Result<(), CliError> {
    let output::envelope::Published {
        result,
        diagnostics,
        stats,
    } = published;
    let stats = stats.unwrap_or_default();
    let total = result.questions.len();
    for (index, question) in result.questions.into_iter().enumerate() {
        write_stdout_line(
            invocation,
            format_args!(
                "question={}/{} name={} type={} id={} status={} error={}",
                index + 1,
                total,
                question.query_name,
                packetcraftr::dns::QueryType::new(question.query_type),
                question.transaction_id,
                question.status.as_str(),
                question.error.as_deref().unwrap_or("none"),
            ),
        )?;
        if let Some(report) = question.result {
            render_text(
                invocation,
                output::envelope::Published::new(*report, Vec::new()),
                presentation,
            )?;
        }
    }
    write_stdout_line(
        invocation,
        format_args!(
            "dns batch questions={} udp_packets_completed={} bytes={}",
            total, stats.packets_completed, stats.bytes,
        ),
    )?;
    render_diagnostics_text(invocation, &diagnostics)
}

pub(super) fn render_text(
    invocation: &crate::invocation::Invocation,
    published: output::envelope::Published<output::dns::Report>,
    presentation: crate::invocation::Presentation,
) -> Result<(), CliError> {
    let output::envelope::Published {
        result,
        diagnostics,
        stats,
    } = published;
    let server = result.server.parse::<IpAddr>().map_or_else(
        |_| format!("{}:{}", result.server, result.server_port),
        |address| SocketAddr::new(address, result.server_port).to_string(),
    );
    write_stdout_line(
        invocation,
        format_args!(
            "server={} resolved={} query={} type={} id={} fallback_attempted={} accepted_transport={} outcome={}",
            server,
            comma_separated(&result.resolved_addresses),
            result.query_name,
            packetcraftr::dns::QueryType::new(result.query_type),
            result.transaction_id,
            result.fallback_attempted,
            render_optional(result.accepted_transport, |value| value.to_string()),
            result.outcome.as_str(),
        ),
    )?;
    for attempt in &result.attempts {
        write_stdout_line(
            invocation,
            format_args!(
                "attempt={} transport={} server={} source_port={} status={} sent={} received={} latency={} rcode={} reason={}",
                attempt.attempt,
                attempt.transport,
                attempt.server_address,
                render_optional(attempt.source_port, |value| value.to_string()),
                attempt.status.as_str(),
                render_optional(attempt.sent_at, |value| value.to_string()),
                render_optional(attempt.received_at, |value| value.to_string()),
                render_optional(attempt.latency, duration_text),
                render_optional(attempt.response_code, |value| value.to_string()),
                attempt.reason,
            ),
        )?;
        if let Some(frame) = &attempt.frame
            && presentation.verbose
        {
            write_stdout_line(
                invocation,
                format_args!("  frame {}", CapturedFrameText(frame)),
            )?;
        }
    }
    for (section, records) in [
        (output::dns::Section::Answer, &result.answers),
        (output::dns::Section::Authority, &result.authorities),
        (output::dns::Section::Additional, &result.additionals),
    ] {
        for record in records {
            render_record(invocation, section, record)?;
        }
    }
    for record in &result.rejected_records {
        write_stdout_line(
            invocation,
            format_args!(
                "rejected section={} index={} owner={} type_code={} reason={}",
                record.section, record.index, record.owner, record.type_code, record.reason,
            ),
        )?;
    }
    render_undecoded(
        invocation,
        result.undecoded.iter().map(|evidence| {
            (
                Some(format!("attempt={}", evidence.attempt)),
                &evidence.frame,
            )
        }),
    )?;
    write_stdout_line(
        invocation,
        format_args!(
            "{}",
            response_summary(ResponseLine {
                response_code: render_optional(
                    result
                        .response
                        .as_ref()
                        .map(|response| response.response_code),
                    |value| value.to_string()
                ),
                response_code_name: result
                    .response
                    .as_ref()
                    .map_or("none", |response| response.response_code_name.as_str()),
                authoritative: render_optional(
                    result
                        .response
                        .as_ref()
                        .map(|response| response.authoritative),
                    |value| value.to_string()
                ),
                truncated: render_optional(
                    result.response.as_ref().map(|response| response.truncated),
                    |value| value.to_string()
                ),
                accepted: result
                    .answers
                    .len()
                    .saturating_add(result.authorities.len())
                    .saturating_add(result.additionals.len()),
                rejected: result.rejected_record_count,
                counters: stats.map(|stats| (stats.packets_completed, stats.bytes)),
            })
        ),
    )?;
    render_diagnostics_text(invocation, &diagnostics)
}

fn render_record(
    invocation: &crate::invocation::Invocation,
    section: output::dns::Section,
    record: &output::dns::Record,
) -> Result<(), CliError> {
    let mut data = serde_json::to_value(&record.data).map_err(serialization_failure)?;
    let record_type = data
        .as_object_mut()
        .and_then(|fields| fields.remove("type"))
        .and_then(|tag| tag.as_str().map(str::to_owned))
        .unwrap_or_default();
    render_dns_record(
        invocation,
        section,
        &record.owner,
        record_type,
        record.class,
        record.ttl,
        data,
    )
}

/// Record data that already survived decoding cannot fail to serialize.
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
    /// Completed UDP packets and bytes.
    counters: Option<(u64, u64)>,
}

fn response_summary(summary: ResponseLine<'_>) -> String {
    let ResponseLine {
        response_code,
        response_code_name,
        authoritative,
        truncated,
        accepted,
        rejected,
        counters,
    } = summary;
    let line = format!(
        "dns response_code={response_code} response_code_name={response_code_name} authoritative={authoritative} truncated={truncated} accepted={accepted} rejected={rejected}"
    );
    match counters {
        Some((udp_packets_completed, bytes)) => {
            format!("{line} udp_packets_completed={udp_packets_completed} bytes={bytes}")
        }
        None => line,
    }
}

pub(super) fn emit_event(
    event: packetcraftr::dns::Event,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let published = output::envelope::Published::<output::dns::Event>::try_from(event)
        .map_err(CliError::classified)?;
    Ok(stream.emit_published(published)?)
}

pub(super) fn emit_complete(
    report: packetcraftr::dns::Report,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    Ok(
        stream.complete_published(output::envelope::Published::<output::dns::Event>::from(
            report,
        ))?,
    )
}

pub(super) fn emit_batch_complete(
    batch: packetcraftr::dns::batch::Report,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    Ok(
        stream.complete_published(output::envelope::Published::<output::dns::Event>::from(
            batch,
        ))?,
    )
}
