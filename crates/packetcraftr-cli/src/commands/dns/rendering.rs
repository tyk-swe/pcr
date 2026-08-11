// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{output, packet};

use crate::errors::CliError;
use crate::rendering::{
    comma_separated, emit_json_compact, emit_stream_record, optional_display,
    output_timestamp_text, render_diagnostics_text, render_optional, spaced_hex, write_stdout_line,
};

pub(super) fn render_dns_text(
    result: output::dns::Result,
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
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
        dns_outcome_name(result.outcome),
    ))?;
    for attempt in &result.attempts {
        write_stdout_line(format_args!(
            "attempt={} server={} source_port={} status={} sent={} received={} latency={} rcode={} reason={}",
            attempt.attempt,
            attempt.server_address,
            attempt.source_port,
            dns_outcome_name(attempt.status),
            output_timestamp_text(attempt.sent_at),
            render_optional(attempt.received_at, output_timestamp_text),
            render_optional(attempt.latency, |value| format!("{value:?}")),
            optional_display(attempt.response_code),
            attempt.reason,
        ))?;
        if let Some(frame) = &attempt.frame {
            write_stdout_line(format_args!(
                "  frame dlt={} caplen={} wirelen={} {}",
                frame.link_type,
                frame.captured_length,
                frame.original_length,
                spaced_hex(frame.bytes())
            ))?;
        }
    }
    for (section, records) in [
        (output::dns::Section::Answer, &result.answers),
        (output::dns::Section::Authority, &result.authorities),
        (output::dns::Section::Additional, &result.additionals),
    ] {
        for record in records {
            render_dns_record_text(section, record)?;
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
            "undecoded attempt={} dlt={} caplen={} wirelen={} {}",
            evidence.attempt,
            evidence.frame.link_type,
            evidence.frame.captured_length,
            evidence.frame.original_length,
            spaced_hex(evidence.frame.bytes())
        ))?;
    }
    write_stdout_line(format_args!(
        "dns response_code={} response_name={} authoritative={} truncated={} accepted={} rejected={} queries={} bytes={}",
        optional_display(result.response_code),
        result.response_code_name.as_deref().unwrap_or("none"),
        optional_display(result.authoritative),
        optional_display(result.truncated),
        result.answers.len() + result.authorities.len() + result.additionals.len(),
        result.rejected_record_count,
        stats.packets_completed,
        stats.bytes,
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn render_dns_record_text(
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

pub(super) fn render_dns_stream(
    result: output::dns::Result,
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
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
    let mut sequence = 0_u64;
    for evidence in attempts {
        emit_stream_record(
            output::contract::Command::Dns,
            &mut sequence,
            output::dns::Event::Attempt {
                server: server.clone(),
                server_port,
                query_name: query_name.clone(),
                query_type: query_type.clone(),
                evidence,
            },
        )?;
    }
    for (section, records) in [
        (output::dns::Section::Answer, answers),
        (output::dns::Section::Authority, authorities),
        (output::dns::Section::Additional, additionals),
    ] {
        for record in records {
            emit_stream_record(
                output::contract::Command::Dns,
                &mut sequence,
                output::dns::Event::Record {
                    server: server.clone(),
                    server_port,
                    query_name: query_name.clone(),
                    query_type: query_type.clone(),
                    section,
                    record,
                },
            )?;
        }
    }
    for record in rejected_records {
        emit_stream_record(
            output::contract::Command::Dns,
            &mut sequence,
            output::dns::Event::Rejected {
                server: server.clone(),
                server_port,
                query_name: query_name.clone(),
                query_type: query_type.clone(),
                record,
            },
        )?;
    }
    for evidence in undecoded {
        emit_stream_record(
            output::contract::Command::Dns,
            &mut sequence,
            output::dns::Event::Undecoded { evidence },
        )?;
    }
    emit_json_compact(
        &output::envelope::Stream::success(
            output::contract::Command::Dns,
            sequence,
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
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

pub(super) fn dns_outcome_name(value: output::dns::Outcome) -> &'static str {
    match value {
        output::dns::Outcome::Response => "response",
        output::dns::Outcome::Truncated => "truncated",
        output::dns::Outcome::Timeout => "timeout",
        output::dns::Outcome::Unrelated => "unrelated",
        output::dns::Outcome::DecodeFailure => "decode_failure",
        output::dns::Outcome::NetworkFailure => "network_failure",
    }
}
