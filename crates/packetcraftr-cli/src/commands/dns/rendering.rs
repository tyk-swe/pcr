// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{output, packet};

use crate::errors::CliError;
use crate::rendering::{
    emit_json_compact, emit_stream_record, output_timestamp_text, render_diagnostics_text,
    spaced_hex, write_stdout_line,
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
        result
            .resolved_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
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
            attempt
                .received_at
                .map(output_timestamp_text)
                .unwrap_or_else(|| "none".to_owned()),
            attempt
                .latency
                .map(|value| format!("{value:?}"))
                .unwrap_or_else(|| "none".to_owned()),
            attempt
                .response_code
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_owned()),
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
        result
            .response_code
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
        result.response_code_name.as_deref().unwrap_or("none"),
        result
            .authoritative
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
        result
            .truncated
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::{dns_outcome_name, render_dns_stream, render_dns_text};
    use crate::rendering::capture_stdout;
    use packetcraftr::output::{
        dns::{
            Attempt, AttemptStatus, Edns, EdnsOption, Outcome, Record, RecordData, RejectedRecord,
            Result as DnsResult, Section, Timestamp,
        },
        envelope::Stats,
    };

    fn record(owner: &str, data: RecordData) -> Record {
        Record {
            owner: owner.to_owned(),
            class: 1,
            ttl: 300,
            data,
        }
    }

    fn result() -> DnsResult {
        DnsResult {
            server: "dns.example".to_owned(),
            server_port: 53,
            resolved_addresses: vec![Ipv4Addr::new(192, 0, 2, 53).into()],
            query_name: "www.example.".to_owned(),
            query_type: "A".to_owned(),
            transaction_id: 42,
            transport: "udp".to_owned(),
            outcome: Outcome::Response,
            response_code: Some(0),
            response_code_name: Some("NOERROR".to_owned()),
            edns: Some(Edns {
                udp_payload_size: 1232,
                extended_response_code: 0,
                version: 0,
                dnssec_ok: true,
                flags: 0,
                options: vec![EdnsOption {
                    code: 12,
                    data_hex: "0102".to_owned(),
                }],
            }),
            authoritative: Some(true),
            truncated: Some(false),
            recursion_desired: Some(true),
            recursion_available: Some(true),
            authenticated_data: Some(false),
            checking_disabled: Some(false),
            answers: vec![record(
                "www.example.",
                RecordData::A {
                    address: Ipv4Addr::new(192, 0, 2, 1),
                },
            )],
            authorities: vec![record(
                "example.",
                RecordData::Ns {
                    name_server: "ns.example.".to_owned(),
                },
            )],
            additionals: vec![record(
                "unknown.example.",
                RecordData::Unknown {
                    type_code: 65280,
                    rdata_hex: "ff".to_owned(),
                },
            )],
            rejected_records: vec![RejectedRecord {
                section: Section::Additional,
                index: 2,
                owner: "bad.example.".to_owned(),
                type_code: 99,
                reason: "invalid RDATA".to_owned(),
            }],
            rejected_record_count: 1,
            attempts: vec![
                Attempt {
                    attempt: 1,
                    server_address: Ipv4Addr::new(192, 0, 2, 53).into(),
                    source_port: 49152,
                    status: AttemptStatus::Response,
                    sent_at: Timestamp {
                        unix_seconds: 10,
                        nanoseconds: 0,
                    },
                    received_at: Some(Timestamp {
                        unix_seconds: 10,
                        nanoseconds: 1,
                    }),
                    latency: Some(Duration::from_nanos(1)),
                    frame: None,
                    response_code: Some(0),
                    reason: "correlated response".to_owned(),
                },
                Attempt {
                    attempt: 2,
                    server_address: Ipv4Addr::new(192, 0, 2, 54).into(),
                    source_port: 49153,
                    status: AttemptStatus::Timeout,
                    sent_at: Timestamp {
                        unix_seconds: 11,
                        nanoseconds: 0,
                    },
                    received_at: None,
                    latency: None,
                    frame: None,
                    response_code: None,
                    reason: "timeout".to_owned(),
                },
            ],
            undecoded: Vec::new(),
        }
    }

    #[test]
    fn dns_text_names_cover_every_public_enum_variant() {
        for (value, expected) in [
            (Outcome::Response, "response"),
            (Outcome::Truncated, "truncated"),
            (Outcome::Timeout, "timeout"),
            (Outcome::Unrelated, "unrelated"),
            (Outcome::DecodeFailure, "decode_failure"),
            (Outcome::NetworkFailure, "network_failure"),
        ] {
            assert_eq!(dns_outcome_name(value), expected);
        }
        for (value, expected) in [
            (Section::Answer, "answer"),
            (Section::Authority, "authority"),
            (Section::Additional, "additional"),
        ] {
            assert_eq!(value.to_string(), expected);
        }
    }

    #[test]
    fn dns_text_and_stream_render_attempt_record_and_rejection_shapes() {
        let stats = Stats {
            packets_completed: 2,
            bytes: 128,
            ..Stats::default()
        };
        let ((text, stream), rendered) = capture_stdout(|| {
            (
                render_dns_text(result(), Vec::new(), stats.clone()),
                render_dns_stream(result(), Vec::new(), stats),
            )
        });
        assert!(text.is_ok());
        assert!(stream.is_ok());
        let rendered = crate::rendering::terminal_document(&rendered);
        assert!(rendered.contains("record section=answer"));
        assert!(rendered.contains("\"event\":\"rejected\""));
        assert!(rendered.contains("\"sequence\":6"));
    }
}
