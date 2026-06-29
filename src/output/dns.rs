// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Write;

use anyhow::{Context, Result};
use trust_dns_proto::op::Message;

use crate::engine::command::{DnsQueryResult, DnsRequest};

pub fn format_dns_dry_run(options: &DnsRequest) -> String {
    format!(
        "Dry-run DNS query: domain={} type={} server={} timeout={}ms transaction_id={} transport={} retries={}",
        options.domain,
        options.record_type,
        options.server,
        options.timeout,
        options
            .transaction_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "random".to_string()),
        options.transport,
        options.retries
    )
}

pub fn format_dns_dry_run_json(options: &DnsRequest) -> Result<String> {
    let value = serde_json::json!({
        "mode": "dry_run",
        "query": {
            "domain": options.domain,
            "record_type": options.record_type,
            "server": options.server,
            "timeout_ms": options.timeout,
            "transaction_id": options.transaction_id,
            "transport_mode": options.transport.as_str(),
            "retries": options.retries
        }
    });

    serde_json::to_string_pretty(&value).context("failed to serialize DNS dry-run JSON")
}

pub fn format_dns_message(result: &DnsQueryResult) -> String {
    let mut output = String::new();
    let message = &result.message;

    let _ = writeln!(
        &mut output,
        "Metadata: transport={} attempts={} server={} response_bytes={} udp_truncated={} tcp_fallback_used={}",
        result.transport_used,
        result.attempts,
        result.server,
        result.response_bytes,
        result.udp_truncated,
        result.tcp_fallback_used
    );

    let _ = writeln!(
        &mut output,
        "ID: {:04x}, OpCode: {:?}, ResponseCode: {}, Questions: {}, Answers: {}",
        message.id(),
        message.op_code(),
        message.response_code(),
        message.query_count(),
        message.answer_count()
    );

    let flags = dns_flags(message);
    if !flags.is_empty() {
        let _ = writeln!(&mut output, "Flags: {}", flags.join(", "));
    }

    if message.answer_count() > 0 {
        let _ = writeln!(&mut output, "Answers:");
        for record in message.answers() {
            let _ = writeln!(&mut output, "  {}", record);
        }
    }

    if message.name_server_count() > 0 {
        let _ = writeln!(&mut output, "Authority:");
        for record in message.name_servers() {
            let _ = writeln!(&mut output, "  {}", record);
        }
    }

    if message.additional_count() > 0 {
        let _ = writeln!(&mut output, "Additional:");
        for record in message.additionals() {
            let _ = writeln!(&mut output, "  {}", record);
        }
    }

    output.trim_end().to_string()
}

pub fn format_dns_message_json(result: &DnsQueryResult) -> Result<String> {
    let message = &result.message;
    let flags = dns_flags(message);
    let queries = message
        .queries()
        .iter()
        .map(|query| {
            serde_json::json!({
                "name": query.name().to_string(),
                "record_type": query.query_type().to_string(),
                "class": format!("{:?}", query.query_class())
            })
        })
        .collect::<Vec<_>>();
    let answers = message
        .answers()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let authority = message
        .name_servers()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let additional = message
        .additionals()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    let value = serde_json::json!({
        "mode": "response",
        "metadata": {
            "transport_used": result.transport_used.as_str(),
            "attempts": result.attempts,
            "server": result.server,
            "response_bytes": result.response_bytes,
            "udp_truncated": result.udp_truncated,
            "tcp_fallback_used": result.tcp_fallback_used
        },
        "id": message.id(),
        "opcode": format!("{:?}", message.op_code()),
        "response_code": message.response_code().to_string(),
        "counts": {
            "questions": message.query_count(),
            "answers": message.answer_count(),
            "authority": message.name_server_count(),
            "additional": message.additional_count()
        },
        "flags": flags,
        "questions": queries,
        "answers": answers,
        "authority": authority,
        "additional": additional
    });

    serde_json::to_string_pretty(&value).context("failed to serialize DNS response JSON")
}

fn dns_flags(message: &Message) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if message.header().authoritative() {
        flags.push("AA");
    }
    if message.header().truncated() {
        flags.push("TC");
    }
    if message.header().recursion_desired() {
        flags.push("RD");
    }
    if message.header().recursion_available() {
        flags.push("RA");
    }
    flags
}
