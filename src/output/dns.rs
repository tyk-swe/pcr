// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Write;

use anyhow::{Context, Result};

use crate::domain::command::{DnsQueryResult, DnsRequest};

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
        "ID: {:04x}, OpCode: {}, ResponseCode: {}, Questions: {}, Answers: {}",
        result.id,
        result.opcode,
        result.response_code,
        result.questions.len(),
        result.answers.len()
    );

    if !result.flags.is_empty() {
        let _ = writeln!(&mut output, "Flags: {}", result.flags.join(", "));
    }

    if !result.answers.is_empty() {
        let _ = writeln!(&mut output, "Answers:");
        for record in &result.answers {
            let _ = writeln!(&mut output, "  {}", record);
        }
    }

    if !result.authority.is_empty() {
        let _ = writeln!(&mut output, "Authority:");
        for record in &result.authority {
            let _ = writeln!(&mut output, "  {}", record);
        }
    }

    if !result.additional.is_empty() {
        let _ = writeln!(&mut output, "Additional:");
        for record in &result.additional {
            let _ = writeln!(&mut output, "  {}", record);
        }
    }

    output.trim_end().to_string()
}

pub fn format_dns_message_json(result: &DnsQueryResult) -> Result<String> {
    let queries = result
        .questions
        .iter()
        .map(|query| {
            serde_json::json!({
                "name": query.name,
                "record_type": query.record_type,
                "class": query.class
            })
        })
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
        "id": result.id,
        "opcode": result.opcode,
        "response_code": result.response_code,
        "counts": {
            "questions": result.questions.len(),
            "answers": result.answers.len(),
            "authority": result.authority.len(),
            "additional": result.additional.len()
        },
        "flags": result.flags,
        "questions": queries,
        "answers": result.answers,
        "authority": result.authority,
        "additional": result.additional
    });

    serde_json::to_string_pretty(&value).context("failed to serialize DNS response JSON")
}
