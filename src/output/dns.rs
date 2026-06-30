// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Write;

use anyhow::{Context, Result};

use crate::domain::command::{DnsQueryResult, DnsRequest};

pub(crate) fn format_dns_dry_run(options: &DnsRequest) -> String {
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

pub(crate) fn format_dns_dry_run_json(options: &DnsRequest) -> Result<String> {
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

pub(crate) fn format_dns_message(result: &DnsQueryResult) -> String {
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

pub(crate) fn format_dns_message_json(result: &DnsQueryResult) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::command::{DnsQuestion, DnsTransport, DnsTransportMode};

    fn request() -> DnsRequest {
        DnsRequest {
            domain: "example.test".to_string(),
            record_type: "A".to_string(),
            server: "1.1.1.1:53".to_string(),
            timeout: 500,
            transaction_id: Some(0x1234),
            transport: DnsTransportMode::Tcp,
            retries: 2,
        }
    }

    fn result() -> DnsQueryResult {
        DnsQueryResult {
            id: 0x1234,
            opcode: "Query".to_string(),
            response_code: "NoError".to_string(),
            flags: vec!["RD".to_string(), "RA".to_string()],
            questions: vec![DnsQuestion {
                name: "example.test.".to_string(),
                record_type: "A".to_string(),
                class: "IN".to_string(),
            }],
            answers: vec!["example.test. 300 IN A 192.0.2.1".to_string()],
            authority: vec![],
            additional: vec![],
            transport_used: DnsTransport::Udp,
            attempts: 1,
            server: "1.1.1.1:53".to_string(),
            response_bytes: 64,
            udp_truncated: false,
            tcp_fallback_used: false,
        }
    }

    #[test]
    fn format_dns_dry_run_includes_query_metadata() {
        let output = format_dns_dry_run(&request());

        assert!(output.contains("domain=example.test"));
        assert!(output.contains("transaction_id=4660"));
        assert!(output.contains("transport=tcp"));
        assert!(output.contains("retries=2"));
    }

    #[test]
    fn format_dns_dry_run_json_serializes_expected_fields() {
        let json = format_dns_dry_run_json(&request()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["mode"], "dry_run");
        assert_eq!(value["query"]["transport_mode"], "tcp");
        assert_eq!(value["query"]["transaction_id"], 4660);
    }

    #[test]
    fn format_dns_message_includes_metadata_flags_and_answers() {
        let output = format_dns_message(&result());

        assert!(output.contains("Metadata: transport=udp attempts=1"));
        assert!(output.contains("ID: 1234"));
        assert!(output.contains("Flags: RD, RA"));
        assert!(output.contains("Answers:"));
    }

    #[test]
    fn format_dns_message_json_serializes_counts_and_questions() {
        let json = format_dns_message_json(&result()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["mode"], "response");
        assert_eq!(value["counts"]["questions"], 1);
        assert_eq!(value["metadata"]["transport_used"], "udp");
        assert_eq!(value["questions"][0]["name"], "example.test.");
    }
}
