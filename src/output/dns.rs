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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::command::DnsTransport;
    use std::str::FromStr;
    use trust_dns_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use trust_dns_proto::rr::{DNSClass, Name, RecordType};

    #[test]
    fn format_dns_dry_run_json_is_parseable() {
        let options = DnsRequest {
            domain: "example.com".to_string(),
            record_type: "AAAA".to_string(),
            server: "127.0.0.1:5353".to_string(),
            timeout: 250,
            transaction_id: Some(0x1234),
            transport: crate::engine::command::DnsTransportMode::Tcp,
            retries: 2,
        };

        let output = format_dns_dry_run_json(&options).expect("json output");
        let json: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");

        assert_eq!(json["mode"], "dry_run");
        assert_eq!(json["query"]["domain"], "example.com");
        assert_eq!(json["query"]["record_type"], "AAAA");
        assert_eq!(json["query"]["server"], "127.0.0.1:5353");
        assert_eq!(json["query"]["timeout_ms"], 250);
        assert_eq!(json["query"]["transaction_id"], 0x1234);
        assert_eq!(json["query"]["transport_mode"], "tcp");
        assert_eq!(json["query"]["retries"], 2);
    }

    fn dns_result(message: Message) -> DnsQueryResult {
        DnsQueryResult {
            message,
            transport_used: DnsTransport::Tcp,
            attempts: 2,
            server: "127.0.0.1:5353".to_string(),
            response_bytes: 64,
            udp_truncated: true,
            tcp_fallback_used: true,
        }
    }

    #[test]
    fn format_dns_message_includes_reply_sections_and_flags() {
        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_authoritative(true);
        message.set_recursion_desired(true);
        message.set_recursion_available(true);
        message.set_response_code(ResponseCode::NoError);

        let name = Name::from_str("example.com.").unwrap();
        let mut record = trust_dns_proto::rr::Record::new();
        record.set_name(name);
        record.set_rr_type(RecordType::A);
        record.set_dns_class(DNSClass::IN);
        record.set_ttl(3600);
        record.set_data(Some(trust_dns_proto::rr::RData::A(
            std::net::Ipv4Addr::new(93, 184, 216, 34).into(),
        )));

        message.add_answer(record.clone());
        message.add_name_server(record.clone());
        message.add_additional(record);

        let bytes = message.to_vec().expect("serialize");
        let message = Message::from_vec(&bytes).expect("parse");
        let output = format_dns_message(&dns_result(message));

        assert!(
            output.starts_with("Metadata: transport=tcp attempts=2"),
            "Output: {}",
            output
        );
        assert!(output.contains("response_bytes=64"), "Output: {}", output);
        assert!(
            output.contains("tcp_fallback_used=true"),
            "Output: {}",
            output
        );
        assert!(output.contains("ID: 1234"), "Output: {}", output);
        assert!(
            output.contains("ResponseCode: No Error"),
            "Output: {}",
            output
        );
        let flags = output
            .lines()
            .find(|line| line.starts_with("Flags:"))
            .expect("flags line");
        for flag in ["AA", "RD", "RA"] {
            assert!(flags.contains(flag), "Output: {}", output);
        }
        assert!(output.contains("Answers:"), "Output: {}", output);
        assert!(output.contains("Authority:"), "Output: {}", output);
        assert!(output.contains("Additional:"), "Output: {}", output);
        assert!(output.contains("example.com."), "Output: {}", output);
        assert!(output.contains("IN A 93.184.216.34"), "Output: {}", output);
    }

    #[test]
    fn format_dns_message_json_is_parseable() {
        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_authoritative(true);
        message.set_recursion_desired(true);
        message.set_recursion_available(true);
        message.set_response_code(ResponseCode::NoError);

        let mut query = Query::new();
        query.set_name(Name::from_str("example.com.").unwrap());
        query.set_query_type(RecordType::A);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);

        let mut record = trust_dns_proto::rr::Record::new();
        record.set_name(Name::from_str("example.com.").unwrap());
        record.set_rr_type(RecordType::A);
        record.set_dns_class(DNSClass::IN);
        record.set_ttl(3600);
        record.set_data(Some(trust_dns_proto::rr::RData::A(
            std::net::Ipv4Addr::new(93, 184, 216, 34).into(),
        )));
        message.add_answer(record);

        let bytes = message.to_vec().expect("serialize");
        let message = Message::from_vec(&bytes).expect("parse");
        let output = format_dns_message_json(&dns_result(message)).expect("json output");
        let json: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");

        assert_eq!(json["mode"], "response");
        assert_eq!(json["metadata"]["transport_used"], "tcp");
        assert_eq!(json["metadata"]["attempts"], 2);
        assert_eq!(json["metadata"]["server"], "127.0.0.1:5353");
        assert_eq!(json["metadata"]["response_bytes"], 64);
        assert_eq!(json["metadata"]["udp_truncated"], true);
        assert_eq!(json["metadata"]["tcp_fallback_used"], true);
        assert_eq!(json["id"], 0x1234);
        assert_eq!(json["response_code"], "No Error");
        assert_eq!(json["counts"]["questions"], 1);
        assert_eq!(json["counts"]["answers"], 1);
        assert_eq!(json["questions"][0]["name"], "example.com.");
        assert_eq!(json["questions"][0]["record_type"], "A");
        assert!(json["flags"]
            .as_array()
            .expect("flags array")
            .iter()
            .any(|flag| flag == "AA"));
        assert!(json["answers"][0]
            .as_str()
            .expect("answer string")
            .contains("93.184.216.34"));
    }
}
