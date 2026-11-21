// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::sync::Arc;

use packetcraftr_core::security::{Finding, Report, Severity};
use packetcraftr_netio::udp::Provider as _;
use serde_json::json;

use super::{ConnectionOptions, Error, admit, count};
use crate::clock::Clock;
use crate::dns::wire;
use crate::dns::{MessageLimits, QueryType, ValidatedResponse};
use crate::policy::SocketLimits;
use crate::providers::{TcpOf, TcpProviders, UdpProviders};
use crate::{Client, dns as dns_workflow};

#[derive(Clone, Debug)]
pub struct DnsRequest {
    pub connection: ConnectionOptions,
    pub query_name: String,
    pub query_type: QueryType,
    pub recursion_desired: bool,
    pub tcp_fallback: bool,
    pub max_response_bytes: usize,
    pub limits: MessageLimits,
}

impl DnsRequest {
    pub fn new(endpoint: SocketAddr, query_name: impl Into<String>) -> Self {
        Self {
            connection: ConnectionOptions::new(endpoint),
            query_name: query_name.into(),
            query_type: QueryType::A,
            recursion_desired: true,
            tcp_fallback: true,
            max_response_bytes: 65_535,
            limits: MessageLimits::default(),
        }
    }

    fn validate(&self, query_len: usize) -> Result<(), Error> {
        self.connection.validate()?;
        self.limits.validate().map_err(Error::from)?;
        if !(512..=65_535).contains(&self.max_response_bytes)
            || self.max_response_bytes > self.limits.max_message_bytes
        {
            return Err(Error::Invalid(
                "DNS audit response limit must be within 512..=65535 and no larger than the message limit"
                    .into(),
            ));
        }
        if query_len == 0 || query_len > self.limits.max_message_bytes {
            return Err(Error::Invalid(
                "DNS audit query exceeds the configured message limit".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ExchangeResult {
    transport: &'static str,
    response_bytes: usize,
    response: Option<ValidatedResponse>,
    outcome: String,
}

impl<P: UdpProviders + TcpProviders, K: Clock> Client<P, K> {
    pub fn audit_dns(&self, request: &DnsRequest) -> Result<Report, Error> {
        request.connection.validate()?;
        request.limits.validate().map_err(Error::from)?;
        let transaction_id = dns_workflow::unpredictable_transaction_id()?;
        let query = wire::encode_query(
            &request.query_name,
            request.query_type,
            transaction_id,
            request.recursion_desired,
            None,
        )?;
        request.validate(query.len())?;

        let connections = if request.tcp_fallback { 2 } else { 1 };
        let messages = connections * 2;
        let framing_bytes = if request.tcp_fallback { 4 } else { 0 };
        let application_bytes = count(query.len())
            .saturating_mul(connections)
            .saturating_add(count(request.max_response_bytes).saturating_mul(connections))
            .saturating_add(framing_bytes);
        admit(
            &self.policy,
            request.connection.endpoint,
            SocketLimits::new(connections, messages, application_bytes),
            self.wall_now(),
        )?;

        let deadline = self.deadline(request.connection.timeout);
        let reply = self.providers.udp().exchange(
            request.connection.endpoint,
            &query,
            request.max_response_bytes,
            &deadline,
        )?;
        let mut result = self.decode_udp(request, transaction_id, &reply.exchange)?;
        let udp_result = result.clone();
        let mut fallback_attempted = false;
        let mut fallback_error = None;
        if result
            .response
            .as_ref()
            .is_some_and(|response| response.metadata.truncated)
            && request.tcp_fallback
        {
            fallback_attempted = true;
            match self.tcp_fallback(request, transaction_id, &query, &deadline) {
                Ok(tcp) => result = tcp,
                Err(error) => {
                    let cancelled = matches!(
                        &error,
                        Error::Interrupted(packetcraftr_core::budget::Interrupted::Cancelled(_))
                    ) || matches!(
                        &error,
                        Error::DnsTcp(tcp_error)
                            if tcp_error.category() == crate::dns::tcp::Category::Cancelled
                    );
                    if cancelled {
                        return Err(error);
                    }
                    fallback_error = Some(error.to_string());
                }
            }
        }
        Ok(dns_report(
            request,
            query.len(),
            &result,
            &udp_result,
            fallback_attempted,
            fallback_error.as_deref(),
        ))
    }

    fn decode_udp(
        &self,
        request: &DnsRequest,
        transaction_id: u16,
        exchange: &packetcraftr_netio::bounded::Exchange,
    ) -> Result<ExchangeResult, Error> {
        use packetcraftr_netio::bounded::Outcome;
        let (outcome, response) = match &exchange.outcome {
            Outcome::Complete => {
                let decoded = wire::decode_response(
                    &exchange.response,
                    &request.query_name,
                    request.query_type,
                    transaction_id,
                    request.limits,
                )?;
                ("response".to_owned(), Some(decoded))
            }
            Outcome::Truncated => ("truncated_by_limit".to_owned(), None),
            Outcome::Eof => ("eof".to_owned(), None),
            Outcome::TimedOut => ("timeout".to_owned(), None),
            Outcome::Failed(source) => (format!("failed:{source}"), None),
            Outcome::Cancelled => {
                return Err(Error::Interrupted(
                    packetcraftr_core::budget::Interrupted::Cancelled(
                        packetcraftr_core::budget::Cancelled,
                    ),
                ));
            }
        };
        Ok(ExchangeResult {
            transport: "udp",
            response_bytes: exchange.response.len(),
            response,
            outcome,
        })
    }

    fn tcp_fallback(
        &self,
        request: &DnsRequest,
        transaction_id: u16,
        query: &[u8],
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<ExchangeResult, Error> {
        let timeout = deadline.live_remaining().map_err(Error::Interrupted)?;
        let response = dns_workflow::tcp::query_with_clock(
            dns_workflow::tcp::Request {
                endpoint: request.connection.endpoint,
                query,
                timeout,
                cancellation: self.cancellation.as_ref(),
                max_message_bytes: request.max_response_bytes,
            },
            Arc::new(TcpOf(Arc::clone(&self.providers))),
            &self.clock,
        )?;
        let decoded = wire::decode_tcp_frame(
            &response.frame,
            &request.query_name,
            request.query_type,
            transaction_id,
            request.limits,
        )?;
        Ok(ExchangeResult {
            transport: "tcp",
            response_bytes: response.frame.len().saturating_sub(2),
            response: Some(decoded),
            outcome: "response".to_owned(),
        })
    }
}

fn dns_report(
    request: &DnsRequest,
    query_bytes: usize,
    result: &ExchangeResult,
    udp_result: &ExchangeResult,
    fallback_attempted: bool,
    fallback_error: Option<&str>,
) -> Report {
    let endpoint = request.connection.endpoint.to_string();
    let ratio_x100 = if query_bytes == 0 {
        0
    } else {
        (udp_result.response_bytes as u128 * 100 / query_bytes as u128) as u64
    };
    let mut report = Report::new("audit-dns");
    report
        .measurements
        .insert("endpoint".into(), json!(endpoint));
    report
        .measurements
        .insert("query_name".into(), json!(request.query_name));
    report
        .measurements
        .insert("query_type".into(), json!(request.query_type.to_string()));
    report
        .measurements
        .insert("transport".into(), json!(result.transport));
    report
        .measurements
        .insert("outcome".into(), json!(result.outcome));
    report
        .measurements
        .insert("query_bytes".into(), json!(query_bytes));
    report
        .measurements
        .insert("response_bytes".into(), json!(result.response_bytes));
    report.measurements.insert(
        "udp_response_bytes".into(),
        json!(udp_result.response_bytes),
    );
    report
        .measurements
        .insert("amplification_ratio_x100".into(), json!(ratio_x100));
    report
        .measurements
        .insert("tcp_fallback_attempted".into(), json!(fallback_attempted));

    let Some(response) = &result.response else {
        report
            .completeness
            .note(format!("no validated DNS response: {}", result.outcome));
        if let Some(error) = fallback_error {
            report
                .completeness
                .note(format!("TCP fallback failed: {error}"));
        }
        return report;
    };

    let metadata = &response.metadata;
    let answers = response.answers.len();
    report
        .measurements
        .insert("response_code".into(), json!(metadata.response_code));
    report
        .measurements
        .insert("authoritative".into(), json!(metadata.authoritative));
    report
        .measurements
        .insert("truncated".into(), json!(metadata.truncated));
    report.measurements.insert(
        "recursion_available".into(),
        json!(metadata.recursion_available),
    );
    report.measurements.insert(
        "authenticated_data".into(),
        json!(metadata.authenticated_data),
    );
    report.measurements.insert(
        "checking_disabled".into(),
        json!(metadata.checking_disabled),
    );
    report.measurements.insert("answers".into(), json!(answers));
    report
        .measurements
        .insert("authorities".into(), json!(response.authorities.len()));
    report
        .measurements
        .insert("additionals".into(), json!(response.additionals.len()));
    if let Some(error) = fallback_error {
        report
            .completeness
            .note(format!("TCP fallback failed: {error}"));
    }
    if metadata.truncated && result.transport == "udp" {
        report
            .completeness
            .note("truncated DNS response was not recovered over TCP");
    }

    if request.recursion_desired
        && metadata.recursion_available
        && !metadata.authoritative
        && answers > 0
    {
        report.findings.push(Finding::new(
            "dns.open_recursion",
            Severity::High,
            endpoint.clone(),
            "Server answered a recursive query for a non-authoritative name",
            json!({
                "query_name": request.query_name,
                "answers": answers,
                "recursion_available": true,
                "authoritative": false,
            }),
            "Restrict recursion to trusted clients or disable it on authoritative servers.",
        ));
    } else if metadata.recursion_available {
        report.findings.push(Finding::new(
            "dns.recursion_advertised",
            Severity::Low,
            endpoint.clone(),
            "Server advertises recursion availability",
            json!({ "authoritative": metadata.authoritative, "answers": answers }),
            "Confirm recursion is intended for clients that can reach this endpoint.",
        ));
    }
    if ratio_x100 >= 1_000 && udp_result.response_bytes > 512 {
        report.findings.push(Finding::new(
            "dns.amplification",
            Severity::Medium,
            endpoint.clone(),
            "DNS response is at least ten times the query size",
            json!({
                "query_bytes": query_bytes,
                "response_bytes": udp_result.response_bytes,
                "amplification_ratio_x100": ratio_x100,
            }),
            "Limit response size, rate-limit repeated queries, and restrict recursion to trusted clients.",
        ));
    }
    if metadata.authenticated_data {
        report.findings.push(Finding::new(
            "dns.authenticated_data_without_dnssec_request",
            Severity::Low,
            endpoint,
            "Server set AD although the audit did not request DNSSEC data",
            json!({ "authenticated_data": true }),
            "Only set AD for validated answers requested with DNSSEC handling in mind.",
        ));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{ResponseMetadata, ValidatedResponse};

    #[test]
    fn report_computes_amplification_from_metadata() {
        let request = DnsRequest::new("192.0.2.53:53".parse().unwrap(), "example.test");
        let result = ExchangeResult {
            transport: "udp",
            response_bytes: 600,
            response: Some(ValidatedResponse {
                metadata: ResponseMetadata {
                    response_code: 0,
                    edns: None,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    authenticated_data: false,
                    checking_disabled: false,
                    rejected_record_count: 0,
                },
                answers: vec![],
                authorities: Vec::new(),
                additionals: Vec::new(),
                rejected_records: Vec::new(),
            }),
            outcome: "response".to_owned(),
        };
        let report = dns_report(&request, 30, &result, &result, false, None);
        assert_eq!(report.measurements["amplification_ratio_x100"], json!(2000));
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "dns.amplification")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "dns.recursion_advertised")
        );
    }
}
