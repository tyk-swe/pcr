// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::domain::command::{DnsQueryResult, DnsRequest};
use crate::domain::event::ListenerEvent;
#[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
use crate::domain::policy::TrafficPlan;
use crate::domain::spec::PacketSpec;
use crate::domain::transmission::TransmissionPlan;
use crate::engine::ports::{EngineOutput, PortResult};
use crate::output::{self, OutputController, OutputFormat};

#[derive(Debug, Clone)]
pub(crate) struct OutputEventSink {
    controller: OutputController,
    format: Option<OutputFormat>,
}

impl OutputEventSink {
    pub(crate) fn new(format: Option<OutputFormat>) -> Self {
        Self {
            controller: OutputController::new(format),
            format,
        }
    }
}

impl EngineOutput for OutputEventSink {
    fn emit_preflight_summary(&self, spec: &PacketSpec, plan: &TransmissionPlan) -> PortResult<()> {
        self.controller.emit_preflight_summary(spec, plan)
    }

    #[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
    fn emit_traffic_plan_summary(&self, plan: &TrafficPlan) -> PortResult<()> {
        self.controller.emit_traffic_plan_summary(plan)
    }

    fn emit_listener_event(&self, event: &ListenerEvent) {
        self.controller.emit_listener_event(event);
    }

    fn emit_text_output(&self, rendered: &str) -> PortResult<()> {
        self.controller.emit_text_output(rendered);
        Ok(())
    }

    fn format_dns_dry_run(&self, request: &DnsRequest) -> PortResult<String> {
        match self.format {
            Some(OutputFormat::Json) => output::format_dns_dry_run_json(request),
            _ => Ok(output::format_dns_dry_run(request)),
        }
    }

    fn format_dns_response(&self, result: &DnsQueryResult) -> PortResult<String> {
        match self.format {
            Some(OutputFormat::Json) => output::format_dns_message_json(result),
            _ => Ok(output::format_dns_message(result)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::command::{DnsQuestion, DnsTransport, DnsTransportMode};
    use crate::engine::ports::EngineOutput;

    fn request() -> DnsRequest {
        DnsRequest {
            domain: "example.test".to_string(),
            record_type: "A".to_string(),
            server: "1.1.1.1:53".to_string(),
            timeout: 500,
            transaction_id: Some(0x1234),
            transport: DnsTransportMode::Udp,
            retries: 1,
        }
    }

    fn result() -> DnsQueryResult {
        DnsQueryResult {
            id: 0x1234,
            opcode: "Query".to_string(),
            response_code: "NoError".to_string(),
            flags: vec!["RD".to_string()],
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
    fn dns_dry_run_formatter_defaults_to_text_and_selects_json() {
        let text = OutputEventSink::new(None)
            .format_dns_dry_run(&request())
            .unwrap();
        let json = OutputEventSink::new(Some(OutputFormat::Json))
            .format_dns_dry_run(&request())
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(text.starts_with("Dry-run DNS query:"));
        assert_eq!(value["mode"], "dry_run");
        assert_eq!(value["query"]["domain"], "example.test");
    }

    #[test]
    fn dns_response_formatter_defaults_to_text_and_selects_json() {
        let text = OutputEventSink::new(None)
            .format_dns_response(&result())
            .unwrap();
        let json = OutputEventSink::new(Some(OutputFormat::Json))
            .format_dns_response(&result())
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(text.contains("Metadata: transport=udp attempts=1"));
        assert_eq!(value["mode"], "response");
        assert_eq!(value["metadata"]["transport_used"], "udp");
    }
}
