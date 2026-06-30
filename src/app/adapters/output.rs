// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::domain::command::{DnsQueryResult, DnsRequest};
use crate::domain::event::ListenerEvent;
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

    fn emit_traffic_plan_summary(&self, plan: &TrafficPlan) -> PortResult<()> {
        self.controller.emit_traffic_plan_summary(plan)
    }

    fn emit_listener_event(&self, event: &ListenerEvent) {
        self.controller.emit_listener_event(event);
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
