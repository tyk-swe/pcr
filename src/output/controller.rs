// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;

use crate::domain::event::ListenerEvent;
use crate::domain::net::MacAddress;
#[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
use crate::domain::policy::{PolicyOutcome, TrafficPlan};
use crate::domain::report::PreflightView;
use crate::domain::spec::{PacketSpec, PayloadSource};
use crate::domain::transmission::TransmissionPlan;

use super::format::{format_preview, render_listener_hex};
use super::report::{preflight_report, PreflightReport};
use super::OutputFormat;
use super::{OutputWriter, StdOutputWriter};

#[derive(Clone)]
pub(crate) struct OutputController {
    default_format: Option<OutputFormat>,
    writer: Arc<dyn OutputWriter>,
}

impl OutputController {
    pub(crate) fn new(default_format: Option<OutputFormat>) -> Self {
        Self::with_writer(default_format, Arc::new(StdOutputWriter))
    }

    pub(crate) fn with_writer(
        default_format: Option<OutputFormat>,
        writer: Arc<dyn OutputWriter>,
    ) -> Self {
        Self {
            default_format,
            writer,
        }
    }

    pub(crate) fn emit_preflight_view_summary(
        &self,
        spec: &PacketSpec,
        view: &PreflightView,
    ) -> Result<()> {
        let report = preflight_report(spec, view);
        match self.default_format.unwrap_or(OutputFormat::Summary) {
            OutputFormat::Summary => self.print_summary(&report)?,
            OutputFormat::Detailed => self.print_detailed(spec, view)?,
            OutputFormat::Hex => self.print_hex_preview(spec)?,
            OutputFormat::Json => self.print_json_preview(&report)?,
        }
        Ok(())
    }

    pub(crate) fn emit_preflight_summary(
        &self,
        spec: &PacketSpec,
        plan: &TransmissionPlan,
    ) -> Result<()> {
        let view = PreflightView::from_transmission_plan(plan)?;
        self.emit_preflight_view_summary(spec, &view)
    }

    pub(crate) fn emit_listener_event(&self, event: &ListenerEvent) {
        match self.default_format.unwrap_or(OutputFormat::Summary) {
            OutputFormat::Summary => self.print_listener_summary(event),
            OutputFormat::Detailed => self.print_listener_detailed(event),
            OutputFormat::Hex => self.print_listener_hex(event),
            OutputFormat::Json => self.print_listener_json(event),
        }
    }

    #[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
    pub(crate) fn emit_traffic_plan_summary(&self, plan: &TrafficPlan) -> Result<()> {
        match self.default_format.unwrap_or(OutputFormat::Summary) {
            OutputFormat::Json => {
                let report = serde_json::json!({
                    "mode": "dry_run",
                    "plan": plan,
                    "policy": PolicyOutcome::allowed(),
                });
                self.write_stdout_line(&serde_json::to_string_pretty(&report)?)?;
            }
            OutputFormat::Detailed => {
                let mut output = self.render_traffic_plan_summary(plan);
                output.push_str(&format!("Target scope: {}\n", plan.target_scope));
                output.push_str(&format!("Batch size: {}\n", plan.batch_size));
                output.push_str(&format!("Rate limit: {:?}\n", plan.rate_per_sec));
                output.push_str(&format!(
                    "Required privileges: {:?}\n",
                    plan.required_privileges
                ));
                output.push_str("Policy: allowed\n");
                self.write_stdout(output.as_bytes())?;
            }
            OutputFormat::Summary | OutputFormat::Hex => {
                let output = self.render_traffic_plan_summary(plan);
                self.write_stdout(output.as_bytes())?;
            }
        }
        Ok(())
    }

    fn print_summary(&self, report: &PreflightReport) -> Result<()> {
        self.write_stdout(self.render_compact_plan(report).as_bytes())?;
        Ok(())
    }

    #[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
    fn render_traffic_plan_summary(&self, plan: &TrafficPlan) -> String {
        let estimated = plan
            .estimated_packets
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unbounded".to_string());
        format!(
            "Plan: mode={} targets={} ports={} estimated_packets={} scope={} policy=allowed",
            plan.mode, plan.target_count, plan.port_count, estimated, plan.target_scope
        ) + "\n"
    }

    fn print_detailed(&self, spec: &PacketSpec, view: &PreflightView) -> Result<()> {
        let mut output = String::new();
        output.push_str(&format!("Target: {:?}\n", spec.target));
        output.push_str(&format!("Planned destination: {}\n", view.destination));
        output.push_str(&format!(
            "Planned destination reason: {}\n",
            view.destination_reason
        ));
        output.push_str(&format!("Planned interface: {}\n", view.interface));
        output.push_str(&format!(
            "Planned interface reason: {}\n",
            view.interface_reason
        ));
        output.push_str(&format!("Planned source IP: {}\n", view.source_ip));
        output.push_str(&format!("Planned source reason: {}\n", view.source_reason));
        output.push_str(&format!("Planned mode: {}\n", view.mode));
        output.push_str(&format!("Layer2: {:?}\n", spec.layer2));
        output.push_str(&format!("IP: {:?}\n", spec.ip));
        if let Some(ip) = spec.ip.as_ref() {
            if let Some(profile) = ip.fragmentation.profile {
                output.push_str(&format!("Fragmentation profile: {}\n", profile));
            }
            if let Some(id) = ip.fragmentation.fragment_id {
                output.push_str(&format!("Fragment identification: {}\n", id));
            }
        }
        output.push_str(&format!("Transport: {:?}\n", spec.transport));
        output.push_str(&format!(
            "Destination family: {}\n",
            view.destination_family
        ));
        output.push_str(&format!("Payload: {:?}\n", spec.payload));
        output.push_str(&format!("Transmit: {:?}\n", view.transmit));
        output.push_str(&format!("Listener: {:?}\n", spec.listener));
        output.push_str(&format!("Logging: {:?}\n", spec.logging));
        output.push_str(&format!("Rules: {:?}\n", spec.rules_file));
        self.write_stdout(output.as_bytes())?;
        Ok(())
    }

    fn print_hex_preview(&self, plan: &PacketSpec) -> Result<()> {
        let output = match &plan.payload.source {
            PayloadSource::Hex(data) => format!("hex payload: {data}\n"),
            PayloadSource::Inline(data) => {
                format!("hex view (from string): {:02x?}\n", data.as_bytes())
            }
            PayloadSource::File(path) => format!(
                "payload sourced from file {}; load to inspect hex\n",
                path.display()
            ),
            PayloadSource::Random(size) => {
                format!("payload will be random ({} bytes)\n", size)
            }
            PayloadSource::Dns { query, record_type } => {
                format!("payload: DNS query for {} ({})\n", query, record_type)
            }
            PayloadSource::Http { method, path, host } => format!(
                "payload: HTTP {} {} (Host: {})\n",
                method,
                path,
                host.as_deref().unwrap_or("<none>")
            ),
            PayloadSource::TlsClientHello { server_name } => {
                format!("payload: TLS Client Hello (SNI: {})\n", server_name)
            }
            PayloadSource::Bytes(bytes) => {
                format!("payload: {} bytes (raw)\n", bytes.len())
            }
            PayloadSource::Empty => "no payload supplied\n".to_string(),
        };
        self.write_stdout(output.as_bytes())?;
        Ok(())
    }

    fn print_json_preview(&self, report: &PreflightReport) -> Result<()> {
        self.write_stdout_line(&serde_json::to_string_pretty(report)?)?;
        Ok(())
    }

    fn print_listener_summary(&self, event: &ListenerEvent) {
        struct AddrDisplay<'a> {
            net: Option<&'a IpAddr>,
            l2: Option<&'a MacAddress>,
        }

        impl fmt::Display for AddrDisplay<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if let Some(net) = self.net {
                    write!(f, "{}", net)
                } else if let Some(l2) = self.l2 {
                    write!(f, "{}", l2)
                } else {
                    write!(f, "unknown")
                }
            }
        }

        let src = AddrDisplay {
            net: event.network_source.as_ref(),
            l2: event.layer2_source.as_ref(),
        };
        let dst = AddrDisplay {
            net: event.network_destination.as_ref(),
            l2: event.layer2_destination.as_ref(),
        };

        let proto = event
            .transport
            .as_deref()
            .or(event.network_protocol.as_deref())
            .unwrap_or("frame");

        if event.show_payload && !event.data.is_empty() {
            let _ = self.write_stdout_line(&format!(
                "RX {} -> {} {} ({} bytes) payload={} bytes",
                src,
                dst,
                proto,
                event.length,
                event.data.len()
            ));
        } else {
            let _ = self.write_stdout_line(&format!(
                "RX {} -> {} {} ({} bytes)",
                src, dst, proto, event.length
            ));
        }
    }

    fn print_listener_detailed(&self, event: &ListenerEvent) {
        self.print_listener_summary(event);
        let mut output = String::new();
        if let Some(detail) = event.detail.as_deref() {
            output.push_str(&format!("Detail: {}\n", detail));
        }
        if let Some(l2_src) = event.layer2_source.as_ref() {
            output.push_str(&format!("Layer2 src: {}\n", l2_src));
        }
        if let Some(l2_dst) = event.layer2_destination.as_ref() {
            output.push_str(&format!("Layer2 dst: {}\n", l2_dst));
        }
        if let Some(net_proto) = event.network_protocol.as_deref() {
            output.push_str(&format!("Network: {}\n", net_proto));
        }
        if let Some(src) = event.network_source.as_ref() {
            output.push_str(&format!("Network src: {}\n", src));
        }
        if let Some(dst) = event.network_destination.as_ref() {
            output.push_str(&format!("Network dst: {}\n", dst));
        }
        if let Some(transport) = event.transport.as_deref() {
            output.push_str(&format!("Transport: {}\n", transport));
        }
        if !event.data.is_empty() {
            output.push_str(&format!("Preview: {}\n", format_preview(&event.data)));
            if event.truncated {
                output.push_str("Preview truncated; re-run with --show-reply for full payload\n");
            }
        }
        let _ = self.write_stdout(output.as_bytes());
    }

    fn print_listener_hex(&self, event: &ListenerEvent) {
        let (body, trailer) = render_listener_hex(event);
        let _ = self.write_stdout_line(&body);
        if let Some(trailer) = trailer {
            let _ = self.write_stdout_line(&trailer);
        }
    }

    fn print_listener_json(&self, event: &ListenerEvent) {
        let timestamp = event
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or_default();

        let json = serde_json::json!({
            "timestamp": timestamp,
            "length": event.length,
            "layer2": {
                "source": event.layer2_source.map(|m| m.to_string()),
                "destination": event.layer2_destination.map(|m| m.to_string())
            },
            "network": {
                "source": event.network_source,
                "destination": event.network_destination,
                "protocol": event.network_protocol
            },
            "transport": event.transport,
            "detail": event.detail,
            "payload": {
                "bytes": event.data,
                "truncated": event.truncated,
                "full": event.show_payload
            }
        });

        match serde_json::to_string(&json) {
            Ok(s) => {
                let _ = self.write_stdout_line(&s);
            }
            Err(e) => {
                let _ = self
                    .write_stderr_line(&format!("failed to serialize listener event to JSON: {e}"));
            }
        }
    }

    pub(crate) fn write_stdout(&self, bytes: &[u8]) -> io::Result<()> {
        self.writer.stdout(bytes)
    }

    pub(crate) fn write_stderr(&self, bytes: &[u8]) -> io::Result<()> {
        self.writer.stderr(bytes)
    }

    pub(crate) fn write_stdout_line(&self, line: &str) -> io::Result<()> {
        self.write_stdout(format!("{line}\n").as_bytes())
    }

    pub(crate) fn write_stderr_line(&self, line: &str) -> io::Result<()> {
        self.write_stderr(format!("{line}\n").as_bytes())
    }

    fn render_compact_plan(&self, report: &PreflightReport) -> String {
        let selected_destination = report
            .selection
            .get("destination")
            .and_then(|value| value.get("ip"))
            .and_then(|value| value.as_str())
            .unwrap_or(&report.destination);
        let destination_reason = report
            .selection
            .get("destination")
            .and_then(|value| value.get("reason"))
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let interface = report
            .selection
            .get("interface")
            .and_then(|value| value.get("name"))
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let interface_reason = report
            .selection
            .get("interface")
            .and_then(|value| value.get("reason"))
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let source_ip = report
            .selection
            .get("source")
            .and_then(|value| value.get("ip"))
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let source_reason = report
            .selection
            .get("source")
            .and_then(|value| value.get("reason"))
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let count = report
            .count
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unbounded".to_string());
        let payload = render_payload_summary(&report.payload);

        format!(
            "Plan: {} packet\n  target:       {}\n  resolved dst: {}      reason={}\n  interface:    {}             reason={}\n  source ip:    {}      reason={}\n  mode:         {}\n  payload:      {}\n  count:        {}\n  policy:       {}\n",
            report.protocol,
            report.destination,
            selected_destination,
            destination_reason,
            interface,
            interface_reason,
            source_ip,
            source_reason,
            report.mode,
            payload,
            count,
            report.policy.status
        )
    }
}

fn render_payload_summary(payload: &serde_json::Value) -> String {
    match payload.get("type").and_then(|value| value.as_str()) {
        Some("inline") => {
            let bytes = payload
                .get("value")
                .and_then(|value| value.as_str())
                .map(str::len)
                .unwrap_or_default();
            format!("inline, {bytes} bytes")
        }
        Some("hex") => "hex".to_string(),
        Some("file") => payload
            .get("path")
            .and_then(|value| value.as_str())
            .map(|path| format!("file, {path}"))
            .unwrap_or_else(|| "file".to_string()),
        Some("random") => payload
            .get("size")
            .and_then(|value| value.as_u64())
            .map(|size| format!("random, {size} bytes"))
            .unwrap_or_else(|| "random".to_string()),
        Some(other) => other.to_string(),
        None => "empty".to_string(),
    }
}
