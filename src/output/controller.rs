// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::IpAddr;
use std::time::SystemTime;

use anyhow::Result;

use crate::domain::net::MacAddress;
use crate::domain::policy::{PolicyOutcome, TrafficPlan};
use crate::domain::report::PreflightView;
use crate::domain::spec::{PacketSpec, PayloadSource};
use crate::domain::transmission::{
    emission_accounting, TransmissionLinkType, TransmissionPlan, TransmissionTarget,
};

use super::format::{format_preview, render_listener_hex};
use super::report::{preflight_report, PreflightReport};
use super::ListenerEvent;
use super::OutputFormat;

#[derive(Debug, Clone)]
pub struct OutputController {
    default_format: Option<OutputFormat>,
}

impl OutputController {
    pub fn new(default_format: Option<OutputFormat>) -> Self {
        Self { default_format }
    }

    pub(crate) fn emit_preflight_view_summary(
        &self,
        spec: &PacketSpec,
        view: &PreflightView,
    ) -> Result<()> {
        let report = preflight_report(spec, view);
        match self.default_format.unwrap_or(OutputFormat::Summary) {
            OutputFormat::Summary => self.print_summary(&report),
            OutputFormat::Detailed => self.print_detailed(spec, view),
            OutputFormat::Hex => self.print_hex_preview(spec),
            OutputFormat::Json => self.print_json_preview(&report)?,
        }
        Ok(())
    }

    pub fn emit_preflight_summary(&self, spec: &PacketSpec, plan: &TransmissionPlan) -> Result<()> {
        let view = preflight_view_from_plan(plan)?;
        self.emit_preflight_view_summary(spec, &view)
    }

    pub fn emit_listener_event(&self, event: &ListenerEvent) {
        match self.default_format.unwrap_or(OutputFormat::Summary) {
            OutputFormat::Summary => self.print_listener_summary(event),
            OutputFormat::Detailed => self.print_listener_detailed(event),
            OutputFormat::Hex => self.print_listener_hex(event),
            OutputFormat::Json => self.print_listener_json(event),
        }
    }

    pub fn emit_traffic_plan_summary(&self, plan: &TrafficPlan) -> Result<()> {
        match self.default_format.unwrap_or(OutputFormat::Summary) {
            OutputFormat::Json => {
                let report = serde_json::json!({
                    "mode": "dry_run",
                    "plan": plan,
                    "policy": PolicyOutcome::allowed(),
                });
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            OutputFormat::Detailed => {
                self.print_traffic_plan_summary(plan);
                println!("Target scope: {}", plan.target_scope);
                println!("Batch size: {}", plan.batch_size);
                println!("Rate limit: {:?}", plan.rate_per_sec);
                println!("Required privileges: {:?}", plan.required_privileges);
                println!("Policy: allowed");
            }
            OutputFormat::Summary | OutputFormat::Hex => {
                self.print_traffic_plan_summary(plan);
            }
        }
        Ok(())
    }

    fn print_summary(&self, report: &PreflightReport) {
        println!("{}", report.summary_line());
    }

    fn print_traffic_plan_summary(&self, plan: &TrafficPlan) {
        let estimated = plan
            .estimated_packets
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unbounded".to_string());
        println!(
            "Plan: mode={} targets={} ports={} estimated_packets={} scope={} policy=allowed",
            plan.mode, plan.target_count, plan.port_count, estimated, plan.target_scope
        );
    }

    fn print_detailed(&self, spec: &PacketSpec, view: &PreflightView) {
        println!("Target: {:?}", spec.target);
        println!("Planned destination: {}", view.destination);
        println!("Planned destination reason: {}", view.destination_reason);
        println!("Planned interface: {}", view.interface);
        println!("Planned interface reason: {}", view.interface_reason);
        println!("Planned source IP: {}", view.source_ip);
        println!("Planned source reason: {}", view.source_reason);
        println!("Planned mode: {}", view.mode);
        println!("Layer2: {:?}", spec.layer2);
        println!("IP: {:?}", spec.ip);
        if let Some(ip) = spec.ip.as_ref() {
            if let Some(profile) = ip.fragmentation.profile {
                println!("Fragmentation profile: {}", profile);
            }
            if let Some(id) = ip.fragmentation.fragment_id {
                println!("Fragment identification: {}", id);
            }
        }
        println!("Transport: {:?}", spec.transport);
        println!("Destination family: {}", view.destination_family);
        println!("Payload: {:?}", spec.payload);
        println!("Transmit: {:?}", view.transmit);
        println!("Listener: {:?}", spec.listener);
        println!("Logging: {:?}", spec.logging);
        println!("Rules: {:?}", spec.rules_file);
    }

    fn print_hex_preview(&self, plan: &PacketSpec) {
        match &plan.payload.source {
            PayloadSource::Hex(data) => println!("hex payload: {data}"),
            PayloadSource::Inline(data) => {
                println!("hex view (from string): {:02x?}", data.as_bytes())
            }
            PayloadSource::File(path) => {
                println!(
                    "payload sourced from file {}; load to inspect hex",
                    path.display()
                );
            }
            PayloadSource::Random(size) => {
                println!("payload will be random ({} bytes)", size);
            }
            PayloadSource::Dns { query, record_type } => {
                println!("payload: DNS query for {} ({})", query, record_type);
            }
            PayloadSource::Http { method, path, host } => {
                println!(
                    "payload: HTTP {} {} (Host: {})",
                    method,
                    path,
                    host.as_deref().unwrap_or("<none>")
                );
            }
            PayloadSource::TlsClientHello { server_name } => {
                println!("payload: TLS Client Hello (SNI: {})", server_name);
            }
            PayloadSource::Bytes(bytes) => {
                println!("payload: {} bytes (raw)", bytes.len());
            }
            PayloadSource::Empty => println!("no payload supplied"),
        }
    }

    fn print_json_preview(&self, report: &PreflightReport) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(report)?);
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
            println!(
                "RX {} -> {} {} ({} bytes) payload={} bytes",
                src,
                dst,
                proto,
                event.length,
                event.data.len()
            );
        } else {
            println!("RX {} -> {} {} ({} bytes)", src, dst, proto, event.length);
        }
    }

    fn print_listener_detailed(&self, event: &ListenerEvent) {
        self.print_listener_summary(event);
        if let Some(detail) = event.detail.as_deref() {
            println!("Detail: {}", detail);
        }
        if let Some(l2_src) = event.layer2_source.as_ref() {
            println!("Layer2 src: {}", l2_src);
        }
        if let Some(l2_dst) = event.layer2_destination.as_ref() {
            println!("Layer2 dst: {}", l2_dst);
        }
        if let Some(net_proto) = event.network_protocol.as_deref() {
            println!("Network: {}", net_proto);
        }
        if let Some(src) = event.network_source.as_ref() {
            println!("Network src: {}", src);
        }
        if let Some(dst) = event.network_destination.as_ref() {
            println!("Network dst: {}", dst);
        }
        if let Some(transport) = event.transport.as_deref() {
            println!("Transport: {}", transport);
        }
        if !event.data.is_empty() {
            println!("Preview: {}", format_preview(&event.data));
            if event.truncated {
                println!("Preview truncated; re-run with --show-reply for full payload");
            }
        }
    }

    fn print_listener_hex(&self, event: &ListenerEvent) {
        let (body, trailer) = render_listener_hex(event);
        println!("{}", body);
        if let Some(trailer) = trailer {
            println!("{}", trailer);
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

        match serde_json::to_string_pretty(&json) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("failed to serialize listener event to JSON: {e}");
            }
        }
    }
}

fn preflight_view_from_plan(plan: &TransmissionPlan) -> Result<PreflightView> {
    let accounting =
        emission_accounting(&plan.transmit, plan.policy, plan.summary.frame_count as u64)?;
    let send_mode = if accounting.attempts.is_some() {
        "finite"
    } else {
        "unbounded"
    };

    Ok(PreflightView {
        destination: planned_destination(plan),
        selected_destination_ip: plan.selection.destination_ip.to_string(),
        destination_reason: plan.selection.destination_reason.as_str(),
        destination_family: planned_destination_family(plan),
        interface: plan.interface_name.clone(),
        interface_reason: plan.selection.interface_reason.as_str(),
        source_ip: plan.selection.source_ip.to_string(),
        source_reason: plan.selection.source_reason.as_str(),
        mode: planned_mode(plan),
        transport: plan.summary.transport,
        count: accounting.attempts,
        attempts: accounting.attempts,
        units_per_attempt: accounting.units_per_attempt,
        total_emitted_units: accounting.total_emitted_units,
        send_mode,
        frame_count: plan.summary.frame_count,
        largest_frame_len: plan.summary.largest_frame_len,
        transmit: plan.transmit.clone(),
    })
}

fn planned_destination_family(plan: &TransmissionPlan) -> &'static str {
    match &plan.destination {
        TransmissionTarget::Ipv4(_) => "IPv4",
        TransmissionTarget::Ipv6(_) => "IPv6",
    }
}

fn planned_destination(plan: &TransmissionPlan) -> String {
    match &plan.destination {
        TransmissionTarget::Ipv4(addr) => addr.to_string(),
        TransmissionTarget::Ipv6(addr) => addr.to_string(),
    }
}

fn planned_mode(plan: &TransmissionPlan) -> &'static str {
    if plan.transmit.is_layer3()
        || matches!(
            &plan.link_type,
            TransmissionLinkType::Ipv4 | TransmissionLinkType::Ipv6
        )
    {
        "L3"
    } else {
        "L2"
    }
}
