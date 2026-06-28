use serde::Serialize;

use crate::engine::preflight::PreflightView;
use crate::engine::spec::{PacketSpec, PayloadSource, TransportSpec};

use super::format::format_preview;

#[derive(Debug, Clone, Serialize)]
pub struct PreflightReport {
    pub destination: String,
    pub protocol: &'static str,
    pub count: Option<u64>,
    pub send_mode: &'static str,
    pub mode: &'static str,
    pub destination_family: &'static str,
    pub target: serde_json::Value,
    pub layer2: serde_json::Value,
    pub ip: Option<serde_json::Value>,
    pub transport: serde_json::Value,
    pub payload: serde_json::Value,
    pub transmit: serde_json::Value,
    pub listener: serde_json::Value,
    pub rules_file: Option<String>,
    pub logging: serde_json::Value,
}

impl PreflightReport {
    pub(crate) fn summary_line(&self) -> String {
        let count = self
            .count
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unbounded".to_string());
        format!(
            "Summary: dest={} proto={} count={} mode={}",
            self.destination, self.protocol, count, self.mode
        )
    }
}

pub(crate) fn preflight_report(spec: &PacketSpec, view: &PreflightView) -> PreflightReport {
    PreflightReport {
        destination: view.destination.clone(),
        protocol: view.transport,
        count: view.count,
        send_mode: view.send_mode,
        mode: view.mode,
        destination_family: view.destination_family,
        target: serde_json::json!({
            "address": view.destination,
            "interface": view.interface
        }),
        layer2: serde_json::json!({
            "smac": spec.layer2.source.as_ref().map(|mac| mac.to_string()),
            "dmac": spec.layer2.destination.as_ref().map(|mac| mac.to_string()),
            "ethertype": spec.layer2.ethertype
        }),
        ip: spec.ip.as_ref().map(|ip| {
            serde_json::json!({
                "src": ip.source,
                "dst": ip.destination,
                "ttl": ip.ttl,
                "tos": ip.tos,
                "id": ip.identification,
                "fragment": {
                    "mtu": ip.fragmentation.mtu,
                    "offset": ip.fragmentation.offset,
                    "mf": ip.fragmentation.more_fragments,
                    "df": ip.fragmentation.dont_fragment,
                    "overlap": ip.fragmentation.overlap,
                    "teardrop": ip.fragmentation.teardrop,
                    "profile": ip
                        .fragmentation
                        .profile
                        .map(|profile| profile.to_string()),
                    "id": ip.fragmentation.fragment_id
                }
            })
        }),
        transport: transport_json(spec),
        payload: payload_json(spec),
        transmit: serde_json::json!({
            "count": view.transmit.count,
            "interval_ms": view.transmit.interval.map(|d| d.as_millis()),
            "flood": view.transmit.flood,
            "loop": view.transmit.loop_send,
            "force_layer3": view.transmit.force_layer3,
            "auto_layer3": view.transmit.auto_layer3,
            "layer3_active": view.transmit.is_layer3(),
            "send_mode": view.send_mode
        }),
        listener: serde_json::json!({
            "enabled": spec.listener.enabled,
            "filter": spec.listener.filter,
            "promisc": spec.listener.promiscuous,
            "show_reply": spec.listener.show_reply,
            "timeout_secs": spec.listener.timeout.map(|d| d.as_secs()),
            "pcap_save": spec
                .listener
                .capture_file
                .as_ref()
                .map(|p| p.display().to_string()),
            "implicit": spec.listener.implicit,
            "queue_capacity": spec.listener.queue_capacity
        }),
        rules_file: spec.rules_file.as_ref().map(|p| p.display().to_string()),
        logging: serde_json::json!({
            "log_file": spec.logging.log_file.as_ref().map(|p| p.display().to_string()),
            "pcap_write": spec.logging.pcap_write.as_ref().map(|p| p.display().to_string()),
            "metrics_json": spec
                .logging
                .metrics_json
                .as_ref()
                .map(|p| p.display().to_string())
        }),
    }
}

fn payload_json(plan: &PacketSpec) -> serde_json::Value {
    match &plan.payload.source {
        PayloadSource::Empty => serde_json::json!({"type": "empty"}),
        PayloadSource::Inline(data) => {
            serde_json::json!({"type": "inline", "value": data})
        }
        PayloadSource::Hex(hex) => serde_json::json!({"type": "hex", "value": hex}),
        PayloadSource::File(path) => serde_json::json!({
            "type": "file",
            "path": path.display().to_string()
        }),
        PayloadSource::Random(size) => serde_json::json!({
            "type": "random",
            "size": size
        }),
        PayloadSource::Dns { query, record_type } => serde_json::json!({
            "type": "dns",
            "query": query,
            "record_type": record_type
        }),
        PayloadSource::Http { method, path, host } => serde_json::json!({
            "type": "http",
            "method": method,
            "path": path,
            "host": host
        }),
        PayloadSource::TlsClientHello { server_name } => serde_json::json!({
            "type": "tls_client_hello",
            "server_name": server_name
        }),
        PayloadSource::Bytes(bytes) => serde_json::json!({
            "type": "bytes",
            "size": bytes.len(),
            "preview_hex": format_preview(bytes)
        }),
    }
}

fn transport_json(plan: &PacketSpec) -> serde_json::Value {
    match &plan.transport {
        TransportSpec::Auto => serde_json::json!({"mode": "auto"}),
        TransportSpec::Tcp(spec) => serde_json::json!({
            "mode": "tcp",
            "sport": spec.source_port,
            "dport": spec.destination_port,
            "flags": {
                "syn": spec.flags.syn,
                "ack": spec.flags.ack,
                "fin": spec.flags.fin,
                "rst": spec.flags.rst,
                "psh": spec.flags.psh,
                "urg": spec.flags.urg
            },
            "seq": spec.sequence,
            "ack": spec.acknowledgement,
            "window": spec.window_size,
            "options": spec
                .options
                .as_ref()
                .map(|opts| opts.iter().map(|b| format!("{:02x}", b)).collect::<String>())
        }),
        TransportSpec::Udp(spec) => serde_json::json!({
            "mode": "udp",
            "sport": spec.source_port,
            "dport": spec.destination_port
        }),
        TransportSpec::Icmp(spec) => serde_json::json!({
            "mode": "icmp",
            "type": spec.kind,
            "code": spec.code,
            "id": spec.identifier,
            "seq": spec.sequence
        }),
        TransportSpec::Icmpv6(spec) => serde_json::json!({
            "mode": "icmpv6",
            "type": spec.kind,
            "code": spec.code,
            "id": spec.identifier,
            "seq": spec.sequence
        }),
    }
}
