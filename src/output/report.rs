// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use crate::domain::policy::PolicyOutcome;
use crate::domain::report::PreflightView;
use crate::domain::spec::{PacketSpec, PayloadSource, TransportSpec};

#[cfg(any(test, feature = "fuzz"))]
use super::format::format_preview;

#[derive(Debug, Clone, Serialize)]
pub(super) struct PreflightReport {
    pub destination: String,
    pub protocol: &'static str,
    pub count: Option<u64>,
    pub attempts: Option<u64>,
    pub units_per_attempt: u64,
    pub total_emitted_units: Option<u64>,
    pub send_mode: &'static str,
    pub mode: &'static str,
    pub destination_family: &'static str,
    pub selection: serde_json::Value,
    pub target: serde_json::Value,
    pub layer2: serde_json::Value,
    pub ip: Option<serde_json::Value>,
    pub transport: serde_json::Value,
    pub payload: serde_json::Value,
    pub transmit: serde_json::Value,
    pub listener: serde_json::Value,
    pub rules_file: Option<String>,
    pub logging: serde_json::Value,
    pub policy: PolicyOutcome,
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
        attempts: view.attempts,
        units_per_attempt: view.units_per_attempt,
        total_emitted_units: view.total_emitted_units,
        send_mode: view.send_mode,
        mode: view.mode,
        destination_family: view.destination_family,
        selection: serde_json::json!({
            "interface": {
                "name": view.interface,
                "reason": view.interface_reason
            },
            "source": {
                "ip": view.source_ip,
                "reason": view.source_reason
            },
            "destination": {
                "ip": view.selected_destination_ip,
                "reason": view.destination_reason
            }
        }),
        target: serde_json::json!({
            "address": view.destination,
            "interface": view.interface,
            "interface_reason": view.interface_reason
        }),
        layer2: serde_json::json!({
            "smac": spec.layer2.source.as_ref().map(ToString::to_string),
            "dmac": spec.layer2.destination.as_ref().map(ToString::to_string),
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
        policy: PolicyOutcome::allowed(),
    }
}

fn payload_json(spec: &PacketSpec) -> serde_json::Value {
    match &spec.payload.source {
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
        #[cfg(any(test, feature = "fuzz"))]
        PayloadSource::Bytes(bytes) => serde_json::json!({
            "type": "bytes",
            "size": bytes.len(),
            "preview_hex": format_preview(bytes)
        }),
    }
}

fn transport_json(spec: &PacketSpec) -> serde_json::Value {
    match &spec.transport {
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
                "urg": spec.flags.urg,
                "ece": spec.flags.ece,
                "cwr": spec.flags.cwr
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
            "seq": spec.sequence,
            "parameter": spec.parameter
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::report::PreflightView;
    use crate::domain::request::{
        FragmentProfile, FragmentRequest, IpRequest, Layer2Request, LoggingRequest, PacketRequest,
        TcpRequest, TransmissionRequest, TransportProtocolRequest, TransportRequest, VlanRequest,
    };
    use crate::domain::spec::{
        IcmpSpec, Icmpv6Spec, ListenerSpec, LoggingSpec, TransmissionSpec, UdpSpec,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn packet_spec() -> PacketSpec {
        let mut spec = PacketSpec::from_request(&PacketRequest {
            layer2: Layer2Request {
                source_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
                destination_mac: Some("11:22:33:44:55:66".to_string()),
                ethertype: Some("ipv4".to_string()),
                vlan: VlanRequest {
                    id: Some(100),
                    priority: Some(3),
                    drop_eligible_indicator: Some(true),
                },
            },
            ip: IpRequest {
                source_ip: Some("192.0.2.1".to_string()),
                destination_ip: Some("198.51.100.1".to_string()),
                ttl: Some(31),
                tos: Some(16),
                identification: Some(99),
                fragment: FragmentRequest {
                    mtu: Some(576),
                    offset: Some(8),
                    more_fragments: Some(true),
                    profile: Some(FragmentProfile::Overlap),
                    ..Default::default()
                },
                ..Default::default()
            },
            transport: TransportRequest {
                source_port: Some(1234),
                destination_port: Some(443),
                command: Some(TransportProtocolRequest::Tcp(TcpRequest {
                    flags: Some("SA".to_string()),
                    sequence: Some(1),
                    acknowledgement: Some(2),
                    window_size: Some(4096),
                    options_hex: Some("020405b4".to_string()),
                    ..Default::default()
                })),
            },
            transmit: TransmissionRequest {
                count: Some(2),
                interval: Some("10ms".to_string()),
                force_layer3: Some(true),
                ..Default::default()
            },
            rules_file: Some("rules.yml".to_string()),
            logging: LoggingRequest {
                log_file: Some("app.log".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

        spec.payload.source = PayloadSource::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        spec.ip.as_mut().unwrap().fragmentation.fragment_id = Some(1234);
        spec.listener = ListenerSpec {
            enabled: true,
            filter: Some("tcp port 443".to_string()),
            promiscuous: true,
            show_reply: true,
            timeout: Some(Duration::from_secs(5)),
            capture_file: Some(PathBuf::from("capture.pcap")),
            implicit: true,
            queue_capacity: Some(128),
        };
        spec.logging = LoggingSpec {
            log_file: Some(PathBuf::from("app.log")),
            pcap_write: Some(PathBuf::from("sent.pcap")),
            metrics_json: Some(PathBuf::from("metrics.json")),
        };
        spec
    }

    fn preflight_view(transmit: TransmissionSpec) -> PreflightView {
        PreflightView {
            destination: "198.51.100.1".to_string(),
            selected_destination_ip: "198.51.100.1".to_string(),
            destination_reason: "target_literal",
            destination_family: "IPv4",
            interface: "eth0".to_string(),
            interface_reason: "explicit_interface",
            source_ip: "192.0.2.1".to_string(),
            source_reason: "explicit_source_ip",
            mode: "L3",
            transport: "TCP",
            count: Some(2),
            attempts: Some(2),
            units_per_attempt: 1,
            total_emitted_units: Some(2),
            send_mode: "finite",
            transmit,
        }
    }

    #[test]
    fn preflight_report_summary_line_formats_bounded_and_unbounded_counts() {
        let mut report =
            preflight_report(&packet_spec(), &preflight_view(TransmissionSpec::default()));
        assert_eq!(
            report.summary_line(),
            "Summary: dest=198.51.100.1 proto=TCP count=2 mode=L3"
        );

        report.count = None;
        assert_eq!(
            report.summary_line(),
            "Summary: dest=198.51.100.1 proto=TCP count=unbounded mode=L3"
        );
    }

    #[test]
    fn preflight_report_includes_selection_transmit_listener_and_logging() {
        let spec = packet_spec();
        let report = preflight_report(&spec, &preflight_view(spec.transmit.clone()));

        assert_eq!(report.selection["interface"]["name"], "eth0");
        assert_eq!(report.selection["source"]["reason"], "explicit_source_ip");
        assert_eq!(report.transmit["count"], 2);
        assert_eq!(report.transmit["interval_ms"], 10);
        assert_eq!(report.transmit["force_layer3"], true);
        assert_eq!(report.transmit["layer3_active"], true);
        assert_eq!(report.listener["enabled"], true);
        assert_eq!(report.listener["filter"], "tcp port 443");
        assert_eq!(report.listener["timeout_secs"], 5);
        assert_eq!(report.listener["pcap_save"], "capture.pcap");
        assert_eq!(report.listener["queue_capacity"], 128);
        assert_eq!(report.rules_file.as_deref(), Some("rules.yml"));
        assert_eq!(report.logging["log_file"], "app.log");
        assert_eq!(report.logging["pcap_write"], "sent.pcap");
        assert_eq!(report.logging["metrics_json"], "metrics.json");
        assert_eq!(report.policy, PolicyOutcome::allowed());
    }

    #[test]
    fn preflight_report_formats_layer_ip_transport_and_bytes_payload() {
        let mut spec = packet_spec();
        if let TransportSpec::Tcp(transport) = &mut spec.transport {
            transport.flags.ece = true;
            transport.flags.cwr = true;
        }
        let report = preflight_report(&spec, &preflight_view(spec.transmit.clone()));

        assert_eq!(report.layer2["smac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(report.layer2["dmac"], "11:22:33:44:55:66");
        assert_eq!(report.layer2["ethertype"], 0x0800);
        assert_eq!(report.ip.as_ref().unwrap()["ttl"], 31);
        assert_eq!(
            report.ip.as_ref().unwrap()["fragment"]["profile"],
            "overlap"
        );
        assert_eq!(report.transport["mode"], "tcp");
        assert_eq!(report.transport["sport"], 1234);
        assert_eq!(report.transport["flags"]["syn"], true);
        assert_eq!(report.transport["flags"]["ack"], true);
        assert_eq!(report.transport["flags"]["ece"], true);
        assert_eq!(report.transport["flags"]["cwr"], true);
        assert_eq!(report.transport["options"], "020405b4");
        assert_eq!(report.payload["type"], "bytes");
        assert_eq!(report.payload["size"], 4);
        assert_eq!(report.payload["preview_hex"], "de ad be ef");
    }

    #[test]
    fn preflight_report_serializes_output_ready_json_shape() {
        let spec = packet_spec();
        let report = preflight_report(&spec, &preflight_view(spec.transmit.clone()));
        let value = serde_json::to_value(&report).unwrap();

        assert_eq!(value["destination"], "198.51.100.1");
        assert_eq!(value["protocol"], "TCP");
        assert_eq!(value["mode"], "L3");
        assert_eq!(value["selection"]["destination"]["ip"], "198.51.100.1");
        assert_eq!(value["target"]["interface_reason"], "explicit_interface");
        assert_eq!(value["policy"]["status"], "allowed");
    }

    #[test]
    fn payload_json_formats_each_payload_source() {
        let cases = [
            (PayloadSource::Empty, serde_json::json!({"type": "empty"})),
            (
                PayloadSource::Inline("hello".to_string()),
                serde_json::json!({"type": "inline", "value": "hello"}),
            ),
            (
                PayloadSource::Hex("deadbeef".to_string()),
                serde_json::json!({"type": "hex", "value": "deadbeef"}),
            ),
            (
                PayloadSource::File(PathBuf::from("payload.bin")),
                serde_json::json!({"type": "file", "path": "payload.bin"}),
            ),
            (
                PayloadSource::Random(32),
                serde_json::json!({"type": "random", "size": 32}),
            ),
            (
                PayloadSource::Dns {
                    query: "example.test".to_string(),
                    record_type: "AAAA".to_string(),
                },
                serde_json::json!({
                    "type": "dns",
                    "query": "example.test",
                    "record_type": "AAAA"
                }),
            ),
            (
                PayloadSource::TlsClientHello {
                    server_name: "example.test".to_string(),
                },
                serde_json::json!({
                    "type": "tls_client_hello",
                    "server_name": "example.test"
                }),
            ),
        ];

        for (source, expected) in cases {
            let mut spec = PacketSpec::default();
            spec.payload.source = source;

            assert_eq!(payload_json(&spec), expected);
        }

        let mut spec = PacketSpec::default();
        spec.payload.source = PayloadSource::Http {
            method: "GET".to_string(),
            path: "/".to_string(),
            host: Some("example.test".to_string()),
        };
        assert_eq!(
            payload_json(&spec),
            serde_json::json!({
                "type": "http",
                "method": "GET",
                "path": "/",
                "host": "example.test"
            })
        );
    }

    #[test]
    fn transport_json_formats_non_tcp_variants() {
        let mut spec = PacketSpec {
            transport: TransportSpec::Auto,
            ..Default::default()
        };
        assert_eq!(transport_json(&spec), serde_json::json!({"mode": "auto"}));

        spec.transport = TransportSpec::Udp(UdpSpec {
            source_port: Some(1234),
            destination_port: Some(53),
        });
        assert_eq!(
            transport_json(&spec),
            serde_json::json!({"mode": "udp", "sport": 1234, "dport": 53})
        );

        spec.transport = TransportSpec::Icmp(IcmpSpec {
            kind: Some(8),
            code: Some(0),
            identifier: Some(1),
            sequence: Some(2),
        });
        assert_eq!(
            transport_json(&spec),
            serde_json::json!({"mode": "icmp", "type": 8, "code": 0, "id": 1, "seq": 2})
        );

        spec.transport = TransportSpec::Icmpv6(Icmpv6Spec {
            kind: Some(128),
            code: Some(0),
            identifier: Some(3),
            sequence: Some(4),
            parameter: Some(5),
        });
        assert_eq!(
            transport_json(&spec),
            serde_json::json!({
                "mode": "icmpv6",
                "type": 128,
                "code": 0,
                "id": 3,
                "seq": 4,
                "parameter": 5
            })
        );
    }
}
