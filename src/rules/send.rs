// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::domain::request::{PacketRequest, TransportProtocolRequest};
use crate::rules::error::RuleError;
use crate::rules::model::PacketContext;
use crate::rules::template::{apply_template, render_option};

#[derive(Debug, Clone)]
pub(crate) struct RuleSendTemplate {
    request: PacketRequest,
}

impl RuleSendTemplate {
    pub(crate) fn new(request: PacketRequest) -> Self {
        Self { request }
    }

    pub(crate) fn render(&self, packet: Option<&PacketContext>) -> PacketRequest {
        let mut request = self.request.clone();
        render_option(&mut request.destination.destination, packet);
        render_option(&mut request.destination.destination_ip, packet);
        render_option(&mut request.destination.interface, packet);
        render_option(&mut request.layer2.source_mac, packet);
        render_option(&mut request.layer2.destination_mac, packet);
        render_option(&mut request.layer2.ethertype, packet);
        render_option(&mut request.ip.source_ip, packet);
        render_option(&mut request.ip.destination_ip, packet);
        render_vec(&mut request.ipv6.extensions, packet);
        render_option(&mut request.payload.data, packet);
        render_option(&mut request.payload.data_hex, packet);
        render_option(&mut request.payload.data_file, packet);
        render_option(&mut request.payload.dns_query, packet);
        render_option(&mut request.payload.dns_type, packet);
        render_option(&mut request.payload.http_method, packet);
        render_option(&mut request.payload.http_path, packet);
        render_option(&mut request.payload.http_host, packet);
        render_option(&mut request.payload.tls_client_hello, packet);
        render_option(&mut request.transmit.interval, packet);
        render_option(&mut request.listener.filter, packet);
        render_option(&mut request.listener.capture_file, packet);
        render_option(&mut request.rules_file, packet);
        render_option(&mut request.logging.log_file, packet);
        render_option(&mut request.logging.pcap_write, packet);
        render_option(&mut request.logging.metrics_json, packet);
        render_option(&mut request.logging.prometheus_bind, packet);

        if let Some(TransportProtocolRequest::Tcp(tcp)) = request.transport.command.as_mut() {
            render_option(&mut tcp.flags, packet);
            render_option(&mut tcp.timestamps, packet);
            render_option(&mut tcp.options_hex, packet);
        }

        request
    }
}

fn render_vec(fields: &mut [String], packet: Option<&PacketContext>) {
    for field in fields {
        *field = apply_template(field, packet);
    }
}

pub(crate) trait RuleSendDispatcher: std::fmt::Debug + Send + Sync {
    /// Queues a rule send action after rendering and validation.
    ///
    /// `Ok(())` means the send was accepted by the bounded rule executor. Live transmission
    /// completion, failure, and timeout states are reported later through rule-action telemetry.
    fn dispatch(
        &self,
        rule_name: &str,
        template: &RuleSendTemplate,
        packet: Option<&PacketContext>,
    ) -> std::result::Result<(), RuleError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::request::{
        DestinationRequest, IpRequest, Ipv6Request, Layer2Request, ListenerRequest, LoggingRequest,
        PayloadRequest, TcpRequest, TransmissionRequest, TransportRequest,
    };
    use std::time::SystemTime;

    fn packet() -> PacketContext {
        PacketContext {
            description: "TCP".to_string(),
            source: Some("192.0.2.10".to_string()),
            destination: Some("198.51.100.20".to_string()),
            length: 40,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn rule_send_template_renders_nested_request_fields() {
        let template = RuleSendTemplate::new(PacketRequest {
            destination: DestinationRequest {
                destination: Some("{destination}".to_string()),
                ..Default::default()
            },
            ipv6: Ipv6Request {
                extensions: vec!["dest:{source}".to_string()],
            },
            payload: PayloadRequest {
                data: Some("seen {description}".to_string()),
                ..Default::default()
            },
            transport: TransportRequest {
                command: Some(TransportProtocolRequest::Tcp(TcpRequest {
                    flags: Some("{description}".to_string()),
                    options_hex: Some("{length}".to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
            ..Default::default()
        });

        let rendered = template.render(Some(&packet()));

        assert_eq!(
            rendered.destination.destination.as_deref(),
            Some("198.51.100.20")
        );
        assert_eq!(rendered.ipv6.extensions, vec!["dest:192.0.2.10"]);
        assert_eq!(rendered.payload.data.as_deref(), Some("seen TCP"));
        let Some(TransportProtocolRequest::Tcp(tcp)) = rendered.transport.command else {
            panic!("expected rendered TCP request");
        };
        assert_eq!(tcp.flags.as_deref(), Some("TCP"));
        assert_eq!(tcp.options_hex.as_deref(), Some("40"));
    }

    #[test]
    fn rule_send_template_renders_remaining_string_fields() {
        let template = RuleSendTemplate::new(PacketRequest {
            destination: DestinationRequest {
                destination_ip: Some("{destination}".to_string()),
                interface: Some("if-{description}".to_string()),
                ..Default::default()
            },
            layer2: Layer2Request {
                source_mac: Some("{source}".to_string()),
                destination_mac: Some("{destination}".to_string()),
                ethertype: Some("{length}".to_string()),
                ..Default::default()
            },
            ip: IpRequest {
                source_ip: Some("{source}".to_string()),
                destination_ip: Some("{destination}".to_string()),
                ..Default::default()
            },
            payload: PayloadRequest {
                data_hex: Some("{length}".to_string()),
                data_file: Some("/tmp/{description}.bin".to_string()),
                dns_query: Some("{description}.example".to_string()),
                dns_type: Some("{description}".to_string()),
                http_method: Some("{description}".to_string()),
                http_path: Some("/{length}".to_string()),
                http_host: Some("{destination}".to_string()),
                tls_client_hello: Some("{source}".to_string()),
                ..Default::default()
            },
            transmit: TransmissionRequest {
                interval: Some("{length}ms".to_string()),
                ..Default::default()
            },
            listener: ListenerRequest {
                filter: Some("host {source}".to_string()),
                capture_file: Some("{description}.pcap".to_string()),
                ..Default::default()
            },
            rules_file: Some("{description}.yaml".to_string()),
            logging: LoggingRequest {
                log_file: Some("{description}.log".to_string()),
                pcap_write: Some("{destination}.pcap".to_string()),
                metrics_json: Some("{source}.json".to_string()),
                prometheus_bind: Some("{destination}:9090".to_string()),
                ..Default::default()
            },
            transport: TransportRequest {
                command: Some(TransportProtocolRequest::Tcp(TcpRequest {
                    timestamps: Some("{length}:{length}".to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
            ..Default::default()
        });

        let rendered = template.render(Some(&packet()));

        assert_eq!(
            rendered.destination.destination_ip.as_deref(),
            Some("198.51.100.20")
        );
        assert_eq!(rendered.destination.interface.as_deref(), Some("if-TCP"));
        assert_eq!(rendered.layer2.source_mac.as_deref(), Some("192.0.2.10"));
        assert_eq!(
            rendered.layer2.destination_mac.as_deref(),
            Some("198.51.100.20")
        );
        assert_eq!(rendered.layer2.ethertype.as_deref(), Some("40"));
        assert_eq!(rendered.ip.source_ip.as_deref(), Some("192.0.2.10"));
        assert_eq!(rendered.ip.destination_ip.as_deref(), Some("198.51.100.20"));
        assert_eq!(rendered.payload.data_hex.as_deref(), Some("40"));
        assert_eq!(rendered.payload.data_file.as_deref(), Some("/tmp/TCP.bin"));
        assert_eq!(rendered.payload.dns_query.as_deref(), Some("TCP.example"));
        assert_eq!(rendered.payload.dns_type.as_deref(), Some("TCP"));
        assert_eq!(rendered.payload.http_method.as_deref(), Some("TCP"));
        assert_eq!(rendered.payload.http_path.as_deref(), Some("/40"));
        assert_eq!(rendered.payload.http_host.as_deref(), Some("198.51.100.20"));
        assert_eq!(
            rendered.payload.tls_client_hello.as_deref(),
            Some("192.0.2.10")
        );
        assert_eq!(rendered.transmit.interval.as_deref(), Some("40ms"));
        assert_eq!(rendered.listener.filter.as_deref(), Some("host 192.0.2.10"));
        assert_eq!(rendered.listener.capture_file.as_deref(), Some("TCP.pcap"));
        assert_eq!(rendered.rules_file.as_deref(), Some("TCP.yaml"));
        assert_eq!(rendered.logging.log_file.as_deref(), Some("TCP.log"));
        assert_eq!(
            rendered.logging.pcap_write.as_deref(),
            Some("198.51.100.20.pcap")
        );
        assert_eq!(
            rendered.logging.metrics_json.as_deref(),
            Some("192.0.2.10.json")
        );
        assert_eq!(
            rendered.logging.prometheus_bind.as_deref(),
            Some("198.51.100.20:9090")
        );
        let Some(TransportProtocolRequest::Tcp(tcp)) = rendered.transport.command else {
            panic!("expected rendered TCP request");
        };
        assert_eq!(tcp.timestamps.as_deref(), Some("40:40"));
    }
}
