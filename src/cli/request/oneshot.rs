// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::{options, req};

impl From<&options::OneShotOptions> for req::PacketRequest {
    fn from(options: &options::OneShotOptions) -> Self {
        Self {
            destination: req::DestinationRequest {
                destination: options.destination.clone(),
                destination_ip: options.ip.destination_ip.clone(),
                interface: options.transmit.interface.clone(),
                resolved_destination: None,
            },
            layer2: req::Layer2Request::from(&options.layer2),
            ip: req::IpRequest::from(&options.ip),
            ipv6: req::Ipv6Request::from(&options.ip),
            transport: req::TransportRequest::from(&options.transport),
            payload: req::PayloadRequest::from(&options.payload),
            transmit: req::TransmissionRequest::from(&options.transmit),
            listener: req::ListenerRequest::from(&options.listen),
            rules_file: options.rule.rules_file.clone(),
            logging: req::LoggingRequest::from(&options.logging),
        }
    }
}

impl From<&options::Layer2Options> for req::Layer2Request {
    fn from(options: &options::Layer2Options) -> Self {
        Self {
            source_mac: options.source_mac.clone(),
            destination_mac: options.destination_mac.clone(),
            ethertype: options.ethertype.clone(),
            vlan: req::VlanRequest::from(&options.vlan),
        }
    }
}

impl From<&options::VlanOptions> for req::VlanRequest {
    fn from(options: &options::VlanOptions) -> Self {
        Self {
            id: options.id,
            priority: options.priority,
            drop_eligible_indicator: options.drop_eligible_indicator,
        }
    }
}

impl From<&options::IpOptions> for req::IpRequest {
    fn from(options: &options::IpOptions) -> Self {
        Self {
            source_ip: options.source_ip.clone(),
            destination_ip: options.destination_ip.clone(),
            prefer_ipv6: options.prefer_ipv6,
            prefer_ipv4: options.prefer_ipv4,
            ttl: options.ttl,
            tos: options.tos,
            identification: options.identification,
            fragment: req::FragmentRequest {
                mtu: options.fragment_mtu,
                offset: options.fragment_offset,
                more_fragments: options.more_fragments,
                dont_fragment: options.dont_fragment,
                overlap: options.fragment_overlap,
                teardrop: options.teardrop,
                profile: options.fragment_profile.map(req::FragmentProfile::from),
                fragment_id: options.fragment_id,
            },
        }
    }
}

impl From<&options::IpOptions> for req::Ipv6Request {
    fn from(options: &options::IpOptions) -> Self {
        Self {
            extensions: options.ipv6_extensions.clone(),
        }
    }
}

impl From<&options::TransportOptions> for req::TransportRequest {
    fn from(options: &options::TransportOptions) -> Self {
        Self {
            command: options
                .command
                .as_ref()
                .map(req::TransportProtocolRequest::from),
            source_port: options.source_port,
            destination_port: options.destination_port,
        }
    }
}

impl From<&options::TransportCommand> for req::TransportProtocolRequest {
    fn from(command: &options::TransportCommand) -> Self {
        match command {
            options::TransportCommand::Tcp(options) => Self::Tcp(req::TcpRequest::from(options)),
            options::TransportCommand::Udp(_) => Self::Udp,
            options::TransportCommand::Icmp(options) => Self::Icmp(req::IcmpRequest::from(options)),
            options::TransportCommand::Icmpv6(options) => {
                Self::Icmpv6(req::Icmpv6Request::from(options))
            }
        }
    }
}

impl From<&options::TcpOptions> for req::TcpRequest {
    fn from(options: &options::TcpOptions) -> Self {
        Self {
            flags: options.flags.clone(),
            sequence: options.sequence,
            acknowledgement: options.acknowledgement,
            window_size: options.window_size,
            mss: options.mss,
            window_scale: options.window_scale,
            sack_permitted: options.sack_permitted,
            timestamps: options.timestamps.clone(),
            options_hex: options.options_hex.clone(),
        }
    }
}

impl From<&options::IcmpOptions> for req::IcmpRequest {
    fn from(options: &options::IcmpOptions) -> Self {
        Self {
            kind: options.kind,
            code: options.code,
            identifier: options.identifier,
            sequence: options.sequence,
        }
    }
}

impl From<&options::Icmpv6Options> for req::Icmpv6Request {
    fn from(options: &options::Icmpv6Options) -> Self {
        Self {
            kind: options.kind,
            code: options.code,
            identifier: options.identifier,
            sequence: options.sequence,
            parameter: options.parameter,
            error: options.error.map(req::Icmpv6ErrorKind::from),
            error_code: options.error_code.map(req::Icmpv6ErrorCode::from),
            mtu: options.mtu,
        }
    }
}

impl From<&options::PayloadOptions> for req::PayloadRequest {
    fn from(options: &options::PayloadOptions) -> Self {
        Self {
            data: options.data.clone(),
            data_hex: options.data_hex.clone(),
            data_file: options.data_file.clone(),
            random_payload_size: options.random_payload_size,
            dns_query: options.dns_query.clone(),
            dns_type: options.dns_type.clone(),
            http_method: options.http_method.clone(),
            http_path: options.http_path.clone(),
            http_host: options.http_host.clone(),
            tls_client_hello: options.tls_client_hello.clone(),
        }
    }
}

impl From<&options::TransmitOptions> for req::TransmissionRequest {
    fn from(options: &options::TransmitOptions) -> Self {
        Self {
            count: options.count,
            interval: options.interval.clone(),
            flood: options.flood,
            loop_forever: options.loop_forever,
            force_layer3: options.force_layer3,
            ipv6_nd: options.ipv6_nd,
        }
    }
}

impl From<&options::ListenOptions> for req::ListenerRequest {
    fn from(options: &options::ListenOptions) -> Self {
        Self {
            listen: options.listen,
            filter: options.filter.clone(),
            promiscuous: options.promiscuous,
            show_reply: options.show_reply,
            timeout: options.timeout,
            capture_file: options.capture_file.clone(),
            queue_capacity: options.queue_capacity,
        }
    }
}

impl From<&options::LoggingOptions> for req::LoggingRequest {
    fn from(options: &options::LoggingOptions) -> Self {
        Self {
            log_file: options.log_file.clone(),
            pcap_write: options.pcap_write.clone(),
            metrics_json: options.metrics_json.clone(),
            log_level: options.log_level.map(req::LogLevel::from),
            structured: options.structured,
            prometheus_bind: options.prometheus_bind.clone(),
            allow_public_metrics: options.allow_public_metrics,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cli::{enums as cli_enums, options};
    use crate::domain::request as req;

    #[test]
    fn packet_request_from_oneshot_maps_nested_sections() {
        let options = options::OneShotOptions {
            destination: Some("example.test".to_string()),
            layer2: options::Layer2Options {
                source_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
                destination_mac: Some("11:22:33:44:55:66".to_string()),
                ethertype: Some("ipv4".to_string()),
                vlan: options::VlanOptions {
                    id: Some(100),
                    priority: Some(3),
                    drop_eligible_indicator: Some(true),
                },
            },
            ip: options::IpOptions {
                source_ip: Some("192.0.2.1".to_string()),
                destination_ip: Some("192.0.2.2".to_string()),
                ttl: Some(32),
                tos: Some(12),
                identification: Some(55),
                fragment_mtu: Some(576),
                fragment_offset: Some(8),
                more_fragments: Some(true),
                fragment_profile: Some(cli_enums::FragmentProfile::Overlap),
                ipv6_extensions: vec!["dest:options=0102".to_string()],
                ..Default::default()
            },
            transmit: options::TransmitOptions {
                count: Some(3),
                interval: Some("10ms".to_string()),
                interface: Some("eth-test".to_string()),
                force_layer3: Some(true),
                ipv6_nd: Some(true),
                ..Default::default()
            },
            listen: options::ListenOptions {
                listen: Some(true),
                filter: Some("icmp".to_string()),
                show_reply: Some(true),
                timeout: Some(5),
                capture_file: Some("out.pcap".to_string()),
                queue_capacity: Some(64),
                ..Default::default()
            },
            rule: options::RuleOptions {
                rules_file: Some("rules.yml".to_string()),
                ..Default::default()
            },
            logging: options::LoggingOptions {
                log_file: Some("app.log".to_string()),
                pcap_write: Some("sent.pcap".to_string()),
                metrics_json: Some("metrics.json".to_string()),
                log_level: Some(cli_enums::LogLevel::Debug),
                structured: Some(true),
                prometheus_bind: Some("127.0.0.1:9090".to_string()),
                allow_public_metrics: Some(true),
            },
            ..Default::default()
        };

        let request = req::PacketRequest::from(&options);

        assert_eq!(
            request.destination.destination.as_deref(),
            Some("example.test")
        );
        assert_eq!(request.destination.interface.as_deref(), Some("eth-test"));
        assert_eq!(
            request.layer2.source_mac.as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(request.layer2.vlan.id, Some(100));
        assert_eq!(request.ip.source_ip.as_deref(), Some("192.0.2.1"));
        assert_eq!(request.ip.fragment.mtu, Some(576));
        assert_eq!(request.ip.fragment.offset, Some(8));
        assert_eq!(request.ip.fragment.more_fragments, Some(true));
        assert_eq!(
            request.ip.fragment.profile,
            Some(req::FragmentProfile::Overlap)
        );
        assert_eq!(request.ipv6.extensions, ["dest:options=0102"]);
        assert_eq!(request.transmit.count, Some(3));
        assert_eq!(request.listener.filter.as_deref(), Some("icmp"));
        assert_eq!(request.rules_file.as_deref(), Some("rules.yml"));
        assert_eq!(request.logging.log_level, Some(req::LogLevel::Debug));
        assert_eq!(
            request.logging.prometheus_bind.as_deref(),
            Some("127.0.0.1:9090")
        );
    }

    #[test]
    fn transport_command_maps_tcp_udp_icmp_and_icmpv6() {
        let tcp = req::TransportProtocolRequest::from(&options::TransportCommand::Tcp(
            options::TcpOptions {
                flags: Some("SA".to_string()),
                sequence: Some(1),
                acknowledgement: Some(2),
                window_size: Some(3),
                mss: Some(4),
                window_scale: Some(5),
                sack_permitted: Some(true),
                timestamps: Some("6:7".to_string()),
                options_hex: None,
            },
        ));
        let udp = req::TransportProtocolRequest::from(&options::TransportCommand::Udp(
            options::UdpOptions::default(),
        ));
        let icmp = req::TransportProtocolRequest::from(&options::TransportCommand::Icmp(
            options::IcmpOptions {
                kind: Some(8),
                code: Some(0),
                identifier: Some(10),
                sequence: Some(11),
            },
        ));
        let icmpv6 = req::TransportProtocolRequest::from(&options::TransportCommand::Icmpv6(
            options::Icmpv6Options {
                kind: Some(128),
                code: Some(0),
                identifier: Some(12),
                sequence: Some(13),
                parameter: Some(14),
                error: Some(cli_enums::Icmpv6ErrorKind::PacketTooBig),
                error_code: Some(cli_enums::Icmpv6ErrorCode::ParameterProblemUnrecognizedOption),
                mtu: Some(1500),
            },
        ));

        assert!(matches!(
            tcp,
            req::TransportProtocolRequest::Tcp(tcp)
                if tcp.flags.as_deref() == Some("SA")
                    && tcp.sequence == Some(1)
                    && tcp.acknowledgement == Some(2)
                    && tcp.window_size == Some(3)
                    && tcp.mss == Some(4)
                    && tcp.window_scale == Some(5)
                    && tcp.sack_permitted == Some(true)
                    && tcp.timestamps.as_deref() == Some("6:7")
        ));
        assert!(matches!(udp, req::TransportProtocolRequest::Udp));
        assert!(matches!(
            icmp,
            req::TransportProtocolRequest::Icmp(icmp)
                if icmp.kind == Some(8)
                    && icmp.code == Some(0)
                    && icmp.identifier == Some(10)
                    && icmp.sequence == Some(11)
        ));
        assert!(matches!(
            icmpv6,
            req::TransportProtocolRequest::Icmpv6(icmpv6)
                if icmpv6.kind == Some(128)
                    && icmpv6.parameter == Some(14)
                    && icmpv6.error == Some(req::Icmpv6ErrorKind::PacketTooBig)
                    && icmpv6.error_code
                        == Some(req::Icmpv6ErrorCode::ParameterProblemUnrecognizedOption)
                    && icmpv6.mtu == Some(1500)
        ));
    }

    #[test]
    fn payload_and_transmission_options_map_without_interpretation() {
        let payload = req::PayloadRequest::from(&options::PayloadOptions {
            data: Some("hello".to_string()),
            data_hex: Some("6869".to_string()),
            data_file: Some("payload.bin".to_string()),
            random_payload_size: Some(8),
            dns_query: Some("example.test".to_string()),
            dns_type: Some("AAAA".to_string()),
            http_method: Some("GET".to_string()),
            http_path: Some("/".to_string()),
            http_host: Some("example.test".to_string()),
            tls_client_hello: Some("example.test".to_string()),
        });
        let transmit = req::TransmissionRequest::from(&options::TransmitOptions {
            count: Some(9),
            interval: Some("1s".to_string()),
            flood: Some(true),
            loop_forever: Some(true),
            interface: Some("eth0".to_string()),
            force_layer3: Some(true),
            ipv6_nd: Some(true),
        });

        assert_eq!(payload.data.as_deref(), Some("hello"));
        assert_eq!(payload.data_hex.as_deref(), Some("6869"));
        assert_eq!(payload.dns_type.as_deref(), Some("AAAA"));
        assert_eq!(transmit.count, Some(9));
        assert_eq!(transmit.interval.as_deref(), Some("1s"));
        assert_eq!(transmit.flood, Some(true));
        assert_eq!(transmit.loop_forever, Some(true));
        assert_eq!(transmit.force_layer3, Some(true));
        assert_eq!(transmit.ipv6_nd, Some(true));
    }
}
