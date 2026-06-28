use std::net::IpAddr;
use std::path::PathBuf;

use pnet::packet::ethernet::EtherTypes;

use super::error::{SpecError, SpecResult};

use crate::engine::request::{infer_prefer_ipv6_hint, PacketRequest};

use super::destination::{DestinationSpec, TargetAddress};
use super::ip::IpSpec;
use super::ipv6::Ipv6Spec;
use super::layer2::Layer2Spec;
use super::listener::ListenerSpec;
use super::logging::LoggingSpec;
use super::payload::PayloadSpec;
use super::transmission::TransmissionSpec;
use super::transport::TransportSpec;

#[derive(Debug, Clone, Default)]
pub struct PacketSpec {
    pub target: DestinationSpec,
    pub layer2: Layer2Spec,
    pub ip: Option<IpSpec>,
    pub ipv6: Ipv6Spec,
    pub transport: TransportSpec,
    pub payload: PayloadSpec,
    pub transmit: TransmissionSpec,
    pub listener: ListenerSpec,
    pub rules_file: Option<PathBuf>,
    pub logging: LoggingSpec,
}

impl PacketSpec {
    pub fn from_request(request: &PacketRequest) -> SpecResult<Self> {
        let target = DestinationSpec::from_request(&request.destination)?;
        let layer2 = Layer2Spec::from_request(&request.layer2)?;
        let ip = IpSpec::from_request(&request.ip)?;
        let ipv6 = Ipv6Spec::from_request(&request.ipv6)?;
        let prefer_ipv6_hint = infer_prefer_ipv6_hint(request);

        let destination_hint = if let Some(ip) = ip.as_ref().and_then(|ip| ip.destination) {
            Some(ip)
        } else {
            match target.address.as_ref() {
                Some(TargetAddress::Ip(ip)) => Some(*ip),
                Some(TargetAddress::Host(_)) => request.destination.resolved_destination,
                None => None,
            }
        };

        let transport = TransportSpec::from_request(
            &request.transport,
            destination_hint,
            prefer_ipv6_hint.unwrap_or(false),
        )?;
        let payload = PayloadSpec::from_request(&request.payload)?;
        let mut transmit = TransmissionSpec::from_request(&request.transmit)?;

        let resolved_destination = ip
            .as_ref()
            .and_then(|ip| ip.destination)
            .or(destination_hint);
        let ipv6_target = resolved_destination
            .map(|addr| matches!(addr, IpAddr::V6(_)))
            .unwrap_or_else(|| prefer_ipv6_hint.unwrap_or(false));
        transmit.apply_ipv6_defaults(&layer2, ipv6_target);

        let listener = ListenerSpec::from_request(&request.listener)?;
        let rules_file = request.rules_file.as_ref().map(PathBuf::from);
        let logging = LoggingSpec::from_request(&request.logging)?;

        let spec = Self {
            target,
            layer2,
            ip,
            ipv6,
            transport,
            payload,
            transmit,
            listener,
            rules_file,
            logging,
        };
        spec.validate_ip_version_consistency(ipv6_target)?;
        Ok(spec)
    }

    fn validate_ip_version_consistency(&self, ipv6_target: bool) -> SpecResult<()> {
        if let Some(ethertype) = self.layer2.ethertype {
            let expected = if ipv6_target {
                EtherTypes::Ipv6.0
            } else {
                EtherTypes::Ipv4.0
            };

            if matches!(ethertype, value if value == EtherTypes::Ipv4.0 || value == EtherTypes::Ipv6.0)
                && ethertype != expected
            {
                return Err(SpecError::EtherTypeIpVersionMismatch {
                    ethertype,
                    target_version: if ipv6_target { 6 } else { 4 },
                });
            }
        }

        if let Some(ip) = &self.ip {
            if let Some(source) = ip.source {
                if source.is_ipv6() != ipv6_target {
                    return Err(SpecError::SourceIpVersionMismatch {
                        src_ip: source,
                        target_version: if ipv6_target { 6 } else { 4 },
                    });
                }
            }

            if let Some(prefer_v6) = ip.prefer_ipv6 {
                if prefer_v6 != ipv6_target {
                    let conflicting_ip = ip.destination.or(match self.target.address.as_ref() {
                        Some(TargetAddress::Ip(addr)) => Some(*addr),
                        _ => None,
                    });

                    if let Some(target) = conflicting_ip {
                        return Err(SpecError::TargetIpVersionPreferenceMismatch {
                            target,
                            prefer_version: if prefer_v6 { 6 } else { 4 },
                        });
                    }
                }
            }
        }

        if ipv6_target {
            if let Some(ip) = &self.ip {
                if ip.identification.is_some() {
                    return Err(SpecError::IpV4OptionWithIpV6Target { option: "--id" });
                }
                if ip.fragmentation.dont_fragment {
                    return Err(SpecError::IpV4OptionWithIpV6Target {
                        option: "--df-flag",
                    });
                }
            }
            if matches!(&self.transport, TransportSpec::Icmp(_)) {
                return Err(SpecError::IpV4OptionWithIpV6Target { option: "icmp" });
            }
        } else {
            if !self.ipv6.exthdrs.is_empty() {
                return Err(SpecError::IpV6OptionWithIpV4Target {
                    option: "--ipv6-ext",
                });
            }
            if let Some(ip) = &self.ip {
                if ip.fragmentation.fragment_id.is_some() {
                    return Err(SpecError::IpV6OptionWithIpV4Target {
                        option: "--frag-id",
                    });
                }
            }
            if matches!(&self.transport, TransportSpec::Icmpv6(_)) {
                return Err(SpecError::IpV6OptionWithIpV4Target { option: "icmpv6" });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::request::{
        IcmpRequest, Icmpv6Request, IpRequest, Ipv6Request, PacketRequest,
        TransportProtocolRequest, TransportRequest,
    };
    use crate::engine::spec::Ipv6ExtHeader;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn validate_consistency_rejects_ipv4_source_with_ipv6_target() {
        let spec = PacketSpec {
            ip: Some(IpSpec {
                source: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = spec.validate_ip_version_consistency(true);
        assert!(matches!(
            result,
            Err(SpecError::SourceIpVersionMismatch { .. })
        ));
    }

    #[test]
    fn validate_consistency_rejects_ipv6_source_with_ipv4_target() {
        let spec = PacketSpec {
            ip: Some(IpSpec {
                source: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = spec.validate_ip_version_consistency(false);
        assert!(matches!(
            result,
            Err(SpecError::SourceIpVersionMismatch { .. })
        ));
    }

    #[test]
    fn validate_consistency_rejects_ipv4_options_with_ipv6_target() {
        let spec = PacketSpec {
            ip: Some(IpSpec {
                identification: Some(1234),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = spec.validate_ip_version_consistency(true);
        assert!(matches!(
            result,
            Err(SpecError::IpV4OptionWithIpV6Target { option: "--id" })
        ));
    }

    #[test]
    fn validate_consistency_rejects_ipv6_options_with_ipv4_target() {
        let mut spec = PacketSpec::default();
        spec.ipv6.exthdrs = vec![Ipv6ExtHeader::HopByHop { options: vec![] }];

        let result = spec.validate_ip_version_consistency(false);
        assert!(matches!(
            result,
            Err(SpecError::IpV6OptionWithIpV4Target {
                option: "--ipv6-ext"
            })
        ));
    }

    #[test]
    fn validate_consistency_rejects_icmp_with_ipv6_target() {
        let mut spec = PacketSpec::default();
        spec.transport = TransportSpec::Icmp(crate::engine::spec::transport::IcmpSpec::default());

        let result = spec.validate_ip_version_consistency(true);
        assert!(matches!(
            result,
            Err(SpecError::IpV4OptionWithIpV6Target { option: "icmp" })
        ));
    }

    #[test]
    fn validate_consistency_rejects_icmpv6_with_ipv4_target() {
        let mut spec = PacketSpec::default();
        spec.transport =
            TransportSpec::Icmpv6(crate::engine::spec::transport::Icmpv6Spec::default());

        let result = spec.validate_ip_version_consistency(false);
        assert!(matches!(
            result,
            Err(SpecError::IpV6OptionWithIpV4Target { option: "icmpv6" })
        ));
    }

    #[test]
    fn from_request_respects_explicit_ipv4_preference() {
        let request = PacketRequest {
            ip: IpRequest {
                prefer_ipv4: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };

        let spec = PacketSpec::from_request(&request).expect("packet spec should build");

        assert!(matches!(spec.transport, TransportSpec::Icmp(_)));
    }

    #[test]
    fn from_request_prefers_family_from_destination_ip_literal() {
        let ipv6_request = PacketRequest {
            ip: IpRequest {
                destination_ip: Some("2001:db8::1".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let ipv4_request = PacketRequest {
            ip: IpRequest {
                destination_ip: Some("192.0.2.1".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let ipv6_spec = PacketSpec::from_request(&ipv6_request).expect("IPv6 spec should build");
        let ipv4_spec = PacketSpec::from_request(&ipv4_request).expect("IPv4 spec should build");

        assert!(matches!(ipv6_spec.transport, TransportSpec::Icmpv6(_)));
        assert!(matches!(ipv4_spec.transport, TransportSpec::Icmp(_)));
    }

    #[test]
    fn from_request_prefers_family_from_source_ip_literal() {
        let request = PacketRequest {
            ip: IpRequest {
                source_ip: Some("2001:db8::2".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let spec = PacketSpec::from_request(&request).expect("packet spec should build");

        assert!(matches!(spec.transport, TransportSpec::Icmpv6(_)));
    }

    #[test]
    fn from_request_prefers_ipv6_when_extensions_present() {
        let request = PacketRequest {
            ipv6: Ipv6Request {
                extensions: vec!["hop".to_string()],
            },
            ..Default::default()
        };

        let spec = PacketSpec::from_request(&request).expect("packet spec should build");

        assert!(matches!(spec.transport, TransportSpec::Icmpv6(_)));
    }

    #[test]
    fn from_request_prefers_ipv6_when_fragment_id_set() {
        let mut request = PacketRequest::default();
        request.ip.fragment.fragment_id = Some(1234);

        let spec = PacketSpec::from_request(&request).expect("packet spec should build");

        assert!(matches!(spec.transport, TransportSpec::Icmpv6(_)));
    }

    #[test]
    fn from_request_preserves_icmp_family_requests() {
        let icmp = PacketRequest {
            transport: TransportRequest {
                command: Some(TransportProtocolRequest::Icmp(IcmpRequest::default())),
                ..Default::default()
            },
            ..Default::default()
        };
        let icmpv6 = PacketRequest {
            transport: TransportRequest {
                command: Some(TransportProtocolRequest::Icmpv6(Icmpv6Request::default())),
                ..Default::default()
            },
            ..Default::default()
        };

        let icmp_spec = PacketSpec::from_request(&icmp).expect("ICMP spec should build");
        let icmpv6_spec = PacketSpec::from_request(&icmpv6).expect("ICMPv6 spec should build");

        assert!(matches!(icmp_spec.transport, TransportSpec::Icmp(_)));
        assert!(matches!(icmpv6_spec.transport, TransportSpec::Icmpv6(_)));
    }
}
