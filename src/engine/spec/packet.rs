// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

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

        let destination_hint = ip.as_ref().and_then(|ip| ip.destination).or_else(|| {
            target.address.as_ref().and_then(|addr| {
                addr.resolved_ip()
                    .or(request.destination.resolved_destination)
            })
        });

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
                    let conflicting_ip = ip.destination.or_else(|| {
                        self.target
                            .address
                            .as_ref()
                            .and_then(TargetAddress::resolved_ip)
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
