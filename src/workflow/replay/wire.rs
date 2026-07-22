use super::{
    Frame, IoSendReport, IpAddr, Ipv4Addr, Ipv6Addr, Kind, LinkMode, LinkType, LiveIoError,
    NetworkEnvelope, ReplayError, RouteProvider, SystemRouteProvider,
};

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_HEADER_LEN: usize = 4;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_SERVICE_VLAN: u16 = 0x88a8;

pub(super) fn map_replay_route_error(source: crate::net::route::NativeRouteError) -> LiveIoError {
    let classification = SystemRouteProvider.classify_error(&source);
    match classification.kind {
        Kind::Capability => LiveIoError::Unsupported {
            message: source.to_string(),
        },
        _ => LiveIoError::Send {
            message: format!("replay route selection failed: {source}"),
        },
    }
}

pub(super) fn replay_network_envelope(frame: &Frame) -> Result<NetworkEnvelope, LiveIoError> {
    let invalid = |message: String| LiveIoError::InvalidTransmissionFrame { message };
    let bytes = frame.bytes().as_ref();
    let Some(version) = bytes.first().map(|byte| byte >> 4) else {
        return Err(invalid("replay frame is empty".to_owned()));
    };
    match (frame.link_type, version) {
        (LinkType::IPV4, actual) if actual != 4 => {
            return Err(invalid(format!(
                "capture link type {} declares IPv4 but the frame contains IP version {actual}",
                frame.link_type.0
            )));
        }
        (LinkType::IPV6, actual) if actual != 6 => {
            return Err(invalid(format!(
                "capture link type {} declares IPv6 but the frame contains IP version {actual}",
                frame.link_type.0
            )));
        }
        _ => {}
    }
    match version {
        4 if bytes.len() >= 20 => {
            let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
            let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
            Ok(NetworkEnvelope {
                source: IpAddr::V4(source),
                destination: IpAddr::V4(destination),
            })
        }
        6 if bytes.len() >= 40 => {
            let mut source = [0_u8; 16];
            let mut destination = [0_u8; 16];
            source.copy_from_slice(&bytes[8..24]);
            destination.copy_from_slice(&bytes[24..40]);
            Ok(NetworkEnvelope {
                source: IpAddr::V6(Ipv6Addr::from(source)),
                destination: IpAddr::V6(Ipv6Addr::from(destination)),
            })
        }
        4 => Err(invalid(
            "replay frame has a truncated IPv4 header".to_owned(),
        )),
        6 => Err(invalid(
            "replay frame has a truncated IPv6 header".to_owned(),
        )),
        value => Err(invalid(format!(
            "replay frame has unsupported IP version {value}"
        ))),
    }
}

pub(super) struct ReplayWireDestinations {
    pub(super) addresses: Vec<IpAddr>,
    pub(super) has_unsupported_routing_header: bool,
}

pub(super) fn replay_wire_destinations(
    frame: &Frame,
) -> Result<ReplayWireDestinations, crate::packet::semantics::SemanticError> {
    let bytes = frame.bytes().as_ref();
    let (network_offset, protocol) = match frame.link_type {
        LinkType::BSD_RAW | LinkType::RAW => (0, bytes.first().map(|byte| byte >> 4).unwrap_or(0)),
        LinkType::IPV4 => (0, 4),
        LinkType::IPV6 => (0, 6),
        LinkType::ETHERNET if bytes.len() >= ETHERNET_HEADER_LEN => {
            let mut offset = ETHERNET_HEADER_LEN;
            let mut ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
            for _ in 0..crate::packet::build::DEFAULT_MAX_LAYERS {
                if !matches!(ether_type, ETHERTYPE_VLAN | ETHERTYPE_SERVICE_VLAN)
                    || bytes.len() < offset + VLAN_HEADER_LEN
                {
                    break;
                }
                ether_type = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
                offset += VLAN_HEADER_LEN;
            }
            let protocol = match ether_type {
                ETHERTYPE_IPV4 => 4,
                ETHERTYPE_IPV6 => 6,
                _ => 0,
            };
            (offset, protocol)
        }
        _ => (0, 0),
    };
    let mut destinations = Vec::new();
    let has_unsupported_routing_header = match protocol {
        4 => {
            collect_ipv4_wire_destinations(bytes, network_offset, &mut destinations)?;
            false
        }
        6 => collect_ipv6_wire_destinations(bytes, network_offset, &mut destinations),
        _ => false,
    };
    Ok(ReplayWireDestinations {
        addresses: destinations,
        has_unsupported_routing_header,
    })
}

fn collect_ipv4_wire_destinations(
    bytes: &[u8],
    offset: usize,
    output: &mut Vec<IpAddr>,
) -> Result<(), crate::packet::semantics::SemanticError> {
    let Some(header) = bytes.get(offset..offset.saturating_add(20)) else {
        return Ok(());
    };
    output.push(IpAddr::V4(Ipv4Addr::new(
        header[16], header[17], header[18], header[19],
    )));
    let header_length = usize::from(header[0] & 0x0f).saturating_mul(4);
    if !(20..=60).contains(&header_length) {
        return Ok(());
    }
    let Some(header) = bytes.get(offset..offset.saturating_add(header_length)) else {
        return Ok(());
    };
    for destination in crate::packet::semantics::ipv4_source_route_destinations(&header[20..])? {
        output.push(IpAddr::V4(destination));
    }
    Ok(())
}

fn collect_ipv6_wire_destinations(bytes: &[u8], offset: usize, output: &mut Vec<IpAddr>) -> bool {
    let Some(header) = bytes.get(offset..offset.saturating_add(40)) else {
        return false;
    };
    let mut destination = [0_u8; 16];
    destination.copy_from_slice(&header[24..40]);
    output.push(IpAddr::V6(Ipv6Addr::from(destination)));
    let mut next_header = header[6];
    let mut cursor = offset.saturating_add(40);
    let mut has_unsupported_routing_header = false;
    let mut saw_routing_header = false;
    for _ in 0..crate::packet::build::DEFAULT_MAX_LAYERS {
        match next_header {
            0 | 43 | 60 => {
                let Some(extension) = bytes.get(cursor..cursor.saturating_add(8)) else {
                    has_unsupported_routing_header |= next_header == 43;
                    break;
                };
                let length = (usize::from(extension[1]) + 1).saturating_mul(8);
                let Some(extension) = bytes.get(cursor..cursor.saturating_add(length)) else {
                    has_unsupported_routing_header |= next_header == 43;
                    break;
                };
                if next_header == 43 && extension[2] == 4 && !saw_routing_header {
                    saw_routing_header = true;
                    let segment_count = usize::from(extension[4]).saturating_add(1);
                    let expected_length = segment_count
                        .checked_mul(16)
                        .and_then(|length| length.checked_add(8));
                    let mut segments = extension[8..]
                        .chunks_exact(16)
                        .map(|segment| {
                            let mut address = [0_u8; 16];
                            address.copy_from_slice(segment);
                            Ipv6Addr::from(address)
                        })
                        .collect::<Vec<_>>();
                    segments.reverse();
                    let valid = expected_length == Some(extension.len())
                        && crate::packet::semantics::validate_segment_route(
                            Ipv6Addr::from(destination),
                            segments.clone(),
                            extension[3],
                            extension[4],
                            extension[5],
                        )
                        .is_ok();
                    if valid {
                        output.extend(segments.into_iter().map(IpAddr::V6));
                    } else {
                        has_unsupported_routing_header = true;
                    }
                } else if next_header == 43 {
                    has_unsupported_routing_header = true;
                }
                next_header = extension[0];
                cursor = cursor.saturating_add(length);
            }
            44 => {
                let Some(fragment) = bytes.get(cursor..cursor.saturating_add(8)) else {
                    break;
                };
                next_header = fragment[0];
                cursor = cursor.saturating_add(8);
            }
            51 => {
                let Some(authentication) = bytes.get(cursor..cursor.saturating_add(2)) else {
                    break;
                };
                let length = (usize::from(authentication[1]) + 2).saturating_mul(4);
                if bytes.get(cursor..cursor.saturating_add(length)).is_none() {
                    break;
                }
                next_header = authentication[0];
                cursor = cursor.saturating_add(length);
            }
            _ => break,
        }
    }
    has_unsupported_routing_header
}

pub(super) fn replay_link_mode(
    sequence: u64,
    link_type: LinkType,
    requested: LinkMode,
) -> Result<LinkMode, ReplayError> {
    let supported = match link_type {
        LinkType::ETHERNET => LinkMode::Layer2,
        LinkType::BSD_RAW | LinkType::RAW | LinkType::IPV4 | LinkType::IPV6 => LinkMode::Layer3,
        _ => {
            return Err(ReplayError::UnsupportedLinkType {
                sequence,
                link_type: link_type.0,
            });
        }
    };
    match requested {
        LinkMode::Auto => Ok(supported),
        requested if requested == supported => Ok(requested),
        requested => Err(ReplayError::LinkModeMismatch {
            sequence,
            link_type: link_type.0,
            requested,
        }),
    }
}

pub(super) fn validate_transmission_evidence(
    sequence: u64,
    frame: &Frame,
    report: &IoSendReport,
) -> Result<(), ReplayError> {
    if report.bytes_sent != frame.bytes().len() {
        return Err(ReplayError::Transmission {
            sequence,
            source: LiveIoError::PartialSend {
                expected: frame.bytes().len(),
                actual: report.bytes_sent,
            },
        });
    }
    let wire_bytes = report
        .wire_bytes
        .as_ref()
        .ok_or_else(|| ReplayError::InvalidEvidence {
            sequence,
            message: "backend omitted exact wire bytes".to_owned(),
        })?;
    if wire_bytes != frame.bytes() {
        return Err(ReplayError::InvalidEvidence {
            sequence,
            message: format!(
                "backend returned {} wire bytes that differ from the {} submitted bytes",
                wire_bytes.len(),
                frame.bytes().len()
            ),
        });
    }
    Ok(())
}
