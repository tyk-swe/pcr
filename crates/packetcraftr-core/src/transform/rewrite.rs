// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Error;
use crate::{
    frame::{Frame, LinkType},
    packet::{VlanKind, VlanTag},
    protocol::{
        BuiltinProtocol, checksum,
        headers::MAX_VLAN_DEPTH,
        headers::{EthernetHeader, IpHeader, Ipv4Header, Ipv6Header, LinkHeader},
        network::ip_protocol,
        network_from_addresses, transport_checksum,
    },
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, ops::Range};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlanRewrite {
    pub ether_type: u16,
    pub identifier: u16,
    #[serde(default)]
    pub priority: u8,
    #[serde(default)]
    pub drop_eligible: bool,
}
impl VlanRewrite {
    fn tci(self) -> Result<u16, Error> {
        let kind = VlanKind::from_ether_type(self.ether_type)
            .filter(|_| self.identifier <= 4095 && self.priority <= 7)
            .ok_or(Error::Invalid("invalid VLAN rewrite tag"))?;
        Ok(VlanTag {
            kind,
            priority: self.priority,
            drop_eligible: self.drop_eligible,
            vlan_id: self.identifier,
        }
        .tci())
    }
}
impl From<VlanTag> for VlanRewrite {
    fn from(tag: VlanTag) -> Self {
        Self {
            ether_type: tag.kind.ether_type(),
            identifier: tag.vlan_id,
            priority: tag.priority,
            drop_eligible: tag.drop_eligible,
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HeaderRewrite {
    pub source_mac: Option<[u8; 6]>,
    pub destination_mac: Option<[u8; 6]>,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    /// Replace the outer Ethernet VLAN stack; an empty list removes all tags.
    pub vlans: Option<Vec<VlanRewrite>>,
}
impl HeaderRewrite {
    pub fn is_empty(&self) -> bool {
        self.source_mac.is_none()
            && self.destination_mac.is_none()
            && self.source_ip.is_none()
            && self.destination_ip.is_none()
            && self.source_port.is_none()
            && self.destination_port.is_none()
            && self.vlans.is_none()
    }
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(tags) = &self.vlans {
            if tags.len() > MAX_VLAN_DEPTH {
                return Err(Error::Limit {
                    field: "VLAN depth",
                    limit: MAX_VLAN_DEPTH,
                });
            }
            for tag in tags {
                tag.tci()?;
            }
        }
        if let (Some(source), Some(destination)) = (self.source_ip, self.destination_ip)
            && source.is_ipv4() != destination.is_ipv4()
        {
            return Err(Error::Invalid(
                "rewrite addresses use different IP families",
            ));
        }
        Ok(())
    }
}
/// Ceilings for one [`rewrite`].
///
/// Every value is honored as given, so there is nothing to validate: a frame
/// longer than `max_output_bytes` is refused, and zero refuses every frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewriteLimits {
    pub max_output_bytes: usize,
}
impl Default for RewriteLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: crate::frame::DEFAULT_SIZE_LIMIT,
        }
    }
}
/// Rewrite outer Ethernet/VLAN, IP addresses, and TCP/UDP ports while retaining
/// payload and capture identity. Address edits regenerate applicable transport
/// pseudo-header checksums; IPv4 UDP checksum zero remains disabled. Frames must
/// exclude a link FCS. Capture adapters must reject declared FCS/authentication
/// metadata. IP fragments needing reconstruction, source-routing options, IPv6
/// routing/home-address headers, AH/ESP, and unknown upper layers are rejected
/// for network/port edits. MAC/VLAN-only edits do not interpret the IP payload.
///
/// The output is the captured frame with only the named header bytes and the
/// checksums covering them changed, so link trailers and malformed or unknown
/// bytes survive byte for byte. A codec round trip would re-encode them.
pub fn rewrite(
    frame: &Frame,
    patch: &HeaderRewrite,
    limits: RewriteLimits,
) -> Result<Frame, Error> {
    patch.validate()?;
    if frame.bytes().len() > limits.max_output_bytes {
        return Err(Error::Limit {
            field: "max_output_bytes",
            limit: limits.max_output_bytes,
        });
    }
    if patch.is_empty() {
        return Ok(frame.clone());
    }
    if frame.captured_length() != frame.original_length() {
        return Err(Error::Invalid("cannot rewrite a truncated capture"));
    }
    let link_edits =
        patch.source_mac.is_some() || patch.destination_mac.is_some() || patch.vlans.is_some();
    if link_edits && frame.link_type != LinkType::ETHERNET {
        return Err(Error::Unsupported("MAC/VLAN edits require Ethernet"));
    }
    let link = LinkHeader::walk(frame.link_type, frame.bytes())?
        .ok_or(Error::Unsupported("rewrite requires Ethernet or raw IP"))?;
    let old_offset = link.network_offset();
    let new_offset = patch.vlans.as_ref().map_or(old_offset, |tags| {
        EthernetHeader::LENGTH + EthernetHeader::VLAN_TAG_LENGTH * tags.len()
    });
    let length = frame
        .bytes()
        .len()
        .checked_sub(old_offset)
        .and_then(|n| n.checked_add(new_offset))
        .filter(|length| *length <= limits.max_output_bytes)
        .ok_or(Error::Limit {
            field: "max_output_bytes",
            limit: limits.max_output_bytes,
        })?;
    let mut bytes = Vec::with_capacity(length);
    if let LinkHeader::Ethernet(ethernet) = &link {
        // The addresses are copied and then overwritten in place, and a
        // replaced VLAN stack is spliced in as bytes: the payload behind the
        // link header is carried over exactly as captured.
        bytes.extend_from_slice(&frame.bytes()[..12]);
        if let Some(tags) = &patch.vlans {
            for tag in tags {
                bytes.extend_from_slice(&tag.ether_type.to_be_bytes());
                bytes.extend_from_slice(&tag.tci()?.to_be_bytes());
            }
            bytes.extend_from_slice(&ethernet.ether_type().to_be_bytes());
        } else {
            bytes.extend_from_slice(&frame.bytes()[12..old_offset]);
        }
    }
    bytes.extend_from_slice(&frame.bytes()[old_offset..]);
    if let Some(mac) = patch.source_mac {
        bytes[6..12].copy_from_slice(&mac);
    }
    if let Some(mac) = patch.destination_mac {
        bytes[..6].copy_from_slice(&mac);
    }
    if patch.source_ip.is_some()
        || patch.destination_ip.is_some()
        || patch.source_port.is_some()
        || patch.destination_port.is_some()
    {
        // The IP bytes moved with the link header only, so offsets walked in
        // the captured frame hold in the output.
        let header = link.walk_ip(frame.bytes())?.ok_or(Error::Unsupported(
            "network edits require an outer IPv4/IPv6 datagram",
        ))?;
        let ip = &mut bytes[new_offset..];
        network(ip, &header, patch)?;
        if matches!(link, LinkHeader::RawIp { .. }) && header.datagram_length() != ip.len() {
            return Err(Error::Unsupported(
                "raw IP has uninterpreted trailing bytes",
            ));
        }
    }
    let mut output = Frame::without_timestamp(frame.link_type, bytes)?;
    output.timestamp = frame.timestamp;
    output.interface = frame.interface;
    output.direction = frame.direction;
    Ok(output)
}

const AUTHENTICATED_OR_UNKNOWN: &str = "unknown or authenticated upper-layer checksum semantics";

/// Writes the patched addresses and ports into `ip` in place and regenerates
/// the checksums that cover them. IPv4 options, IPv6 extension headers, and
/// the upper-layer payload keep their captured encoding, which a codec
/// re-encode could normalize.
fn network(ip: &mut [u8], header: &IpHeader, patch: &HeaderRewrite) -> Result<(), Error> {
    super::ensure_checksum_coverage(ip, header)?;
    let (source, destination) = match header {
        IpHeader::V4(_) => (Ipv4Header::SOURCE, Ipv4Header::DESTINATION),
        IpHeader::V6(_) => (Ipv6Header::SOURCE, Ipv6Header::DESTINATION),
    };
    for (value, range) in [
        (patch.source_ip, source.clone()),
        (patch.destination_ip, destination.clone()),
    ] {
        match (header, value) {
            (_, None) => {}
            (IpHeader::V4(_), Some(IpAddr::V4(value))) => {
                ip[range].copy_from_slice(&value.octets());
            }
            (IpHeader::V6(_), Some(IpAddr::V6(value))) => {
                ip[range].copy_from_slice(&value.octets());
            }
            _ => return Err(Error::Invalid("cannot change IP address family")),
        }
    }
    // AH authenticates the rewritten bytes. The walk steps over it, so it is
    // refused here like an upper layer `transport` does not know.
    if let IpHeader::V6(ipv6) = header
        && ipv6
            .extensions()
            .iter()
            .any(|extension| extension.protocol() == ip_protocol::AH)
    {
        return Err(Error::Unsupported(AUTHENTICATED_OR_UNKNOWN));
    }
    let address = |ip: &[u8], range: Range<usize>| {
        match header {
            IpHeader::V4(_) => <[u8; 4]>::try_from(&ip[range]).map(IpAddr::from),
            IpHeader::V6(_) => <[u8; 16]>::try_from(&ip[range]).map(IpAddr::from),
        }
        .expect("fixed-width IP address range")
    };
    let addresses = (address(ip, source), address(ip, destination));
    let (protocol, start) = header.upper_layer();
    let end = header.datagram_length();
    transport(&mut ip[start..end], patch, protocol, addresses)?;
    if let IpHeader::V4(ipv4) = header {
        // The header checksum covers the rewritten addresses.
        ip[Ipv4Header::CHECKSUM].fill(0);
        let value = checksum(&ip[..ipv4.header_length()]);
        ip[Ipv4Header::CHECKSUM].copy_from_slice(&value.to_be_bytes());
    }
    Ok(())
}

/// Writes the patched ports and regenerates the transport checksum over the
/// captured segment, whose options and payload stay as captured.
fn transport(
    segment: &mut [u8],
    patch: &HeaderRewrite,
    protocol: u8,
    (source, destination): (IpAddr, IpAddr),
) -> Result<(), Error> {
    let ipv6 = source.is_ipv6();
    let ports = patch.source_port.is_some() || patch.destination_port.is_some();
    if ports && !matches!(protocol, ip_protocol::TCP | ip_protocol::UDP) {
        return Err(Error::Unsupported("port edits require TCP or UDP"));
    }
    let (name, length, checksum_offset) = match protocol {
        ip_protocol::TCP => {
            let header = segment.get(12).map(|byte| usize::from(byte >> 4) * 4);
            if !header.is_some_and(|header| (20..=segment.len()).contains(&header)) {
                return Err(Error::Invalid("invalid TCP header length"));
            }
            (BuiltinProtocol::Tcp, segment.len(), 16)
        }
        ip_protocol::UDP => {
            let length = segment
                .get(4..6)
                .map(|length| usize::from(u16::from_be_bytes([length[0], length[1]])))
                .ok_or(Error::Invalid("invalid UDP length"))?;
            if length < 8 || length > segment.len() {
                return Err(Error::Invalid("invalid UDP length"));
            }
            (BuiltinProtocol::Udp, length, 6)
        }
        ip_protocol::ICMPV6 if ipv6 => {
            if segment.len() < 4 {
                return Err(Error::Invalid("truncated ICMPv6"));
            }
            (BuiltinProtocol::Icmpv6, segment.len(), 2)
        }
        1 | 2 | 4 | 41 | 47 | ip_protocol::NO_NEXT_HEADER | 132 => return Ok(()),
        _ => return Err(Error::Unsupported(AUTHENTICATED_OR_UNKNOWN)),
    };
    let checksum = checksum_offset..checksum_offset + 2;
    let disabled_udp = protocol == ip_protocol::UDP && !ipv6 && segment[checksum.clone()] == [0, 0];
    if let Some(port) = patch.source_port {
        segment[..2].copy_from_slice(&port.to_be_bytes());
    }
    if let Some(port) = patch.destination_port {
        segment[2..4].copy_from_slice(&port.to_be_bytes());
    }
    if disabled_udp {
        return Ok(());
    }
    segment[checksum.clone()].fill(0);
    let mut value = transport_checksum(
        name.as_str(),
        network_from_addresses(source, destination),
        protocol,
        &segment[..length],
    )
    .map_err(Error::Checksum)?;
    if protocol == ip_protocol::UDP && value == 0 {
        value = 0xffff;
    }
    segment[checksum].copy_from_slice(&value.to_be_bytes());
    Ok(())
}
