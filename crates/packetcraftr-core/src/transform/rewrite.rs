// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Error;
use crate::{
    frame::{Frame, LinkType},
    protocol::{checksum, checksum_parts},
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
        if !matches!(self.ether_type, 0x8100 | 0x88a8)
            || self.identifier > 4095
            || self.priority > 7
        {
            return Err(Error::Invalid("invalid VLAN rewrite tag"));
        }
        Ok((u16::from(self.priority) << 13)
            | (u16::from(self.drop_eligible) << 12)
            | self.identifier)
    }
}
impl From<crate::packet::link::VlanTag> for VlanRewrite {
    fn from(tag: crate::packet::link::VlanTag) -> Self {
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
            if tags.len() > 64 {
                return Err(Error::Limit {
                    field: "VLAN depth",
                    limit: 64,
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
#[derive(Clone, Copy, Debug)]
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
    let ethernet = frame.link_type == LinkType::ETHERNET;
    if !ethernet
        && (patch.source_mac.is_some() || patch.destination_mac.is_some() || patch.vlans.is_some())
    {
        return Err(Error::Unsupported("MAC/VLAN edits require Ethernet"));
    }
    let (old_offset, kind) = if ethernet {
        super::ethernet_payload(frame.bytes(), u16_at)?
    } else if frame.link_type.is_raw_ip() {
        (0, 0)
    } else {
        return Err(Error::Unsupported("rewrite requires Ethernet or raw IP"));
    };
    let new_offset = patch
        .vlans
        .as_ref()
        .map_or(old_offset, |tags| 14 + 4 * tags.len());
    let new_length = frame
        .bytes()
        .len()
        .checked_sub(old_offset)
        .and_then(|n| n.checked_add(new_offset))
        .ok_or(Error::Limit {
            field: "max_output_bytes",
            limit: limits.max_output_bytes,
        })?;
    let length = new_length;
    if length > limits.max_output_bytes {
        return Err(Error::Limit {
            field: "max_output_bytes",
            limit: limits.max_output_bytes,
        });
    }
    let mut bytes = Vec::with_capacity(length);
    if ethernet {
        bytes.extend_from_slice(&frame.bytes()[..12]);
        if let Some(tags) = &patch.vlans {
            for tag in tags {
                bytes.extend_from_slice(&tag.ether_type.to_be_bytes());
                bytes.extend_from_slice(&tag.tci()?.to_be_bytes());
            }
            bytes.extend_from_slice(&kind.to_be_bytes());
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
        if ethernet && !matches!(kind, 0x0800 | 0x86dd) {
            return Err(Error::Unsupported(
                "network edits require an outer IPv4/IPv6 datagram",
            ));
        }
        let ip = &mut bytes[new_offset..];
        let version = ip.first().map(|b| b >> 4);
        if (frame.link_type == LinkType::IPV4 || ethernet && kind == 0x0800) && version != Some(4)
            || (frame.link_type == LinkType::IPV6 || ethernet && kind == 0x86dd)
                && version != Some(6)
        {
            return Err(Error::Invalid("link type disagrees with IP version"));
        }
        let end = match version {
            Some(4) => ipv4(ip, patch)?,
            Some(6) => ipv6(ip, patch)?,
            _ => return Err(Error::Invalid("unknown IP version")),
        };
        if !ethernet && end != ip.len() {
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
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(Error::Invalid("truncated rewrite header"))?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}
fn ipv4(ip: &mut [u8], patch: &HeaderRewrite) -> Result<usize, Error> {
    if ip.len() < 20 {
        return Err(Error::Invalid("truncated IPv4 header"));
    }
    let header = usize::from(ip[0] & 15) * 4;
    let length = usize::from(u16_at(ip, 2)?);
    if header < 20 || length < header || length > ip.len() {
        return Err(Error::Invalid("invalid IPv4 lengths"));
    }
    if u16_at(ip, 6)? & 0x3fff != 0 {
        return Err(Error::Unsupported(
            "IP address/port edits require reassembly of IPv4 fragments",
        ));
    }
    let mut option = 20;
    while option < header {
        match ip[option] {
            0 => break,
            1 => option += 1,
            131 | 137 => {
                return Err(Error::Unsupported(
                    "IPv4 source routing changes checksum destinations",
                ));
            }
            _ => {
                let n = usize::from(
                    *ip.get(option + 1)
                        .ok_or(Error::Invalid("truncated IPv4 option"))?,
                );
                if n < 2 || option + n > header {
                    return Err(Error::Invalid("invalid IPv4 option length"));
                }
                option += n;
            }
        }
    }
    for (value, start) in [(patch.source_ip, 12), (patch.destination_ip, 16)] {
        if let Some(value) = value {
            let IpAddr::V4(value) = value else {
                return Err(Error::Invalid("cannot change IP address family"));
            };
            ip[start..start + 4].copy_from_slice(&value.octets());
        }
    }
    let protocol = ip[9];
    let addresses: [u8; 8] = ip[12..20].try_into().expect("IPv4 addresses");
    transport(&mut ip[header..length], patch, false, protocol, &addresses)?;
    ip[10..12].fill(0);
    let value = checksum(&ip[..header]);
    ip[10..12].copy_from_slice(&value.to_be_bytes());
    Ok(length)
}
fn ipv6(ip: &mut [u8], patch: &HeaderRewrite) -> Result<usize, Error> {
    if ip.len() < 40 {
        return Err(Error::Invalid("truncated IPv6 header"));
    }
    let payload = usize::from(u16_at(ip, 4)?);
    let length = 40 + payload;
    if length > ip.len() {
        return Err(Error::Invalid("truncated IPv6 payload"));
    }
    if payload == 0 && ip[6] != 59 {
        return Err(Error::Unsupported("IPv6 jumbograms are not rewritten"));
    }
    let (mut protocol, mut position, mut extensions) = (ip[6], 40, 0);
    while matches!(protocol, 0 | 43 | 44 | 60) {
        extensions += 1;
        if extensions > 64 {
            return Err(Error::Limit {
                field: "IPv6 extensions",
                limit: 64,
            });
        }
        if position + 8 > length {
            return Err(Error::Invalid("truncated IPv6 extension"));
        }
        if protocol == 43 {
            return Err(Error::Unsupported(
                "IPv6 routing header changes checksum destinations",
            ));
        }
        let next = ip[position];
        if protocol == 44 {
            if u16_at(ip, position + 2)? & 0xfff9 != 0 {
                return Err(Error::Unsupported(
                    "IP address/port edits require reassembly of IPv6 fragments",
                ));
            }
            position += 8;
        } else {
            let end = position + (usize::from(ip[position + 1]) + 1) * 8;
            if end > length {
                return Err(Error::Invalid("invalid IPv6 option-header length"));
            }
            let mut option = position + 2;
            while option < end {
                if ip[option] == 0 {
                    option += 1;
                    continue;
                }
                if ip[option] == 201 {
                    return Err(Error::Unsupported(
                        "IPv6 Home Address option changes checksum sources",
                    ));
                }
                let n = usize::from(
                    *ip.get(option + 1)
                        .ok_or(Error::Invalid("truncated IPv6 option"))?,
                ) + 2;
                if option + n > end {
                    return Err(Error::Invalid("invalid IPv6 option length"));
                }
                option += n;
            }
            position = end;
        }
        protocol = next;
    }
    for (value, start) in [(patch.source_ip, 8), (patch.destination_ip, 24)] {
        if let Some(value) = value {
            let IpAddr::V6(value) = value else {
                return Err(Error::Invalid("cannot change IP address family"));
            };
            ip[start..start + 16].copy_from_slice(&value.octets());
        }
    }
    let addresses: [u8; 32] = ip[8..40].try_into().expect("IPv6 addresses");
    transport(&mut ip[position..length], patch, true, protocol, &addresses)?;
    Ok(length)
}
fn transport(
    segment: &mut [u8],
    patch: &HeaderRewrite,
    ipv6: bool,
    protocol: u8,
    addresses: &[u8],
) -> Result<(), Error> {
    let ports = patch.source_port.is_some() || patch.destination_port.is_some();
    if ports && !matches!(protocol, 6 | 17) {
        return Err(Error::Unsupported("port edits require TCP or UDP"));
    }
    let (length, checksum_offset) = match protocol {
        6 => {
            if segment.len() < 20
                || usize::from(segment[12] >> 4) * 4 < 20
                || usize::from(segment[12] >> 4) * 4 > segment.len()
            {
                return Err(Error::Invalid("invalid TCP header length"));
            }
            (segment.len(), 16)
        }
        17 => {
            let length = usize::from(u16_at(segment, 4)?);
            if length < 8 || length > segment.len() {
                return Err(Error::Invalid("invalid UDP length"));
            }
            (length, 6)
        }
        58 if ipv6 => {
            if segment.len() < 4 {
                return Err(Error::Invalid("truncated ICMPv6"));
            }
            (segment.len(), 2)
        }
        1 | 2 | 4 | 41 | 47 | 59 | 132 => return Ok(()),
        _ => {
            return Err(Error::Unsupported(
                "unknown or authenticated upper-layer checksum semantics",
            ));
        }
    };
    let disabled_udp = protocol == 17 && !ipv6 && u16_at(segment, 6)? == 0;
    if let Some(port) = patch.source_port {
        segment[..2].copy_from_slice(&port.to_be_bytes());
    }
    if let Some(port) = patch.destination_port {
        segment[2..4].copy_from_slice(&port.to_be_bytes());
    }
    if disabled_udp {
        return Ok(());
    }
    segment[checksum_offset..checksum_offset + 2].fill(0);
    let mut value = if ipv6 {
        checksum_parts(&[
            addresses,
            &(length as u32).to_be_bytes(),
            &[0, 0, 0, protocol],
            &segment[..length],
        ])
    } else {
        checksum_parts(&[
            addresses,
            &[0, protocol],
            &(length as u16).to_be_bytes(),
            &segment[..length],
        ])
    };
    if protocol == 17 && value == 0 {
        value = 0xffff;
    }
    segment[checksum_offset..checksum_offset + 2].copy_from_slice(&value.to_be_bytes());
    Ok(())
}
