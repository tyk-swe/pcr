// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Error;
use crate::frame::{Frame, LinkType};
use crate::protocol::{
    checksum,
    headers::{IpHeader, Ipv4Header, Ipv6Header, LinkHeader},
    network::ip_protocol,
};

/// IP MTU excludes the link header. Limits apply before retaining output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentOptions {
    pub mtu: usize,
    /// Required for fragmented IPv6; absent IPv4 retains its original ID.
    pub identification: Option<u32>,
    pub max_fragments: usize,
    pub max_output_bytes: usize,
}
impl Default for FragmentOptions {
    fn default() -> Self {
        Self {
            mtu: 1500,
            identification: None,
            max_fragments: 1024,
            max_output_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Fragments raw-IP or Ethernet/VLAN datagrams. Existing fragments, IPv4 DF,
/// IPv6 AH/ESP, jumbograms and unknown extension chains are rejected.
/// IPv4 copied options appear on later fragments. IPv6 per-fragment headers
/// follow RFC 8200; the complete upper-layer header must fit in fragment zero.
/// A datagram already within MTU is returned unchanged. When splitting, link
/// trailers are omitted and Ethernet padding is regenerated without an FCS.
///
/// Each fragment is assembled from captured bytes: the link header, the
/// original IP header (or its unfragmentable part) with only the length,
/// fragment, and checksum fields rewritten, and a slice of the payload. A
/// codec re-encode of the header could normalize options, reserved bits, and
/// extension headers the fragments must repeat exactly.
pub fn fragment(frame: &Frame, options: FragmentOptions) -> Result<Vec<Frame>, Error> {
    if options.max_fragments == 0 || options.max_fragments > 8192 {
        return Err(Error::Limit {
            field: "max_fragments",
            limit: 8192,
        });
    }
    if frame.captured_length() != frame.original_length() {
        return Err(Error::Invalid("capture is truncated"));
    }
    let link = LinkHeader::walk(frame.link_type, frame.bytes())?.ok_or(Error::Unsupported(
        "capture link type is not raw IP or Ethernet/VLAN",
    ))?;
    let header = link
        .walk_ip(frame.bytes())?
        .ok_or(Error::Unsupported("Ethernet payload is not IPv4/IPv6"))?;
    let offset = link.network_offset();
    let ip = &frame.bytes()[offset..];
    match header {
        IpHeader::V4(header) => ipv4(frame, offset, ip, &header, options),
        IpHeader::V6(header) => ipv6(frame, offset, ip, &header, options),
    }
}

fn ipv4(
    frame: &Frame,
    offset: usize,
    ip: &[u8],
    ipv4: &Ipv4Header,
    options: FragmentOptions,
) -> Result<Vec<Frame>, Error> {
    let header_len = ipv4.header_length();
    let length = ipv4.total_length();
    if checksum(&ip[..header_len]) != 0 {
        return Err(Error::Invalid("invalid IPv4 header checksum"));
    }
    if ipv4.reserved_flag() {
        return Err(Error::Invalid("IPv4 reserved flag is set"));
    }
    if ipv4.is_fragment() {
        return Err(Error::Unsupported("already fragmented IPv4"));
    }
    if length <= options.mtu {
        return unchanged(frame, options);
    }
    if ipv4.dont_fragment() {
        return Err(Error::Unsupported("IPv4 DF prohibits fragmentation"));
    }
    if length == header_len {
        return Err(Error::Invalid("MTU cannot contain the IPv4 header"));
    }
    let copied = copied_options(ip, ipv4)?;
    let id = options
        .identification
        .map(u16::try_from)
        .transpose()
        .map_err(|_| Error::Invalid("IPv4 identification exceeds 16 bits"))?
        .unwrap_or(ipv4.identification());
    let flags = ipv4.flags_and_offset();
    let payload = &ip[header_len..length];
    let mut position = 0;
    let mut output = Vec::new();
    let mut retained = 0;
    while position < payload.len() {
        let mut header = if position == 0 {
            ip[..header_len].to_vec()
        } else {
            let mut header = ip[..Ipv4Header::MIN_LENGTH].to_vec();
            header.extend_from_slice(&copied);
            header[0] = 0x40 | (header.len() / 4) as u8;
            header
        };
        let room = options
            .mtu
            .checked_sub(header.len())
            .ok_or(Error::Invalid("MTU cannot contain the IPv4 header"))?;
        let count = payload_count(room, payload.len() - position)?;
        let more = position + count < payload.len();
        let total = u16::try_from(header.len() + count)
            .map_err(|_| Error::Invalid("IPv4 fragment length overflow"))?;
        header[2..4].copy_from_slice(&total.to_be_bytes());
        header[4..6].copy_from_slice(&id.to_be_bytes());
        let fragment_flags = (flags & 0x8000) | (u16::from(more) << 13) | (position / 8) as u16;
        header[6..8].copy_from_slice(&fragment_flags.to_be_bytes());
        header[Ipv4Header::CHECKSUM].fill(0);
        let sum = checksum(&header);
        header[Ipv4Header::CHECKSUM].copy_from_slice(&sum.to_be_bytes());
        append(
            frame,
            offset,
            &header,
            &payload[position..position + count],
            options,
            &mut retained,
            &mut output,
        )?;
        position += count;
    }
    Ok(output)
}

/// The options RFC 791 copies into every fragment, padded to a word.
fn copied_options(ip: &[u8], ipv4: &Ipv4Header) -> Result<Vec<u8>, Error> {
    const COPIED: u8 = 0x80;
    let mut copied = Vec::new();
    for option in ipv4.options(ip) {
        let option = option?;
        if option.kind & COPIED != 0 {
            copied.extend_from_slice(&ip[option.range]);
        }
    }
    while copied.len() % 4 != 0 {
        copied.push(0);
    }
    Ok(copied)
}

fn ipv6(
    frame: &Frame,
    offset: usize,
    ip: &[u8],
    ipv6: &Ipv6Header,
    options: FragmentOptions,
) -> Result<Vec<Frame>, Error> {
    if ipv6.payload_length() == 0 {
        return Err(Error::Unsupported("IPv6 jumbogram or empty datagram"));
    }
    let length = ipv6.datagram_length();
    // The unfragmentable part ends after the last Hop-by-Hop or Routing
    // header; `prefix_next` is the Next Header byte that announces the
    // fragmentable part and becomes the Fragment header's announcement.
    let mut prefix_len = Ipv6Header::LENGTH;
    let mut prefix_next = 6;
    for (index, extension) in ipv6.extensions().iter().enumerate() {
        match extension.protocol() {
            ip_protocol::FRAGMENT | ip_protocol::AH => {
                return Err(Error::Unsupported("fragment, AH or ESP header"));
            }
            ip_protocol::HOP_BY_HOP if index != 0 => {
                return Err(Error::Unsupported("misordered Hop-by-Hop header"));
            }
            ip_protocol::HOP_BY_HOP | ip_protocol::ROUTING => {
                prefix_len = extension.range().end;
                prefix_next = extension.range().start;
            }
            _ => {}
        }
    }
    let (next, cursor) = ipv6.upper_layer();
    if next == ip_protocol::ESP {
        return Err(Error::Unsupported("fragment, AH or ESP header"));
    }
    if length <= options.mtu {
        return unchanged(frame, options);
    }
    let transport_len = match next {
        ip_protocol::TCP => {
            let value = *ip
                .get(cursor + 12)
                .ok_or(Error::Invalid("truncated TCP header"))?;
            let size = usize::from(value >> 4) * 4;
            if size < 20 {
                return Err(Error::Invalid("invalid TCP header length"));
            }
            size
        }
        ip_protocol::UDP | ip_protocol::ICMPV6 => 8,
        132 => 12,
        _ => return Err(Error::Unsupported("unknown IPv6 upper-layer header")),
    };
    if cursor + transport_len > length {
        return Err(Error::Invalid("truncated upper-layer header"));
    }
    let room = options
        .mtu
        .checked_sub(prefix_len + 8)
        .ok_or(Error::Invalid(
            "MTU cannot contain IPv6 per-fragment headers",
        ))?;
    if room / 8 * 8 < cursor + transport_len - prefix_len {
        return Err(Error::Invalid(
            "first IPv6 fragment cannot contain all headers",
        ));
    }
    let id = options.identification.ok_or(Error::Invalid(
        "IPv6 fragmentation requires an explicit identification",
    ))?;
    let payload = &ip[prefix_len..length];
    let mut position = 0;
    let mut output = Vec::new();
    let mut retained = 0;
    while position < payload.len() {
        let count = payload_count(room, payload.len() - position)?;
        let mut header = ip[..prefix_len].to_vec();
        let next = header[prefix_next];
        header[prefix_next] = ip_protocol::FRAGMENT;
        let payload_length = u16::try_from(prefix_len - 40 + 8 + count)
            .map_err(|_| Error::Invalid("IPv6 fragment length overflow"))?;
        header[4..6].copy_from_slice(&payload_length.to_be_bytes());
        header.extend_from_slice(&[next, 0]);
        let flags = (position as u16 & 0xfff8) | u16::from(position + count < payload.len());
        header.extend_from_slice(&flags.to_be_bytes());
        header.extend_from_slice(&id.to_be_bytes());
        append(
            frame,
            offset,
            &header,
            &payload[position..position + count],
            options,
            &mut retained,
            &mut output,
        )?;
        position += count;
    }
    Ok(output)
}

fn unchanged(frame: &Frame, options: FragmentOptions) -> Result<Vec<Frame>, Error> {
    if frame.bytes().len() > options.max_output_bytes {
        return Err(Error::Limit {
            field: "max_output_bytes",
            limit: options.max_output_bytes,
        });
    }
    Ok(vec![frame.clone()])
}
fn payload_count(room: usize, remaining: usize) -> Result<usize, Error> {
    let count = if remaining <= room {
        remaining
    } else {
        room / 8 * 8
    };
    if count == 0 {
        return Err(Error::Invalid("MTU leaves no aligned fragment payload"));
    }
    Ok(count)
}
fn append(
    frame: &Frame,
    offset: usize,
    header: &[u8],
    payload: &[u8],
    options: FragmentOptions,
    retained: &mut usize,
    output: &mut Vec<Frame>,
) -> Result<(), Error> {
    if output.len() >= options.max_fragments {
        return Err(Error::Limit {
            field: "max_fragments",
            limit: options.max_fragments,
        });
    }
    let length =
        (offset + header.len() + payload.len()).max(if frame.link_type == LinkType::ETHERNET {
            60
        } else {
            0
        });
    *retained = retained
        .checked_add(length)
        .filter(|total| *total <= options.max_output_bytes)
        .ok_or(Error::Limit {
            field: "max_output_bytes",
            limit: options.max_output_bytes,
        })?;
    // The captured link header (addresses and VLAN tags) prefixes every
    // fragment unchanged; its trailer is dropped and Ethernet padding is
    // regenerated as zeros.
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&frame.bytes()[..offset]);
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(payload);
    bytes.resize(length, 0);
    let mut fragment = Frame::without_timestamp(frame.link_type, bytes)?;
    fragment.timestamp = frame.timestamp;
    fragment.interface = frame.interface;
    fragment.direction = frame.direction;
    output.push(fragment);
    Ok(())
}
