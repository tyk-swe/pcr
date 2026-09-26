// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Error;
use crate::frame::{Frame, LinkType};
use crate::protocol::checksum;

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
    let offset = ip_offset(frame)?;
    let ip = frame
        .bytes()
        .get(offset..)
        .ok_or(Error::Invalid("missing IP header"))?;
    let version = ip.first().map(|byte| byte >> 4);
    if (frame.link_type == LinkType::IPV4 && version != Some(4))
        || (frame.link_type == LinkType::IPV6 && version != Some(6))
    {
        return Err(Error::Invalid("link type disagrees with IP version"));
    }
    match version {
        Some(4) => ipv4(frame, offset, ip, options),
        Some(6) => ipv6(frame, offset, ip, options),
        _ => Err(Error::Invalid("unrecognized IP version")),
    }
}

fn ip_offset(frame: &Frame) -> Result<usize, Error> {
    match frame.link_type {
        link_type if link_type.is_raw_ip() => Ok(0),
        LinkType::ETHERNET => {
            let bytes = frame.bytes();
            let (offset, kind) = super::ethernet_payload(bytes, u16_at)?;
            if !matches!(kind, 0x0800 | 0x86dd) {
                return Err(Error::Unsupported("Ethernet payload is not IPv4/IPv6"));
            }
            if bytes.get(offset).map(|byte| byte >> 4) != Some(if kind == 0x0800 { 4 } else { 6 }) {
                return Err(Error::Invalid("EtherType disagrees with IP version"));
            }
            Ok(offset)
        }
        _ => Err(Error::Unsupported(
            "capture link type is not raw IP or Ethernet/VLAN",
        )),
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let bytes = bytes
        .get(offset..offset + 2)
        .ok_or(Error::Invalid("truncated header"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn ipv4(
    frame: &Frame,
    offset: usize,
    ip: &[u8],
    options: FragmentOptions,
) -> Result<Vec<Frame>, Error> {
    if ip.len() < 20 {
        return Err(Error::Invalid("truncated IPv4 header"));
    }
    let header_len = usize::from(ip[0] & 15) * 4;
    let length = usize::from(u16_at(ip, 2)?);
    if header_len < 20 || length < header_len || length > ip.len() {
        return Err(Error::Invalid("invalid IPv4 lengths"));
    }
    if checksum(&ip[..header_len]) != 0 {
        return Err(Error::Invalid("invalid IPv4 header checksum"));
    }
    let flags = u16_at(ip, 6)?;
    if flags & 0x8000 != 0 {
        return Err(Error::Invalid("IPv4 reserved flag is set"));
    }
    if flags & 0x3fff != 0 {
        return Err(Error::Unsupported("already fragmented IPv4"));
    }
    if length <= options.mtu {
        return unchanged(frame, options);
    }
    if flags & 0x4000 != 0 {
        return Err(Error::Unsupported("IPv4 DF prohibits fragmentation"));
    }
    if length == header_len {
        return Err(Error::Invalid("MTU cannot contain the IPv4 header"));
    }
    let copied = copied_options(&ip[20..header_len])?;
    let id = options
        .identification
        .map(u16::try_from)
        .transpose()
        .map_err(|_| Error::Invalid("IPv4 identification exceeds 16 bits"))?
        .unwrap_or(u16_at(ip, 4)?);
    let payload = &ip[header_len..length];
    let mut position = 0;
    let mut output = Vec::new();
    let mut retained = 0;
    while position < payload.len() {
        let mut header = if position == 0 {
            ip[..header_len].to_vec()
        } else {
            let mut header = ip[..20].to_vec();
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
        header[10..12].fill(0);
        let sum = checksum(&header);
        header[10..12].copy_from_slice(&sum.to_be_bytes());
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

fn copied_options(options: &[u8]) -> Result<Vec<u8>, Error> {
    let mut copied = Vec::new();
    let mut cursor = 0;
    while let Some(&kind) = options.get(cursor) {
        if kind == 0 {
            break;
        }
        if kind == 1 {
            cursor += 1;
            continue;
        }
        let length = usize::from(
            *options
                .get(cursor + 1)
                .ok_or(Error::Invalid("truncated IPv4 option"))?,
        );
        if length < 2 {
            return Err(Error::Invalid("invalid IPv4 option length"));
        }
        let value = options
            .get(cursor..cursor + length)
            .ok_or(Error::Invalid("truncated IPv4 option"))?;
        if kind & 0x80 != 0 {
            copied.extend_from_slice(value);
        }
        cursor += length;
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
    options: FragmentOptions,
) -> Result<Vec<Frame>, Error> {
    if ip.len() < 40 {
        return Err(Error::Invalid("truncated IPv6 header"));
    }
    let length = usize::from(u16_at(ip, 4)?) + 40;
    if length == 40 {
        return Err(Error::Unsupported("IPv6 jumbogram or empty datagram"));
    }
    if length > ip.len() {
        return Err(Error::Invalid("truncated IPv6 payload"));
    }
    let mut next = ip[6];
    let mut cursor = 40;
    let mut prefix_len = 40;
    let mut prefix_next = 6;
    let mut count = 0;
    while matches!(next, 0 | 43 | 60) {
        if count >= 64 {
            return Err(Error::Limit {
                field: "IPv6 extension depth",
                limit: 64,
            });
        }
        let header = ip
            .get(cursor..cursor + 2)
            .ok_or(Error::Invalid("truncated IPv6 extension"))?;
        let size = (usize::from(header[1]) + 1) * 8;
        if cursor + size > length {
            return Err(Error::Invalid("truncated IPv6 extension"));
        }
        if next == 0 && cursor != 40 {
            return Err(Error::Unsupported("misordered Hop-by-Hop header"));
        }
        let previous = cursor;
        cursor += size;
        if matches!(next, 0 | 43) {
            prefix_len = cursor;
            prefix_next = previous;
        }
        next = header[0];
        count += 1;
    }
    if matches!(next, 44 | 50 | 51) {
        return Err(Error::Unsupported("fragment, AH or ESP header"));
    }
    if length <= options.mtu {
        return unchanged(frame, options);
    }
    let transport_len = match next {
        6 => {
            let value = *ip
                .get(cursor + 12)
                .ok_or(Error::Invalid("truncated TCP header"))?;
            let size = usize::from(value >> 4) * 4;
            if size < 20 {
                return Err(Error::Invalid("invalid TCP header length"));
            }
            size
        }
        17 | 58 => 8,
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
        header[prefix_next] = 44;
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
