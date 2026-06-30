// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv6Addr;

use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use rand::random;

use crate::domain::spec::{FragmentSpec, Ipv6ExtHeader, PacketSpec};
use crate::network::sender::error::{Ipv6Error, Result};

use super::fragment::{
    determine_more_flag, ensure_fragment_alignment, extract_fragment_payload, plan_fragments,
    FragmentPlan,
};
use super::header::{initialize_ipv6_header, IpHeaderContext};
pub(crate) use super::ipv6_ext::routing_initial_destination;
use super::ipv6_ext::{
    encode_extension_headers, get_header_protocol, measure_extension_headers,
    split_fragment_extension_headers, write_extension_headers,
};

pub(crate) const IPV6_HEADER_LEN: usize = 40;
pub(crate) const IPV6_FRAGMENT_HEADER_LEN: usize = 8;

type Ipv6Result<T> = std::result::Result<T, Ipv6Error>;

pub(crate) fn build_ipv6_packets(
    spec: &PacketSpec,
    transport: &[u8],
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    protocol: IpNextHeaderProtocol,
) -> Result<Vec<Vec<u8>>> {
    let context = Ipv6PacketContext::from_spec(spec, destination_ip)?;

    if !context.should_fragment() {
        let packet = build_unfragmented_ipv6_packet(transport, protocol, source_ip, &context)?;
        return Ok(vec![packet]);
    }

    build_fragmented_ipv6_packets(transport, protocol, source_ip, &context)
}

struct Ipv6PacketContext<'a> {
    header: IpHeaderContext,
    extension_headers: &'a [Ipv6ExtHeader],
    final_destination: Ipv6Addr,
    initial_destination: Ipv6Addr,
}

impl<'a> Ipv6PacketContext<'a> {
    fn from_spec(spec: &'a PacketSpec, destination_ip: Ipv6Addr) -> Result<Self> {
        let mut header = IpHeaderContext::from_spec(spec);
        normalize_fragment_spec(header.fragment_mut())?;

        let final_destination = destination_ip;
        let initial_destination =
            routing_initial_destination(&spec.ipv6.exthdrs, final_destination);

        Ok(Self {
            header,
            extension_headers: &spec.ipv6.exthdrs,
            final_destination,
            initial_destination,
        })
    }

    fn should_fragment(&self) -> bool {
        !self.header.fragment().is_default()
    }

    fn fragment(&self) -> &FragmentSpec {
        self.header.fragment()
    }

    fn header(&self) -> &IpHeaderContext {
        &self.header
    }

    fn base_offset(&self) -> u32 {
        self.header.fragment_offset() as u32
    }

    fn fragment_id(&self) -> Option<u32> {
        self.header.fragment().fragment_id
    }
}

fn normalize_fragment_spec(fragment: &mut FragmentSpec) -> Ipv6Result<()> {
    if !fragment.dont_fragment {
        return Ok(());
    }

    let mut normalized = fragment.clone();
    normalized.dont_fragment = false;
    if normalized.is_default() {
        fragment.dont_fragment = false;
        return Ok(());
    }

    Err(Ipv6Error::DontFragmentConflict)
}

fn build_fragmented_ipv6_packets(
    transport: &[u8],
    protocol: IpNextHeaderProtocol,
    source_ip: Ipv6Addr,
    context: &Ipv6PacketContext<'_>,
) -> Result<Vec<Vec<u8>>> {
    let (per_fragment_headers, trailing_headers) =
        split_fragment_extension_headers(context.extension_headers);

    let (per_fragment_bytes, first_next_header) = encode_extension_headers(
        per_fragment_headers,
        IpNextHeaderProtocols::Ipv6Frag,
        context.final_destination,
    )?;
    let (trailing_bytes, fragment_next_header) =
        encode_extension_headers(trailing_headers, protocol, context.final_destination)?;

    let common_header_len = IPV6_HEADER_LEN + per_fragment_bytes.len() + IPV6_FRAGMENT_HEADER_LEN;
    let fragment_plans = plan_fragments(
        context.fragment(),
        transport.len(),
        common_header_len,
        trailing_bytes.len(),
    )?;
    let base_offset = context.base_offset();
    let identification = context.fragment_id().unwrap_or_else(random::<u32>);

    let mut fragments = Vec::with_capacity(fragment_plans.len());
    for (index, plan) in fragment_plans.iter().enumerate() {
        ensure_fragment_alignment(plan)?;
        let payload_bytes = extract_fragment_payload(plan, transport);
        let buffer = assemble_ipv6_fragment(
            context,
            Ipv6FragmentParams {
                plan,
                position: FragmentPosition {
                    index,
                    total: fragment_plans.len(),
                },
                payload: &payload_bytes,
                per_fragment_bytes: &per_fragment_bytes,
                first_next_header,
                trailing_bytes: &trailing_bytes,
                fragment_next_header,
                base_offset,
                identification,
                common_header_len,
                source_ip,
            },
        )?;
        fragments.push(buffer);
    }

    if fragments.is_empty() {
        return Err(Ipv6Error::NoFragments.into());
    }

    Ok(fragments)
}

fn build_unfragmented_ipv6_packet(
    transport: &[u8],
    protocol: IpNextHeaderProtocol,
    source_ip: Ipv6Addr,
    context: &Ipv6PacketContext<'_>,
) -> Result<Vec<u8>> {
    let (mut buffer, ext_len) = build_ipv6_packet_with_extensions(
        context.header(),
        source_ip,
        context.initial_destination,
        context.final_destination,
        protocol,
        context.extension_headers,
        transport.len(),
    )?;
    let payload_start = IPV6_HEADER_LEN + ext_len;
    if buffer.len() < payload_start + transport.len() {
        return Err(Ipv6Error::BufferTooSmall.into());
    }
    buffer[payload_start..payload_start + transport.len()].copy_from_slice(transport);
    Ok(buffer)
}

fn build_ipv6_packet_with_extensions(
    context: &IpHeaderContext,
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    final_destination: Ipv6Addr,
    protocol: IpNextHeaderProtocol,
    extension_headers: &[Ipv6ExtHeader],
    payload_len: usize,
) -> Result<(Vec<u8>, usize)> {
    let ext_len = measure_extension_headers(extension_headers, final_destination)?;
    let total_payload_len = ext_len
        .checked_add(payload_len)
        .ok_or(Ipv6Error::PayloadLengthOverflow)?;
    if total_payload_len > u16::MAX as usize {
        return Err(Ipv6Error::PayloadTooLong.into());
    }

    let first_next_header = if extension_headers.is_empty() {
        protocol
    } else {
        get_header_protocol(&extension_headers[0])
    };

    let mut buffer = vec![0u8; IPV6_HEADER_LEN + ext_len + payload_len];
    let _ = initialize_ipv6_header(
        // Shared initializer ensures consistent hop-limit/traffic class
        &mut buffer,
        context,
        total_payload_len as u16,
        first_next_header,
        source_ip,
        destination_ip,
    )?;

    if !extension_headers.is_empty() {
        let ext_region = &mut buffer[IPV6_HEADER_LEN..IPV6_HEADER_LEN + ext_len];
        write_extension_headers(extension_headers, protocol, final_destination, ext_region)?;
    }
    Ok((buffer, ext_len))
}

#[derive(Copy, Clone)]
struct FragmentPosition {
    index: usize,
    total: usize,
}

struct Ipv6FragmentParams<'a> {
    plan: &'a FragmentPlan,
    position: FragmentPosition,
    payload: &'a [u8],
    per_fragment_bytes: &'a [u8],
    first_next_header: IpNextHeaderProtocol,
    trailing_bytes: &'a [u8],
    fragment_next_header: IpNextHeaderProtocol,
    base_offset: u32,
    identification: u32,
    common_header_len: usize,
    source_ip: Ipv6Addr,
}

fn assemble_ipv6_fragment(
    context: &Ipv6PacketContext<'_>,
    params: Ipv6FragmentParams<'_>,
) -> Result<Vec<u8>> {
    let more_flag = determine_more_flag(params.plan, params.position.index, params.position.total);
    let include_trailing = params.position.index == 0 && !params.trailing_bytes.is_empty();
    let trailing_len = if include_trailing {
        params.trailing_bytes.len()
    } else {
        0
    };
    let total_header_len = params.common_header_len + trailing_len;
    let mut buffer = vec![0u8; total_header_len + params.payload.len()];
    let fragment_payload_len = params
        .per_fragment_bytes
        .len()
        .checked_add(IPV6_FRAGMENT_HEADER_LEN)
        .and_then(|value| value.checked_add(trailing_len))
        .and_then(|value| value.checked_add(params.payload.len()))
        .ok_or(Ipv6Error::FragmentPayloadOverflow)?;
    if fragment_payload_len > u16::MAX as usize {
        return Err(Ipv6Error::FragmentPayloadTooLong.into());
    }
    let _ = initialize_ipv6_header(
        // Reuse shared initializer for consistency
        &mut buffer,
        context.header(),
        fragment_payload_len as u16,
        params.first_next_header,
        params.source_ip,
        context.initial_destination,
    )?;

    let fragment_offset_bytes = params.plan.start
        + if params.position.index == 0 {
            0
        } else {
            params.trailing_bytes.len()
        };
    let fragment_offset_units = params
        .base_offset
        .checked_add((fragment_offset_bytes / 8) as u32)
        .ok_or(Ipv6Error::FragmentOffsetOverflow)?;
    if fragment_offset_units > 0x1fff {
        return Err(Ipv6Error::FragmentOffsetTooLarge.into());
    }

    {
        let payload = &mut buffer[IPV6_HEADER_LEN..];
        let (ext_region, remainder) = payload.split_at_mut(params.per_fragment_bytes.len());
        ext_region.copy_from_slice(params.per_fragment_bytes);
        let (fragment_header, data_region) = remainder.split_at_mut(IPV6_FRAGMENT_HEADER_LEN);
        fragment_header[0] = params.fragment_next_header.0;
        fragment_header[1] = 0;
        let mut offset_field = (fragment_offset_units as u16) << 3; // RFC: 8-byte units
        if more_flag {
            offset_field |= 0x0001;
        }
        fragment_header[2..4].copy_from_slice(&offset_field.to_be_bytes());
        fragment_header[4..8].copy_from_slice(&params.identification.to_be_bytes());
        let (trailing_region, payload_region) = data_region.split_at_mut(trailing_len);
        if include_trailing {
            trailing_region.copy_from_slice(params.trailing_bytes);
        }
        payload_region.copy_from_slice(params.payload);
    }

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::request::{FragmentRequest, IpRequest, PacketRequest};
    use crate::network::sender::error::{Ipv6Error, SenderError};
    use pnet::packet::ipv6::Ipv6Packet;
    use pnet::packet::Packet;

    fn spec(fragment: FragmentRequest) -> PacketSpec {
        PacketSpec::from_request(&PacketRequest {
            ip: IpRequest {
                ttl: Some(32),
                tos: Some(0xcd),
                fragment,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap()
    }

    fn source() -> Ipv6Addr {
        Ipv6Addr::LOCALHOST
    }

    fn destination() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
    }

    #[test]
    fn build_ipv6_packets_builds_unfragmented_packet() {
        let packets = build_ipv6_packets(
            &spec(FragmentRequest::default()),
            b"udp",
            source(),
            destination(),
            IpNextHeaderProtocols::Udp,
        )
        .unwrap();

        assert_eq!(packets.len(), 1);
        let packet = Ipv6Packet::new(&packets[0]).unwrap();
        assert_eq!(packet.get_version(), 6);
        assert_eq!(packet.get_traffic_class(), 0xcd);
        assert_eq!(packet.get_payload_length(), 3);
        assert_eq!(packet.get_next_header(), IpNextHeaderProtocols::Udp);
        assert_eq!(packet.get_hop_limit(), 32);
        assert_eq!(packet.get_source(), source());
        assert_eq!(packet.get_destination(), destination());
        assert_eq!(packet.payload(), b"udp");
    }

    #[test]
    fn build_ipv6_packets_rejects_dont_fragment_with_fragmentation_directives() {
        let err = build_ipv6_packets(
            &spec(FragmentRequest {
                mtu: Some(64),
                dont_fragment: Some(true),
                ..Default::default()
            }),
            b"payload",
            source(),
            destination(),
            IpNextHeaderProtocols::Udp,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            SenderError::Ipv6(Ipv6Error::DontFragmentConflict)
        ));
    }

    #[test]
    fn build_ipv6_packets_ignores_lone_dont_fragment_flag() {
        let packets = build_ipv6_packets(
            &spec(FragmentRequest {
                dont_fragment: Some(true),
                ..Default::default()
            }),
            b"payload",
            source(),
            destination(),
            IpNextHeaderProtocols::Udp,
        )
        .unwrap();

        assert_eq!(packets.len(), 1);
        assert_eq!(
            Ipv6Packet::new(&packets[0]).unwrap().get_next_header(),
            IpNextHeaderProtocols::Udp
        );
    }

    #[test]
    fn build_ipv6_packets_inserts_fragment_headers_and_offsets() {
        let packets = build_ipv6_packets(
            &spec(FragmentRequest {
                mtu: Some(64),
                fragment_id: Some(0x0102_0304),
                ..Default::default()
            }),
            &[0xaa; 40],
            source(),
            destination(),
            IpNextHeaderProtocols::Udp,
        )
        .unwrap();

        assert_eq!(packets.len(), 3);
        let first = Ipv6Packet::new(&packets[0]).unwrap();
        let second = Ipv6Packet::new(&packets[1]).unwrap();
        assert_eq!(first.get_next_header(), IpNextHeaderProtocols::Ipv6Frag);
        assert_eq!(second.get_next_header(), IpNextHeaderProtocols::Ipv6Frag);
        assert_eq!(first.payload()[0], IpNextHeaderProtocols::Udp.0);
        assert_eq!(&first.payload()[4..8], &0x0102_0304u32.to_be_bytes());
        let first_offset = u16::from_be_bytes([first.payload()[2], first.payload()[3]]);
        let second_offset = u16::from_be_bytes([second.payload()[2], second.payload()[3]]);
        assert_eq!(first_offset & 0x0001, 1);
        assert_eq!(second_offset >> 3, 2);
    }
}
