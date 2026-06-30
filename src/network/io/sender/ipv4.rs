// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::checksum as ipv4_checksum;
use rand::random;

use crate::domain::spec::{FragmentSpec, PacketSpec};
use crate::network::sender::error::{Ipv4Error, Result};

use super::fragment::{
    determine_more_flag, ensure_fragment_alignment, extract_fragment_payload, plan_fragments,
    FragmentPlan,
};
use super::header::{initialize_ipv4_header, IpHeaderContext, Ipv4HeaderParams};

pub(crate) const IPV4_HEADER_LEN: usize = 20;

pub(crate) fn build_ipv4_packets(
    spec: &PacketSpec,
    transport: &[u8],
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    protocol: IpNextHeaderProtocol,
) -> Result<Vec<Vec<u8>>> {
    let context = Ipv4PacketContext::from_spec(spec);
    let fragment_plans = plan_fragments(context.fragment(), transport.len(), IPV4_HEADER_LEN, 0)?;
    let mut fragments: Vec<Vec<u8>> = Vec::new();

    for (index, plan) in fragment_plans.iter().enumerate() {
        ensure_fragment_alignment(plan)?;
        let payload_bytes = extract_fragment_payload(plan, transport);
        let buffer = assemble_ipv4_fragment(
            &context,
            Ipv4FragmentParams {
                plan,
                position: FragmentPosition {
                    index,
                    total: fragment_plans.len(),
                },
                payload: &payload_bytes,
                addresses: (source_ip, destination_ip),
                protocol,
            },
        )?;
        fragments.push(buffer);
    }

    if fragments.is_empty() {
        return Err(Ipv4Error::NoFragments.into());
    }

    Ok(fragments)
}

struct Ipv4PacketContext {
    header: IpHeaderContext,
    identification: u16,
}

impl Ipv4PacketContext {
    fn from_spec(spec: &PacketSpec) -> Self {
        let header = IpHeaderContext::from_spec(spec);
        let identification = spec
            .ip
            .as_ref()
            .and_then(|ip| ip.identification)
            .unwrap_or_else(random::<u16>);

        Self {
            header,
            identification,
        }
    }

    fn fragment(&self) -> &FragmentSpec {
        self.header.fragment()
    }

    fn base_offset(&self) -> u16 {
        self.header.fragment_offset()
    }

    fn dont_fragment(&self) -> bool {
        self.header.fragment().dont_fragment
    }

    fn header(&self) -> &IpHeaderContext {
        &self.header
    }

    fn identification(&self) -> u16 {
        self.identification
    }
}

#[derive(Copy, Clone)]
struct FragmentPosition {
    index: usize,
    total: usize,
}

struct Ipv4FragmentParams<'a> {
    plan: &'a FragmentPlan,
    position: FragmentPosition,
    payload: &'a [u8],
    addresses: (Ipv4Addr, Ipv4Addr),
    protocol: IpNextHeaderProtocol,
}

fn assemble_ipv4_fragment(
    context: &Ipv4PacketContext,
    params: Ipv4FragmentParams<'_>,
) -> Result<Vec<u8>> {
    let total_length_usize = IPV4_HEADER_LEN + params.payload.len();
    if total_length_usize > u16::MAX as usize {
        return Err(Ipv4Error::FragmentTooLarge {
            length: total_length_usize,
            max: u16::MAX as usize,
        }
        .into());
    }

    let total_length = total_length_usize as u16;
    let mut buffer = vec![0u8; total_length_usize];
    let more_flag = determine_more_flag(params.plan, params.position.index, params.position.total);
    let offset_units = context
        .base_offset()
        .checked_add((params.plan.start / 8) as u16)
        .ok_or(Ipv4Error::FragmentOffsetOverflow)?;
    if offset_units > 0x1FFF {
        return Err(Ipv4Error::FragmentOffsetTooLarge.into());
    }

    let (source_ip, destination_ip) = params.addresses;
    {
        let mut packet = initialize_ipv4_header(
            &mut buffer,
            context.header(),
            Ipv4HeaderParams {
                total_length,
                identification: context.identification(),
                protocol: params.protocol,
                source_ip,
                destination_ip,
                dont_fragment: context.dont_fragment(),
                more_flag,
                fragment_offset: offset_units,
            },
        )?;
        packet.set_payload(params.payload);
        // Checksum must reflect payload
        let checksum = ipv4_checksum(&packet.to_immutable());
        packet.set_checksum(checksum);
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::request::{FragmentRequest, IpRequest, PacketRequest};
    use crate::network::sender::error::{Ipv4Error, SenderError};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet};
    use pnet::packet::Packet;

    fn spec(fragment: FragmentRequest) -> PacketSpec {
        PacketSpec::from_request(&PacketRequest {
            ip: IpRequest {
                ttl: Some(31),
                tos: Some(0x2b),
                identification: Some(123),
                fragment,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn build_ipv4_packets_builds_unfragmented_packet() {
        let packets = build_ipv4_packets(
            &spec(FragmentRequest::default()),
            b"udp",
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 1),
            IpNextHeaderProtocols::Udp,
        )
        .unwrap();

        assert_eq!(packets.len(), 1);
        let packet = Ipv4Packet::new(&packets[0]).unwrap();
        assert_eq!(packet.get_version(), 4);
        assert_eq!(packet.get_ttl(), 31);
        assert_eq!(packet.get_dscp(), 0x0a);
        assert_eq!(packet.get_ecn(), 0x03);
        assert_eq!(packet.get_identification(), 123);
        assert_eq!(packet.get_next_level_protocol(), IpNextHeaderProtocols::Udp);
        assert_eq!(packet.get_source(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(packet.get_destination(), Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(packet.payload(), b"udp");
        assert_ne!(packet.get_checksum(), 0);
    }

    #[test]
    fn build_ipv4_packets_sets_fragment_offsets_and_more_flags() {
        let packets = build_ipv4_packets(
            &spec(FragmentRequest {
                mtu: Some(44),
                offset: Some(8),
                ..Default::default()
            }),
            &[0xaa; 40],
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 1),
            IpNextHeaderProtocols::Udp,
        )
        .unwrap();

        assert_eq!(packets.len(), 2);
        let first = Ipv4Packet::new(&packets[0]).unwrap();
        let second = Ipv4Packet::new(&packets[1]).unwrap();
        assert_eq!(first.get_fragment_offset(), 8);
        assert_ne!(first.get_flags() & Ipv4Flags::MoreFragments, 0);
        assert_eq!(first.payload().len(), 24);
        assert_eq!(second.get_fragment_offset(), 11);
        assert_eq!(second.get_flags() & Ipv4Flags::MoreFragments, 0);
        assert_eq!(second.payload().len(), 16);
    }

    #[test]
    fn build_ipv4_packets_rejects_oversized_unfragmented_payload() {
        let payload = vec![0u8; u16::MAX as usize - IPV4_HEADER_LEN + 1];
        let err = build_ipv4_packets(
            &spec(FragmentRequest::default()),
            &payload,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 1),
            IpNextHeaderProtocols::Udp,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            SenderError::Ipv4(Ipv4Error::FragmentTooLarge { length, max })
                if length == u16::MAX as usize + 1 && max == u16::MAX as usize
        ));
    }
}
