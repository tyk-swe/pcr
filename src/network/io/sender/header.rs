// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;

use crate::domain::spec::{FragmentSpec, PacketSpec};
use crate::network::sender::error::{HeaderError, Result};

#[derive(Clone)]
pub(crate) struct IpHeaderContext {
    ttl: u8,
    traffic_class: u8,
    fragment: FragmentSpec,
}

pub(crate) struct Ipv4HeaderParams {
    pub(crate) total_length: u16,
    pub(crate) identification: u16,
    pub(crate) protocol: IpNextHeaderProtocol,
    pub(crate) source_ip: Ipv4Addr,
    pub(crate) destination_ip: Ipv4Addr,
    pub(crate) dont_fragment: bool,
    pub(crate) more_flag: bool,
    pub(crate) fragment_offset: u16,
}

pub(crate) fn initialize_ipv4_header<'a>(
    buffer: &'a mut [u8],
    context: &IpHeaderContext,
    params: Ipv4HeaderParams,
) -> Result<MutableIpv4Packet<'a>> {
    let mut packet = MutableIpv4Packet::new(buffer).ok_or(HeaderError::Ipv4AllocationFailed)?;
    packet.set_version(4);
    packet.set_header_length(5);
    packet.set_total_length(params.total_length);
    packet.set_ttl(context.ttl());
    packet.set_dscp(context.dscp());
    packet.set_ecn(context.ecn());
    packet.set_identification(params.identification);
    let mut flags = 0u8;
    if params.dont_fragment {
        flags |= pnet::packet::ipv4::Ipv4Flags::DontFragment;
    }
    if params.more_flag {
        flags |= pnet::packet::ipv4::Ipv4Flags::MoreFragments;
    }
    packet.set_flags(flags);
    packet.set_fragment_offset(params.fragment_offset);
    packet.set_next_level_protocol(params.protocol);
    packet.set_source(params.source_ip);
    packet.set_destination(params.destination_ip);
    packet.set_checksum(0);
    Ok(packet)
}

pub(crate) fn initialize_ipv6_header<'a>(
    buffer: &'a mut [u8],
    context: &IpHeaderContext,
    payload_length: u16,
    next_header: IpNextHeaderProtocol,
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
) -> Result<MutableIpv6Packet<'a>> {
    let mut packet = MutableIpv6Packet::new(buffer).ok_or(HeaderError::Ipv6AllocationFailed)?;
    packet.set_version(6);
    packet.set_traffic_class(context.traffic_class());
    packet.set_flow_label(0);
    packet.set_payload_length(payload_length);
    packet.set_next_header(next_header);
    packet.set_hop_limit(context.hop_limit());
    packet.set_source(source_ip);
    packet.set_destination(destination_ip);
    Ok(packet)
}

impl IpHeaderContext {
    pub(crate) fn from_spec(spec: &PacketSpec) -> Self {
        let ip_spec = spec.ip.as_ref();
        let ttl = ip_spec.and_then(|ip| ip.ttl).unwrap_or(64);
        let traffic_class = ip_spec.and_then(|ip| ip.tos).unwrap_or(0);
        let fragment = ip_spec
            .map(|ip| ip.fragmentation.clone())
            .unwrap_or_default();

        Self {
            ttl,
            traffic_class,
            fragment,
        }
    }

    pub(crate) fn ttl(&self) -> u8 {
        self.ttl
    }

    pub(crate) fn hop_limit(&self) -> u8 {
        self.ttl
    }

    pub(crate) fn dscp(&self) -> u8 {
        self.traffic_class >> 2
    }

    pub(crate) fn ecn(&self) -> u8 {
        self.traffic_class & 0b11
    }

    pub(crate) fn traffic_class(&self) -> u8 {
        self.traffic_class
    }

    pub(crate) fn fragment(&self) -> &FragmentSpec {
        &self.fragment
    }

    pub(crate) fn fragment_mut(&mut self) -> &mut FragmentSpec {
        &mut self.fragment
    }

    pub(crate) fn fragment_offset(&self) -> u16 {
        self.fragment.offset.unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::request::{FragmentRequest, IpRequest, PacketRequest};
    use pnet::packet::ip::IpNextHeaderProtocols;

    fn packet_spec(ip: IpRequest) -> PacketSpec {
        PacketSpec::from_request(&PacketRequest {
            ip,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn ip_header_context_defaults_match_send_defaults() {
        let context = IpHeaderContext::from_spec(&PacketSpec::default());

        assert_eq!(context.ttl(), 64);
        assert_eq!(context.hop_limit(), 64);
        assert_eq!(context.traffic_class(), 0);
        assert_eq!(context.fragment_offset(), 0);
        assert!(context.fragment().is_default());
    }

    #[test]
    fn ip_header_context_reads_ip_fields_from_spec() {
        let context = IpHeaderContext::from_spec(&packet_spec(IpRequest {
            ttl: Some(31),
            tos: Some(0b1010_0011),
            fragment: FragmentRequest {
                offset: Some(16),
                more_fragments: Some(true),
                ..Default::default()
            },
            ..Default::default()
        }));

        assert_eq!(context.ttl(), 31);
        assert_eq!(context.dscp(), 0b0010_1000);
        assert_eq!(context.ecn(), 0b11);
        assert_eq!(context.fragment_offset(), 16);
        assert!(context.fragment().more_fragments);
    }

    #[test]
    fn initialize_ipv4_header_sets_core_fields_and_flags() {
        let context = IpHeaderContext::from_spec(&packet_spec(IpRequest {
            ttl: Some(40),
            tos: Some(0b0011_0101),
            ..Default::default()
        }));
        let mut buffer = [0u8; 20];
        let packet = initialize_ipv4_header(
            &mut buffer,
            &context,
            Ipv4HeaderParams {
                total_length: 20,
                identification: 99,
                protocol: IpNextHeaderProtocols::Tcp,
                source_ip: Ipv4Addr::new(192, 0, 2, 1),
                destination_ip: Ipv4Addr::new(198, 51, 100, 1),
                dont_fragment: true,
                more_flag: true,
                fragment_offset: 8,
            },
        )
        .unwrap();

        assert_eq!(packet.get_version(), 4);
        assert_eq!(packet.get_header_length(), 5);
        assert_eq!(packet.get_total_length(), 20);
        assert_eq!(packet.get_ttl(), 40);
        assert_eq!(packet.get_dscp(), 0b0000_1101);
        assert_eq!(packet.get_ecn(), 0b01);
        assert_eq!(packet.get_identification(), 99);
        assert_eq!(
            packet.get_flags(),
            pnet::packet::ipv4::Ipv4Flags::DontFragment
                | pnet::packet::ipv4::Ipv4Flags::MoreFragments
        );
        assert_eq!(packet.get_fragment_offset(), 8);
        assert_eq!(packet.get_next_level_protocol(), IpNextHeaderProtocols::Tcp);
        assert_eq!(packet.get_source(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(packet.get_destination(), Ipv4Addr::new(198, 51, 100, 1));
    }

    #[test]
    fn initialize_ipv6_header_sets_core_fields() {
        let context = IpHeaderContext::from_spec(&packet_spec(IpRequest {
            ttl: Some(44),
            tos: Some(0xab),
            ..Default::default()
        }));
        let source = Ipv6Addr::LOCALHOST;
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut buffer = [0u8; 40];
        let packet = initialize_ipv6_header(
            &mut buffer,
            &context,
            16,
            IpNextHeaderProtocols::Udp,
            source,
            destination,
        )
        .unwrap();

        assert_eq!(packet.get_version(), 6);
        assert_eq!(packet.get_traffic_class(), 0xab);
        assert_eq!(packet.get_payload_length(), 16);
        assert_eq!(packet.get_next_header(), IpNextHeaderProtocols::Udp);
        assert_eq!(packet.get_hop_limit(), 44);
        assert_eq!(packet.get_source(), source);
        assert_eq!(packet.get_destination(), destination);
    }
}
