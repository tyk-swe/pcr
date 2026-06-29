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
