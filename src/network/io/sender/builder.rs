// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::engine::spec::PacketSpec;
use crate::network::sender::error::Result;

use super::ipv4;
use super::ipv6;
use super::layer2::{self, Layer2Resolved};
use super::transport::TransportBuild;
use super::types::{LinkType, NetworkTarget};

/// Result of constructing packets ready for transmission.
pub(crate) struct PacketBuildResult {
    pub(crate) frames: Vec<Vec<u8>>,
    pub(crate) link_type: LinkType,
    pub(crate) target: NetworkTarget,
}

/// Shared interface for IPv4 and IPv6 packet construction workflows.
pub(crate) trait PacketBuilder {
    fn build(
        &self,
        spec: &PacketSpec,
        transport: &TransportBuild,
        layer2: Option<&Layer2Resolved>,
    ) -> Result<PacketBuildResult>;
}

pub(crate) struct Ipv4PacketBuilder {
    pub(crate) source: Ipv4Addr,
    pub(crate) destination: Ipv4Addr,
}

impl PacketBuilder for Ipv4PacketBuilder {
    fn build(
        &self,
        spec: &PacketSpec,
        transport: &TransportBuild,
        layer2: Option<&Layer2Resolved>,
    ) -> Result<PacketBuildResult> {
        let packets = ipv4::build_ipv4_packets(
            spec,
            &transport.bytes,
            self.source,
            self.destination,
            transport.protocol,
        )?;
        let (frames, link_type) = layer2::wrap_link_layer(layer2, packets, LinkType::Ipv4)?;
        Ok(PacketBuildResult {
            frames,
            link_type,
            target: NetworkTarget::Ipv4(self.destination),
        })
    }
}

pub(crate) struct Ipv6PacketBuilder {
    pub(crate) source: Ipv6Addr,
    pub(crate) destination: Ipv6Addr,
    pub(crate) first_hop: Ipv6Addr,
}

impl PacketBuilder for Ipv6PacketBuilder {
    fn build(
        &self,
        spec: &PacketSpec,
        transport: &TransportBuild,
        layer2: Option<&Layer2Resolved>,
    ) -> Result<PacketBuildResult> {
        // Preserve first hop for L2 resolution and transmission target
        let packets = ipv6::build_ipv6_packets(
            spec,
            &transport.bytes,
            self.source,
            self.destination,
            transport.protocol,
        )?;
        let (frames, link_type) = layer2::wrap_link_layer(layer2, packets, LinkType::Ipv6)?;
        Ok(PacketBuildResult {
            frames,
            link_type,
            target: NetworkTarget::Ipv6(self.first_hop),
        })
    }
}
