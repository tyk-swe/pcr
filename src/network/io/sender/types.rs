// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet::datalink::NetworkInterface;
use pnet::packet::ip::IpNextHeaderProtocol;

use crate::domain::spec::{LoggingSpec, TransmissionSpec};

use super::control::TransmissionPolicy;

#[derive(Debug, Clone)]
pub enum LinkType {
    Ethernet,
    Ipv4,
    Ipv6,
}

impl LinkType {
    pub fn as_str(&self) -> &'static str {
        match self {
            LinkType::Ethernet => "ethernet",
            LinkType::Ipv4 => "ipv4",
            LinkType::Ipv6 => "ipv6",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanningMode {
    Live,
    DryRun,
}

#[derive(Debug, Clone)]
pub struct TransmissionPlan {
    pub frames: Vec<Vec<u8>>,
    pub link_type: LinkType,
    pub transmit: TransmissionSpec,
    pub destination: NetworkTarget,
    pub interface: NetworkInterface,
    pub selection: SelectionMetadata,
    pub protocol: IpNextHeaderProtocol,
    pub summary: TransmissionSummary,
    pub logging: LoggingSpec,
    pub mode: PlanningMode,
    pub policy: TransmissionPolicy,
}

#[derive(Debug, Clone)]
pub struct TransmissionSummary {
    pub payload_len: usize,
    pub largest_frame_len: usize,
    pub frame_count: usize,
    pub transport: &'static str,
}

#[derive(Debug, Clone)]
pub enum NetworkTarget {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionMetadata {
    pub selected_interface: String,
    pub interface_reason: InterfaceSelectionReason,
    pub source_ip: IpAddr,
    pub source_reason: SourceSelectionReason,
    pub destination_ip: IpAddr,
    pub destination_reason: DestinationSelectionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceSelectionReason {
    ExplicitInterface,
    RouteTable,
    Heuristic,
}

impl InterfaceSelectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitInterface => "explicit_interface",
            Self::RouteTable => "route_table",
            Self::Heuristic => "heuristic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceSelectionReason {
    ExplicitSourceIp,
    InterfaceAddress,
    Ipv6ScopeMatch,
}

impl SourceSelectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitSourceIp => "explicit_source_ip",
            Self::InterfaceAddress => "interface_address",
            Self::Ipv6ScopeMatch => "ipv6_scope_match",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationSelectionReason {
    HostnameResolution,
    TargetLiteral,
}

impl DestinationSelectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostnameResolution => "hostname_resolution",
            Self::TargetLiteral => "target_literal",
        }
    }
}
