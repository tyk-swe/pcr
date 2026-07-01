// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

mod destination;
mod error;
mod fragment;
mod ip;
mod ipv6;
mod layer2;
mod listener;
mod logging;
mod packet;
mod payload;
mod transmission;
mod transport;
mod utils;

pub(crate) use destination::{DestinationSpec, TargetAddress};
pub(crate) use error::SpecError;
pub(crate) use fragment::FragmentSpec;
pub(crate) use ipv6::{Ipv6ExtHeader, MAX_ROUTING_SEGMENTS};
pub(crate) use layer2::VlanTag;
pub(crate) use listener::ListenerSpec;
pub(crate) use logging::LoggingSpec;
pub(crate) use packet::PacketSpec;
pub(crate) use payload::PayloadSource;
#[cfg(feature = "fuzz")]
pub(crate) use payload::PayloadSpec;
pub(crate) use transmission::TransmissionSpec;
pub(crate) use transport::{IcmpSpec, Icmpv6Spec, TcpFlagSet, TcpSpec, TransportSpec, UdpSpec};
