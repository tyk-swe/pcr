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

pub use destination::{DestinationSpec, TargetAddress};
pub use error::{SpecError, SpecResult};
pub use fragment::FragmentSpec;
pub use ip::IpSpec;
pub use ipv6::{Ipv6ExtHeader, Ipv6Spec, MAX_ROUTING_SEGMENTS};
pub use layer2::{Layer2Spec, VlanTag};
pub use listener::ListenerSpec;
pub use logging::LoggingSpec;
pub use packet::PacketSpec;
pub use payload::{PayloadSource, PayloadSpec};
pub use transmission::TransmissionSpec;
pub use transport::{IcmpSpec, Icmpv6Spec, TcpFlagSet, TcpSpec, TransportSpec, UdpSpec};
