// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod envelope;
mod icmp;
mod igmp;
pub mod igmpv3;
mod ipv4;
mod ipv6;
pub mod mld;
pub mod ndp;
mod raw_ip;
mod vrrp;

pub mod ip_protocol {
    pub const HOP_BY_HOP: u8 = 0;
    pub const ICMPV4: u8 = 1;
    pub const IGMP: u8 = 2;
    pub const IPV4: u8 = 4;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const IPV6: u8 = 41;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const GRE: u8 = 47;
    pub const ESP: u8 = 50;
    pub const AH: u8 = 51;
    pub const ICMPV6: u8 = 58;
    pub const NO_NEXT_HEADER: u8 = 59;
    pub const DESTINATION_OPTIONS: u8 = 60;
    pub const VRRP: u8 = 112;
    pub const SCTP: u8 = 132;
}

pub(crate) use envelope::resolve_envelope;
pub use icmp::{Icmpv4, Icmpv6};
pub(crate) use icmp::{Icmpv4Codec, Icmpv6Codec};
pub use igmp::Igmp;
pub(crate) use igmp::IgmpCodec;
pub use ipv4::Ipv4;
pub(crate) use ipv4::Ipv4Codec;
pub use ipv6::{DestinationOptions, Fragment, HopByHop, Ipv6, SegmentRoutingHeader};
pub(crate) use ipv6::{
    DestinationOptionsCodec, FragmentCodec, HopByHopCodec, Ipv6Codec, SegmentRoutingHeaderCodec,
};
pub(crate) use raw_ip::RawIpCodec;
pub use vrrp::Vrrp;
pub(crate) use vrrp::VrrpCodec;
