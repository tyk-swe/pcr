// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use bytes::Bytes;

use super::*;
use crate::packet::{
    Packet,
    build::{BuildContext, BuildMode, BuildOptions, Builder},
    decode::{DecodeOptions, Dissector},
    expression::{Options as ExpressionOptions, parse as parse_packet_expression},
    field::WireValue,
    layer::{Padding, Raw},
};
use crate::protocol::{
    gre::Gre,
    icmp::{Icmpv4, Icmpv6},
    ipv6::{DestinationOptions, HopByHop, SegmentRoutingHeader},
    link::{Arp, Ethernet, Vlan, Vlan8021ad},
    network::{Igmp, Ipv4, Ipv6},
    transport::{Sctp, Tcp, Udp},
};

mod discriminator;
mod registration;
mod round_trip;
mod strictness_protocol_coverage;
mod wire_contract;
