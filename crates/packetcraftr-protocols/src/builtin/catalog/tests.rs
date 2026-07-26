// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Built-in catalog integration tests.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use bytes::Bytes;

use super::*;
use crate::{
    gre::Gre,
    icmp::{Icmpv4, Icmpv6},
    ipv6::{DestinationOptions, HopByHop, SegmentRoutingHeader},
    link::{Arp, Ethernet, Vlan, Vlan8021ad},
    network::{Igmp, Ipv4, Ipv6},
    transport::{Sctp, Tcp, Udp},
};
use packetcraftr_packet::{
    Packet,
    build::{BuildContext, BuildMode, BuildOptions, Builder},
    decode::{DecodeOptions, Dissector},
    expression::{Options as ExpressionOptions, parse as parse_packet_expression},
    field::WireValue,
    layer::{Padding, Raw},
};

#[path = "tests/discriminator.rs"]
mod discriminator;
#[path = "tests/registration.rs"]
mod registration;
#[path = "tests/round_trip.rs"]
mod round_trip;
#[path = "tests/strictness_protocol_coverage.rs"]
mod strictness_protocol_coverage;
#[path = "tests/wire_contract.rs"]
mod wire_contract;
