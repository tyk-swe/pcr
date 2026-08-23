// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Portable built-in Internet protocol layers and their deterministic registry module.

use super::super::{
    application, capture as capture_link, ipv6 as ipv6_ext, link, matcher,
    network::{self as ip, icmp},
    raw, transport,
    tunnel::{self, gre},
};

use capture_link::{BsdLoopCodec, BsdNullCodec, LinuxSll2Codec, LinuxSllCodec};
use gre::GreCodec;
use icmp::{Icmpv4Codec, Icmpv6Codec};
use ip::{IgmpCodec, Ipv4Codec, Ipv6Codec, RawIpCodec};
use ipv6_ext::{DestinationOptionsCodec, FragmentCodec, HopByHopCodec, SegmentRoutingHeaderCodec};
use link::{ArpCodec, EthernetCodec, LlcCodec, SnapCodec, Vlan8021adCodec, VlanCodec};
use raw::{MalformedCodec, PaddingCodec, RawCodec};
use transport::{SctpCodec, TcpCodec, UdpCodec};
use tunnel::{
    AhCodec, ErspanCodec, EspCodec, GeneveCodec, L2tpv3Codec, MplsCodec, PppCodec, PppoeCodec,
    VxlanCodec,
};

use crate::semantics::{BuiltinProtocol, builtin_protocol_catalog};

use application::DnsCodec;

mod registration;

fn register_catalog(builder: &mut crate::registry::Builder) -> Result<(), crate::registry::Error> {
    macro_rules! register_matcher {
        ($variant:ident, none) => {};
        ($variant:ident, reverse_flow) => {
            builder.register_matcher(
                BuiltinProtocol::$variant.as_str(),
                matcher::ReverseFlowMatcher::new(BuiltinProtocol::$variant),
            )?;
        };
        ($variant:ident, echo_v4) => {
            builder.register_matcher(
                BuiltinProtocol::$variant.as_str(),
                matcher::EchoMatcher::v4(),
            )?;
        };
        ($variant:ident, echo_v6) => {
            builder.register_matcher(
                BuiltinProtocol::$variant.as_str(),
                matcher::EchoMatcher::v6(),
            )?;
        };
    }

    macro_rules! register_protocols {
        ($(
            $variant:ident {
                canonical: $canonical:literal,
                aliases: [$($alias:literal),* $(,)?],
                constructible: $constructible:literal,
                matcher: $matcher:ident,
                codec: $codec:ident
            }
        )*) => {{
            $(
                builder.register_builtin_codec($codec, BuiltinProtocol::$variant.aliases())?;
                register_matcher!($variant, $matcher);
            )*
            Ok(())
        }};
    }

    builtin_protocol_catalog!(register_protocols)
}

/// Build the default immutable registry without global mutable registration.
pub fn registry() -> Result<crate::registry::Registry, crate::registry::Error> {
    let mut builder = crate::registry::Registry::builder();
    register_catalog(&mut builder)?;
    registration::register(&mut builder)?;
    builder.build()
}
