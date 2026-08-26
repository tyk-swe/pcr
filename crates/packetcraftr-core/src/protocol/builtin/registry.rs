// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Portable built-in Internet protocol layers and their deterministic registry module.

use super::super::{
    application, capture as capture_link, gre, icmp, ipv6 as ipv6_ext, link, matcher,
    network as ip, raw, transport, tunnel,
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

use application::{DnsCodec, TlsCodec};

pub(crate) mod registration;

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
    registry_with(|_builder| Ok(()))
}

/// Build the default registry, then let the caller add bindings before it is
/// frozen.
///
/// The default registry is immutable once built, so a command that remaps a
/// service onto a non-standard port — `--tls-port 4433` — needs the extra
/// binding before [`crate::registry::Builder::build`]. `extra` sees a builder
/// already carrying every built-in codec and binding, so it can bind, but not
/// unbind, and a conflicting binding is reported as
/// [`crate::registry::Error`].
///
/// ```
/// use packetcraftr_core::protocol::builtin;
///
/// let registry = builtin::registry_with(|builder| {
///     builder.bind("tcp", 4433, "tls", 100)?;
///     Ok(())
/// })
/// .expect("extra binding is valid");
/// assert_eq!(
///     registry
///         .child_for("tcp", packetcraftr_core::registry::Discriminator(4433))
///         .map(|protocol| protocol.as_str()),
///     Some("tls")
/// );
/// ```
pub fn registry_with<F>(extra: F) -> Result<crate::registry::Registry, crate::registry::Error>
where
    F: FnOnce(&mut crate::registry::Builder) -> Result<(), crate::registry::Error>,
{
    let mut builder = crate::registry::Registry::builder();
    register_catalog(&mut builder)?;
    registration::register(&mut builder)?;
    extra(&mut builder)?;
    builder.build()
}

/// Build the default registry with extra TCP ports dissected as TLS.
///
/// The built-in ports stay bound; `ports` adds to them. Re-binding a port that
/// is already TLS is accepted, so a caller need not filter the default list.
///
/// ```
/// use packetcraftr_core::protocol::builtin;
///
/// let registry = builtin::registry_with_tls_ports(&[4433]).expect("extra TLS port");
/// assert_eq!(
///     registry
///         .child_for("tcp", packetcraftr_core::registry::Discriminator(4433))
///         .map(|protocol| protocol.as_str()),
///     Some("tls")
/// );
/// ```
pub fn registry_with_tls_ports(
    ports: &[u16],
) -> Result<crate::registry::Registry, crate::registry::Error> {
    registry_with(|builder| registration::bind_tls_ports(builder, ports))
}
