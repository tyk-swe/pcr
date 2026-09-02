// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Portable built-in Internet protocol layers and their deterministic registry module.

use std::sync::{Arc, OnceLock};

use crate::protocol::{
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

use crate::protocol::BuiltinProtocol;
use crate::protocol::catalog::builtin_protocol_catalog;

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
                exact_round_trip: $exact_round_trip:literal,
                matcher: $matcher:ident,
                codec: $codec:ident
            }
        )*) => {{
            $(
                builder.register_codec($codec, BuiltinProtocol::$variant.aliases())?;
                register_matcher!($variant, $matcher);
            )*
            Ok(())
        }};
    }

    builtin_protocol_catalog!(register_protocols)
}

/// The default immutable registry, built once and shared by every caller.
///
/// The built-in catalog is a static property of compiled-in code, so this
/// cannot fail at runtime; use [`registry_with`] when a caller-supplied
/// closure may conflict with the defaults.
///
/// # Panics
///
/// Panics if the built-in catalog registers a duplicate protocol, alias, link
/// type, matcher, or filter path — a defect in this crate, not in caller
/// input. `builtin_registry_initializes_and_is_shared` pins that it does not.
pub fn registry() -> Arc<crate::registry::Registry> {
    static REGISTRY: OnceLock<Arc<crate::registry::Registry>> = OnceLock::new();
    Arc::clone(REGISTRY.get_or_init(|| {
        Arc::new(registry_with(|_builder| Ok(())).expect("built-in catalog must register"))
    }))
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

#[cfg(test)]
mod tests {
    #[test]
    fn builtin_registry_initializes_and_is_shared() {
        let first = super::registry();
        let second = super::registry();
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "the built-in registry must be built once and shared"
        );
        assert!(
            first.codec_named("ethernet").is_some(),
            "the shared registry must carry the built-in catalog"
        );
    }
}
