// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_packet::{
    registry::{RegistryBuilder, RegistryError},
    semantics::BuiltinProtocol,
};

use super::{bind, bind_ip_children, bind_ipv6_children, bind_ipv6_extensions};

pub(super) fn register(builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
    bind_ip_children(builder, BuiltinProtocol::Ipv4, 1)?;
    bind_ip_children(builder, BuiltinProtocol::RawIp, 1)?;
    bind_ipv6_children(builder, BuiltinProtocol::Ipv6)?;
    bind_ipv6_extensions(builder, BuiltinProtocol::Ipv6)?;
    for parent in [
        BuiltinProtocol::Ipv6HopByHop,
        BuiltinProtocol::Ipv6DestinationOptions,
        BuiltinProtocol::Ipv6Fragment,
        BuiltinProtocol::Ipv6Srh,
    ] {
        bind_ipv6_children(builder, parent)?;
        bind_ipv6_extensions(builder, parent)?;
    }
    bind(
        builder,
        BuiltinProtocol::RawIp,
        58,
        BuiltinProtocol::Icmpv6,
        100,
    )?;

    bind_ip_children(builder, BuiltinProtocol::Ah, 1)?;
    bind(
        builder,
        BuiltinProtocol::Ah,
        58,
        BuiltinProtocol::Icmpv6,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Ah,
        59,
        BuiltinProtocol::Malformed,
        100,
    )?;
    bind_ipv6_extensions(builder, BuiltinProtocol::Ah)
}
