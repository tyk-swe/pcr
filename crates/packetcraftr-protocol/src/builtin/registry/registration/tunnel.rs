// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_packet::{
    registry::{RegistryBuilder, RegistryError},
    semantics::BuiltinProtocol,
};

use super::bind;
use crate::tunnel::{
    MPLS_BOTTOM_RAW, MPLS_BOTTOM_VERSION_BASE, MPLS_NEXT_LABEL, PPPOE_DISCOVERY, PPPOE_SESSION,
};

pub(super) fn register(builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
    bind(builder, BuiltinProtocol::Esp, 0, BuiltinProtocol::Raw, 0)?;
    bind(builder, BuiltinProtocol::L2tpv3, 0, BuiltinProtocol::Raw, 0)?;

    bind(
        builder,
        BuiltinProtocol::Gre,
        0x0800,
        BuiltinProtocol::Ipv4,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Gre,
        0x86dd,
        BuiltinProtocol::Ipv6,
        100,
    )?;
    bind(builder, BuiltinProtocol::Gre, 0, BuiltinProtocol::Raw, -100)?;
    bind(
        builder,
        BuiltinProtocol::Gre,
        0x88be,
        BuiltinProtocol::Erspan,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Gre,
        0x22eb,
        BuiltinProtocol::Erspan,
        90,
    )?;
    bind(
        builder,
        BuiltinProtocol::Erspan,
        0,
        BuiltinProtocol::Ethernet,
        100,
    )?;

    bind(
        builder,
        BuiltinProtocol::Udp,
        4789,
        BuiltinProtocol::Vxlan,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Vxlan,
        0,
        BuiltinProtocol::Ethernet,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Udp,
        6081,
        BuiltinProtocol::Geneve,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Geneve,
        0x6558,
        BuiltinProtocol::Ethernet,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Geneve,
        0x0800,
        BuiltinProtocol::Ipv4,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Geneve,
        0x86dd,
        BuiltinProtocol::Ipv6,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Geneve,
        0,
        BuiltinProtocol::Raw,
        -100,
    )?;

    bind(
        builder,
        BuiltinProtocol::Pppoe,
        PPPOE_SESSION,
        BuiltinProtocol::Ppp,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Pppoe,
        PPPOE_DISCOVERY,
        BuiltinProtocol::Raw,
        0,
    )?;
    bind(
        builder,
        BuiltinProtocol::Ppp,
        0x0021,
        BuiltinProtocol::Ipv4,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Ppp,
        0x0057,
        BuiltinProtocol::Ipv6,
        100,
    )?;
    bind(builder, BuiltinProtocol::Ppp, 0, BuiltinProtocol::Raw, -100)?;

    bind(
        builder,
        BuiltinProtocol::Mpls,
        MPLS_NEXT_LABEL,
        BuiltinProtocol::Mpls,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Mpls,
        MPLS_BOTTOM_VERSION_BASE + 4,
        BuiltinProtocol::Ipv4,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Mpls,
        MPLS_BOTTOM_VERSION_BASE + 6,
        BuiltinProtocol::Ipv6,
        100,
    )?;
    bind(
        builder,
        BuiltinProtocol::Mpls,
        MPLS_BOTTOM_RAW,
        BuiltinProtocol::Raw,
        -100,
    )?;
    Ok(())
}
