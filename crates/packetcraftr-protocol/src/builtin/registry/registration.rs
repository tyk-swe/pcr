// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Ordered built-in binding registration.

use packetcraftr_packet::{
    registry::{RegistryBuilder, RegistryError},
    semantics::BuiltinProtocol,
};

mod application;
mod filter;
mod ip_extension;
mod link;
mod terminal;
mod transport;
mod tunnel;

pub(super) fn register(builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
    link::register(builder)?;
    ip_extension::register(builder)?;
    tunnel::register(builder)?;
    transport::register(builder)?;
    application::register(builder)?;
    terminal::register(builder)?;
    filter::register(builder)
}

fn bind_common_ip_children(
    builder: &mut RegistryBuilder,
    parent: BuiltinProtocol,
) -> Result<(), RegistryError> {
    bind(builder, parent, 4, BuiltinProtocol::Ipv4, 100)?;
    bind(builder, parent, 6, BuiltinProtocol::Tcp, 100)?;
    bind(builder, parent, 17, BuiltinProtocol::Udp, 100)?;
    bind(builder, parent, 41, BuiltinProtocol::Ipv6, 100)?;
    bind(builder, parent, 47, BuiltinProtocol::Gre, 100)?;
    bind(builder, parent, 50, BuiltinProtocol::Esp, 100)?;
    bind(builder, parent, 51, BuiltinProtocol::Ah, 100)?;
    bind(builder, parent, 115, BuiltinProtocol::L2tpv3, 100)?;
    bind(builder, parent, 132, BuiltinProtocol::Sctp, 100)?;
    bind(builder, parent, 255, BuiltinProtocol::Raw, -100)?;
    Ok(())
}

fn bind_ipv6_children(
    builder: &mut RegistryBuilder,
    parent: BuiltinProtocol,
) -> Result<(), RegistryError> {
    bind_common_ip_children(builder, parent)?;
    bind(builder, parent, 58, BuiltinProtocol::Icmpv6, 100)?;
    bind(builder, parent, 59, BuiltinProtocol::Malformed, 100)?;
    Ok(())
}

fn bind_ipv6_extensions(
    builder: &mut RegistryBuilder,
    parent: BuiltinProtocol,
) -> Result<(), RegistryError> {
    if parent == BuiltinProtocol::Ipv6 {
        bind(builder, parent, 0, BuiltinProtocol::Ipv6HopByHop, 100)?;
    }
    bind(builder, parent, 43, BuiltinProtocol::Ipv6Srh, 100)?;
    bind(builder, parent, 44, BuiltinProtocol::Ipv6Fragment, 100)?;
    bind(
        builder,
        parent,
        60,
        BuiltinProtocol::Ipv6DestinationOptions,
        100,
    )?;
    Ok(())
}

fn bind_link_children(
    builder: &mut RegistryBuilder,
    parent: BuiltinProtocol,
) -> Result<(), RegistryError> {
    bind(builder, parent, 0x0800, BuiltinProtocol::Ipv4, 100)?;
    bind(builder, parent, 0x0806, BuiltinProtocol::Arp, 100)?;
    bind(builder, parent, 0x8100, BuiltinProtocol::Vlan, 100)?;
    bind(builder, parent, 0x8847, BuiltinProtocol::Mpls, 100)?;
    bind(builder, parent, 0x8848, BuiltinProtocol::Mpls, 90)?;
    bind(builder, parent, 0x8864, BuiltinProtocol::Pppoe, 100)?;
    bind(builder, parent, 0x8863, BuiltinProtocol::Pppoe, 90)?;
    bind(builder, parent, 0x88a8, BuiltinProtocol::Vlan8021ad, 100)?;
    bind(builder, parent, 0x86dd, BuiltinProtocol::Ipv6, 100)?;
    bind(builder, parent, 0, BuiltinProtocol::Raw, -100)?;
    Ok(())
}

fn bind_ip_children(
    builder: &mut RegistryBuilder,
    parent: BuiltinProtocol,
    icmp_number: u64,
) -> Result<(), RegistryError> {
    bind_common_ip_children(builder, parent)?;
    bind(builder, parent, icmp_number, BuiltinProtocol::Icmpv4, 100)?;
    bind(builder, parent, 2, BuiltinProtocol::Igmp, 100)?;
    Ok(())
}

fn bind(
    builder: &mut RegistryBuilder,
    parent: BuiltinProtocol,
    discriminator: u64,
    child: BuiltinProtocol,
    priority: i32,
) -> Result<(), RegistryError> {
    builder
        .bind(parent.as_str(), discriminator, child.as_str(), priority)
        .map(|_| ())
}
