// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Ordered built-in binding registration.

use crate::{
    protocol::{
        link::LLC_FRAME_DISCRIMINATOR,
        support::BUILTIN_CAPTURE_ROOTS,
        tunnel::{
            MPLS_BOTTOM_RAW, MPLS_BOTTOM_VERSION_BASE, MPLS_NEXT_LABEL, PPPOE_DISCOVERY,
            PPPOE_SESSION,
        },
    },
    semantics::BuiltinProtocol,
};

type Child = (u64, BuiltinProtocol, i32);
type Binding = (BuiltinProtocol, u64, BuiltinProtocol, i32);

pub(super) fn register(
    builder: &mut crate::registry::Builder,
) -> Result<(), crate::registry::Error> {
    register_link(builder)?;
    register_ip(builder)?;
    register_tunnels(builder)?;
    for parent in [
        BuiltinProtocol::Udp,
        BuiltinProtocol::Tcp,
        BuiltinProtocol::Sctp,
    ] {
        bind_children(builder, parent, &[(0, BuiltinProtocol::Raw, 0)])?;
    }
    bind_all(
        builder,
        &[
            (BuiltinProtocol::Udp, 53, BuiltinProtocol::Dns, 100),
            (BuiltinProtocol::Arp, 0, BuiltinProtocol::Padding, 0),
        ],
    )?;
    crate::protocol::builtin::filter::register_filter_fields(builder)
}

fn register_link(builder: &mut crate::registry::Builder) -> Result<(), crate::registry::Error> {
    for root in BUILTIN_CAPTURE_ROOTS {
        builder.bind_link_type(root.link_type, root.protocol)?;
    }
    for parent in [
        BuiltinProtocol::Ethernet,
        BuiltinProtocol::Vlan,
        BuiltinProtocol::Vlan8021ad,
    ] {
        bind_link_children(builder, parent)?;
    }
    for parent in [
        BuiltinProtocol::Ethernet,
        BuiltinProtocol::Vlan,
        BuiltinProtocol::Vlan8021ad,
    ] {
        bind_children(
            builder,
            parent,
            &[(LLC_FRAME_DISCRIMINATOR, BuiltinProtocol::Llc, 100)],
        )?;
    }
    bind_children(
        builder,
        BuiltinProtocol::Llc,
        &[
            (0xaaaa, BuiltinProtocol::Snap, 100),
            (0, BuiltinProtocol::Raw, -100),
        ],
    )?;
    bind_link_children(builder, BuiltinProtocol::Snap)?;
    for parent in [BuiltinProtocol::LinuxSll, BuiltinProtocol::LinuxSll2] {
        bind_link_children(builder, parent)?;
    }
    for parent in [BuiltinProtocol::BsdNull, BuiltinProtocol::BsdLoop] {
        bind_children(
            builder,
            parent,
            &[
                (4, BuiltinProtocol::Ipv4, 100),
                (6, BuiltinProtocol::Ipv6, 100),
                (0, BuiltinProtocol::Raw, -100),
            ],
        )?;
    }
    Ok(())
}

fn register_ip(builder: &mut crate::registry::Builder) -> Result<(), crate::registry::Error> {
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
    bind_children(
        builder,
        BuiltinProtocol::RawIp,
        &[(58, BuiltinProtocol::Icmpv6, 100)],
    )?;
    bind_ip_children(builder, BuiltinProtocol::Ah, 1)?;
    bind_children(
        builder,
        BuiltinProtocol::Ah,
        &[
            (58, BuiltinProtocol::Icmpv6, 100),
            (59, BuiltinProtocol::Malformed, 100),
        ],
    )?;
    bind_ipv6_extensions(builder, BuiltinProtocol::Ah)
}

fn register_tunnels(builder: &mut crate::registry::Builder) -> Result<(), crate::registry::Error> {
    bind_all(
        builder,
        &[
            (BuiltinProtocol::Esp, 0, BuiltinProtocol::Raw, 0),
            (BuiltinProtocol::L2tpv3, 0, BuiltinProtocol::Raw, 0),
        ],
    )?;
    bind_link_children(builder, BuiltinProtocol::Gre)?;
    bind_all(
        builder,
        &[
            (BuiltinProtocol::Gre, 0x6558, BuiltinProtocol::Ethernet, 100),
            (BuiltinProtocol::Gre, 0x88be, BuiltinProtocol::Erspan, 100),
            (BuiltinProtocol::Gre, 0x22eb, BuiltinProtocol::Erspan, 90),
            (BuiltinProtocol::Erspan, 0, BuiltinProtocol::Ethernet, 100),
            (BuiltinProtocol::Udp, 4789, BuiltinProtocol::Vxlan, 100),
            (BuiltinProtocol::Vxlan, 0, BuiltinProtocol::Ethernet, 100),
            (BuiltinProtocol::Udp, 6081, BuiltinProtocol::Geneve, 100),
            (
                BuiltinProtocol::Geneve,
                0x6558,
                BuiltinProtocol::Ethernet,
                100,
            ),
            (BuiltinProtocol::Geneve, 0x0800, BuiltinProtocol::Ipv4, 100),
            (BuiltinProtocol::Geneve, 0x86dd, BuiltinProtocol::Ipv6, 100),
            (BuiltinProtocol::Geneve, 0, BuiltinProtocol::Raw, -100),
            (
                BuiltinProtocol::Pppoe,
                PPPOE_SESSION,
                BuiltinProtocol::Ppp,
                100,
            ),
            (
                BuiltinProtocol::Pppoe,
                PPPOE_DISCOVERY,
                BuiltinProtocol::Raw,
                0,
            ),
            (BuiltinProtocol::Ppp, 0x0021, BuiltinProtocol::Ipv4, 100),
            (BuiltinProtocol::Ppp, 0x0057, BuiltinProtocol::Ipv6, 100),
            (BuiltinProtocol::Ppp, 0, BuiltinProtocol::Raw, -100),
            (
                BuiltinProtocol::Mpls,
                MPLS_NEXT_LABEL,
                BuiltinProtocol::Mpls,
                100,
            ),
            (
                BuiltinProtocol::Mpls,
                MPLS_BOTTOM_VERSION_BASE + 4,
                BuiltinProtocol::Ipv4,
                100,
            ),
            (
                BuiltinProtocol::Mpls,
                MPLS_BOTTOM_VERSION_BASE + 6,
                BuiltinProtocol::Ipv6,
                100,
            ),
            (
                BuiltinProtocol::Mpls,
                MPLS_BOTTOM_RAW,
                BuiltinProtocol::Raw,
                -100,
            ),
        ],
    )
}

fn bind_common_ip_children(
    builder: &mut crate::registry::Builder,
    parent: BuiltinProtocol,
) -> Result<(), crate::registry::Error> {
    bind_children(
        builder,
        parent,
        &[
            (4, BuiltinProtocol::Ipv4, 100),
            (6, BuiltinProtocol::Tcp, 100),
            (17, BuiltinProtocol::Udp, 100),
            (41, BuiltinProtocol::Ipv6, 100),
            (47, BuiltinProtocol::Gre, 100),
            (50, BuiltinProtocol::Esp, 100),
            (51, BuiltinProtocol::Ah, 100),
            (115, BuiltinProtocol::L2tpv3, 100),
            (132, BuiltinProtocol::Sctp, 100),
            (255, BuiltinProtocol::Raw, -100),
        ],
    )
}

fn bind_ipv6_children(
    builder: &mut crate::registry::Builder,
    parent: BuiltinProtocol,
) -> Result<(), crate::registry::Error> {
    bind_common_ip_children(builder, parent)?;
    bind_children(
        builder,
        parent,
        &[
            (58, BuiltinProtocol::Icmpv6, 100),
            (59, BuiltinProtocol::Malformed, 100),
        ],
    )
}

fn bind_ipv6_extensions(
    builder: &mut crate::registry::Builder,
    parent: BuiltinProtocol,
) -> Result<(), crate::registry::Error> {
    if parent == BuiltinProtocol::Ipv6 {
        bind_children(builder, parent, &[(0, BuiltinProtocol::Ipv6HopByHop, 100)])?;
    }
    bind_children(
        builder,
        parent,
        &[
            (43, BuiltinProtocol::Ipv6Srh, 100),
            (44, BuiltinProtocol::Ipv6Fragment, 100),
            (60, BuiltinProtocol::Ipv6DestinationOptions, 100),
        ],
    )
}

fn bind_link_children(
    builder: &mut crate::registry::Builder,
    parent: BuiltinProtocol,
) -> Result<(), crate::registry::Error> {
    bind_children(
        builder,
        parent,
        &[
            (0x0800, BuiltinProtocol::Ipv4, 100),
            (0x0806, BuiltinProtocol::Arp, 100),
            (0x8100, BuiltinProtocol::Vlan, 100),
            (0x8847, BuiltinProtocol::Mpls, 100),
            (0x8848, BuiltinProtocol::Mpls, 90),
            (0x8864, BuiltinProtocol::Pppoe, 100),
            (0x8863, BuiltinProtocol::Pppoe, 90),
            (0x88a8, BuiltinProtocol::Vlan8021ad, 100),
            (0x86dd, BuiltinProtocol::Ipv6, 100),
            (0, BuiltinProtocol::Raw, -100),
        ],
    )
}

fn bind_ip_children(
    builder: &mut crate::registry::Builder,
    parent: BuiltinProtocol,
    icmp_number: u64,
) -> Result<(), crate::registry::Error> {
    bind_common_ip_children(builder, parent)?;
    bind_children(
        builder,
        parent,
        &[
            (icmp_number, BuiltinProtocol::Icmpv4, 100),
            (2, BuiltinProtocol::Igmp, 100),
        ],
    )
}

fn bind_children(
    builder: &mut crate::registry::Builder,
    parent: BuiltinProtocol,
    children: &[Child],
) -> Result<(), crate::registry::Error> {
    for &(discriminator, child, priority) in children {
        builder.bind(parent.as_str(), discriminator, child.as_str(), priority)?;
    }
    Ok(())
}

fn bind_all(
    builder: &mut crate::registry::Builder,
    bindings: &[Binding],
) -> Result<(), crate::registry::Error> {
    for &(parent, discriminator, child, priority) in bindings {
        builder.bind(parent.as_str(), discriminator, child.as_str(), priority)?;
    }
    Ok(())
}
