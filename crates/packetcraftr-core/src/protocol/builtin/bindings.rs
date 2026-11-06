// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    frame::LinkType,
    protocol::BuiltinProtocol,
    protocol::{
        link::{
            CDP_SNAP_DISCRIMINATOR, EAP_PACKET_SELECTOR, LLC_FRAME_DISCRIMINATOR,
            SNAP_DISCRIMINATOR, STP_DISCRIMINATOR, ether_type,
        },
        network::ip_protocol,
        tunnel::{
            GTPU_IP_VERSION_BASE, GTPU_OTHER_PAYLOAD, MPLS_BOTTOM_RAW, MPLS_BOTTOM_VERSION_BASE,
            MPLS_NEXT_LABEL, PPPOE_DISCOVERY, PPPOE_SESSION, ppp_protocol,
        },
    },
    registry::Priority,
};

type Child = (u64, BuiltinProtocol, Priority);
type Binding = (BuiltinProtocol, u64, BuiltinProtocol, Priority);

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
        bind_children(
            builder,
            parent,
            &[(0, BuiltinProtocol::Raw, Priority::Fallback)],
        )?;
    }
    bind_all(
        builder,
        &[
            (
                BuiltinProtocol::Http,
                0,
                BuiltinProtocol::Raw,
                Priority::Fallback,
            ),
            (
                BuiltinProtocol::Dns,
                0,
                BuiltinProtocol::Raw,
                Priority::Fallback,
            ),
            (
                BuiltinProtocol::Tls,
                0,
                BuiltinProtocol::Raw,
                Priority::Fallback,
            ),
            (
                BuiltinProtocol::Arp,
                0,
                BuiltinProtocol::Padding,
                Priority::Fallback,
            ),
            (
                BuiltinProtocol::Eapol,
                0,
                BuiltinProtocol::Raw,
                Priority::Fallback,
            ),
            (
                BuiltinProtocol::Eapol,
                EAP_PACKET_SELECTOR,
                BuiltinProtocol::Eap,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Ah,
                256 + u64::from(ip_protocol::OSPF),
                BuiltinProtocol::Ospfv3,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Snap,
                CDP_SNAP_DISCRIMINATOR,
                BuiltinProtocol::Cdp,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Ppp,
                u64::from(ppp_protocol::LCP),
                BuiltinProtocol::PppLcp,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Ppp,
                u64::from(ppp_protocol::IPCP),
                BuiltinProtocol::PppIpcp,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Ppp,
                u64::from(ppp_protocol::IPV6CP),
                BuiltinProtocol::PppIpv6cp,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Ppp,
                u64::from(ppp_protocol::EAP),
                BuiltinProtocol::Eap,
                Priority::Primary,
            ),
        ],
    )?;
    register_messages(builder)?;
    register_ports(builder)?;
    super::filter_fields::register_filter_fields(builder)
}

fn register_link(builder: &mut crate::registry::Builder) -> Result<(), crate::registry::Error> {
    for &(link_type, protocol) in LinkType::BUILTIN_ROOTS {
        builder.bind_link_type(link_type, protocol.as_str())?;
    }
    for protocol in [
        BuiltinProtocol::Ethernet,
        BuiltinProtocol::Vlan,
        BuiltinProtocol::Vlan8021ad,
        BuiltinProtocol::BsdNull,
        BuiltinProtocol::BsdLoop,
        BuiltinProtocol::LinuxSll,
        BuiltinProtocol::LinuxSll2,
    ] {
        builder.allow_trailing_padding(protocol.as_str());
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
            &[(
                LLC_FRAME_DISCRIMINATOR,
                BuiltinProtocol::Llc,
                Priority::Primary,
            )],
        )?;
    }
    bind_children(
        builder,
        BuiltinProtocol::Llc,
        &[
            (SNAP_DISCRIMINATOR, BuiltinProtocol::Snap, Priority::Primary),
            (STP_DISCRIMINATOR, BuiltinProtocol::Stp, Priority::Primary),
            (0, BuiltinProtocol::Raw, Priority::Fallback),
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
                (4, BuiltinProtocol::Ipv4, Priority::Primary),
                (6, BuiltinProtocol::Ipv6, Priority::Primary),
                (0, BuiltinProtocol::Raw, Priority::Fallback),
            ],
        )?;
    }
    Ok(())
}

fn register_ip(builder: &mut crate::registry::Builder) -> Result<(), crate::registry::Error> {
    bind_ip_children(
        builder,
        BuiltinProtocol::Ipv4,
        u64::from(ip_protocol::ICMPV4),
    )?;
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
    bind_ip_children(builder, BuiltinProtocol::Ah, u64::from(ip_protocol::ICMPV4))?;
    bind_children(
        builder,
        BuiltinProtocol::Ah,
        &[
            (
                u64::from(ip_protocol::ICMPV6),
                BuiltinProtocol::Icmpv6,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::NO_NEXT_HEADER),
                BuiltinProtocol::Malformed,
                Priority::Primary,
            ),
        ],
    )?;
    bind_ipv6_extensions(builder, BuiltinProtocol::Ah)
}

fn register_tunnels(builder: &mut crate::registry::Builder) -> Result<(), crate::registry::Error> {
    bind_all(
        builder,
        &[
            (
                BuiltinProtocol::Esp,
                0,
                BuiltinProtocol::Raw,
                Priority::Fallback,
            ),
            (
                BuiltinProtocol::L2tpv3,
                0,
                BuiltinProtocol::Raw,
                Priority::Fallback,
            ),
        ],
    )?;
    bind_link_children(builder, BuiltinProtocol::Gre)?;
    bind_all(
        builder,
        &[
            (
                BuiltinProtocol::Gre,
                u64::from(ether_type::TRANSPARENT_ETHERNET_BRIDGING),
                BuiltinProtocol::Ethernet,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Gre,
                u64::from(ether_type::ERSPAN_TYPE_II),
                BuiltinProtocol::Erspan,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Gre,
                u64::from(ether_type::ERSPAN_TYPE_III),
                BuiltinProtocol::Erspan,
                Priority::Secondary,
            ),
            (
                BuiltinProtocol::Erspan,
                0,
                BuiltinProtocol::Ethernet,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Udp,
                4789,
                BuiltinProtocol::Vxlan,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Vxlan,
                0,
                BuiltinProtocol::Ethernet,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Etherip,
                0,
                BuiltinProtocol::Ethernet,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Udp,
                2152,
                BuiltinProtocol::Gtpu,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Gtpu,
                GTPU_IP_VERSION_BASE + 4,
                BuiltinProtocol::Ipv4,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Gtpu,
                GTPU_IP_VERSION_BASE + 6,
                BuiltinProtocol::Ipv6,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Gtpu,
                GTPU_OTHER_PAYLOAD,
                BuiltinProtocol::Raw,
                Priority::Fallback,
            ),
            (
                BuiltinProtocol::Udp,
                6635,
                BuiltinProtocol::Mpls,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Udp,
                6081,
                BuiltinProtocol::Geneve,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Geneve,
                u64::from(ether_type::TRANSPARENT_ETHERNET_BRIDGING),
                BuiltinProtocol::Ethernet,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Geneve,
                u64::from(ether_type::IPV4),
                BuiltinProtocol::Ipv4,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Geneve,
                u64::from(ether_type::IPV6),
                BuiltinProtocol::Ipv6,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Geneve,
                0,
                BuiltinProtocol::Raw,
                Priority::Fallback,
            ),
            (
                BuiltinProtocol::Pppoe,
                PPPOE_SESSION,
                BuiltinProtocol::Ppp,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Pppoe,
                PPPOE_DISCOVERY,
                BuiltinProtocol::Raw,
                Priority::Fallback,
            ),
            (
                BuiltinProtocol::Ppp,
                u64::from(ppp_protocol::IPV4),
                BuiltinProtocol::Ipv4,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Ppp,
                u64::from(ppp_protocol::IPV6),
                BuiltinProtocol::Ipv6,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Ppp,
                0,
                BuiltinProtocol::Raw,
                Priority::Fallback,
            ),
            (
                BuiltinProtocol::Mpls,
                MPLS_NEXT_LABEL,
                BuiltinProtocol::Mpls,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Mpls,
                MPLS_BOTTOM_VERSION_BASE + 4,
                BuiltinProtocol::Ipv4,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Mpls,
                MPLS_BOTTOM_VERSION_BASE + 6,
                BuiltinProtocol::Ipv6,
                Priority::Primary,
            ),
            (
                BuiltinProtocol::Mpls,
                MPLS_BOTTOM_RAW,
                BuiltinProtocol::Raw,
                Priority::Fallback,
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
            (
                u64::from(ip_protocol::IPV4),
                BuiltinProtocol::Ipv4,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::TCP),
                BuiltinProtocol::Tcp,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::UDP),
                BuiltinProtocol::Udp,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::IPV6),
                BuiltinProtocol::Ipv6,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::GRE),
                BuiltinProtocol::Gre,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::ESP),
                BuiltinProtocol::Esp,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::AH),
                BuiltinProtocol::Ah,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::ETHERIP),
                BuiltinProtocol::Etherip,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::VRRP),
                BuiltinProtocol::Vrrp,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::PIM),
                BuiltinProtocol::Pim,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::L2TPV3),
                BuiltinProtocol::L2tpv3,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::SCTP),
                BuiltinProtocol::Sctp,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::MPLS_IN_IP),
                BuiltinProtocol::Mpls,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::ETHERNET),
                BuiltinProtocol::Ethernet,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::RESERVED),
                BuiltinProtocol::Raw,
                Priority::Fallback,
            ),
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
            (
                u64::from(ip_protocol::ICMPV6),
                BuiltinProtocol::Icmpv6,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::OSPF),
                BuiltinProtocol::Ospfv3,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::NO_NEXT_HEADER),
                BuiltinProtocol::Malformed,
                Priority::Primary,
            ),
        ],
    )
}

fn bind_ipv6_extensions(
    builder: &mut crate::registry::Builder,
    parent: BuiltinProtocol,
) -> Result<(), crate::registry::Error> {
    if parent == BuiltinProtocol::Ipv6 {
        bind_children(
            builder,
            parent,
            &[(
                u64::from(ip_protocol::HOP_BY_HOP),
                BuiltinProtocol::Ipv6HopByHop,
                Priority::Primary,
            )],
        )?;
    }
    bind_children(
        builder,
        parent,
        &[
            (
                u64::from(ip_protocol::ROUTING),
                BuiltinProtocol::Ipv6Srh,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::FRAGMENT),
                BuiltinProtocol::Ipv6Fragment,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::DESTINATION_OPTIONS),
                BuiltinProtocol::Ipv6DestinationOptions,
                Priority::Primary,
            ),
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
            (
                u64::from(ether_type::IPV4),
                BuiltinProtocol::Ipv4,
                Priority::Primary,
            ),
            (
                u64::from(ether_type::ARP),
                BuiltinProtocol::Arp,
                Priority::Primary,
            ),
            (
                u64::from(ether_type::VLAN),
                BuiltinProtocol::Vlan,
                Priority::Primary,
            ),
            (
                u64::from(ether_type::MPLS_UNICAST),
                BuiltinProtocol::Mpls,
                Priority::Primary,
            ),
            (
                u64::from(ether_type::MPLS_MULTICAST),
                BuiltinProtocol::Mpls,
                Priority::Secondary,
            ),
            (
                u64::from(ether_type::PPPOE_SESSION_STAGE),
                BuiltinProtocol::Pppoe,
                Priority::Primary,
            ),
            (
                u64::from(ether_type::PPPOE_DISCOVERY_STAGE),
                BuiltinProtocol::Pppoe,
                Priority::Secondary,
            ),
            (
                u64::from(ether_type::EAPOL),
                BuiltinProtocol::Eapol,
                Priority::Primary,
            ),
            (
                u64::from(ether_type::VLAN_8021AD),
                BuiltinProtocol::Vlan8021ad,
                Priority::Primary,
            ),
            (
                u64::from(ether_type::LLDP),
                BuiltinProtocol::Lldp,
                Priority::Primary,
            ),
            (
                u64::from(ether_type::SLOW_PROTOCOLS),
                BuiltinProtocol::Lacp,
                Priority::Primary,
            ),
            (
                u64::from(ether_type::IPV6),
                BuiltinProtocol::Ipv6,
                Priority::Primary,
            ),
            (0, BuiltinProtocol::Raw, Priority::Fallback),
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
            (icmp_number, BuiltinProtocol::Icmpv4, Priority::Primary),
            (
                u64::from(ip_protocol::IGMP),
                BuiltinProtocol::Igmp,
                Priority::Primary,
            ),
            (
                u64::from(ip_protocol::OSPF),
                BuiltinProtocol::Ospfv2,
                Priority::Primary,
            ),
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

fn register_messages(builder: &mut crate::registry::Builder) -> Result<(), crate::registry::Error> {
    for protocol in BuiltinProtocol::ALL {
        if protocol.is_message_protocol() {
            builder.bind(
                protocol.as_str(),
                0,
                if protocol.stream_decode() {
                    protocol.as_str()
                } else {
                    BuiltinProtocol::Raw.as_str()
                },
                Priority::Primary,
            )?;
            if protocol.stream_decode() {
                // Zero continues typed frames; one permits a preserved opaque build tail.
                builder.bind(
                    protocol.as_str(),
                    crate::protocol::message::OPAQUE_TAIL,
                    BuiltinProtocol::Raw.as_str(),
                    Priority::Primary,
                )?;
            }
        }
    }
    Ok(())
}

fn register_ports(builder: &mut crate::registry::Builder) -> Result<(), crate::registry::Error> {
    for protocol in BuiltinProtocol::ALL {
        for (parent, ports) in [
            (BuiltinProtocol::Tcp, protocol.tcp_ports()),
            (BuiltinProtocol::Udp, protocol.udp_ports()),
        ] {
            for &port in ports {
                builder.bind(
                    parent.as_str(),
                    u64::from(port),
                    protocol.as_str(),
                    Priority::Primary,
                )?;
            }
        }
    }
    Ok(())
}
