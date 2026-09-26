// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Linux route-netlink query construction and reply translation.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use futures_util::TryStreamExt;
use rtnetlink::{
    Handle, RouteMessageBuilder,
    packet_route::{
        address::AddressAttribute,
        link::{LinkAttribute, LinkFlags, LinkLayerType},
        route::{RouteAddress, RouteAttribute, RouteMetric, RouteNextHopFlags, RouteType},
    },
};

use crate::platform::route::os_error;
use crate::route::normalize::{NativeRouteSnapshot, finish_route};
use crate::{
    interface::{self, Id as InterfaceId},
    link::Capability,
    route::{Decision, SelectionReason, SystemError},
};
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;

pub(super) async fn query_route(
    handle: Handle,
    destination: IpAddr,
    interface_hint: Option<InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<Decision, SystemError> {
    let message = route_request(destination, interface_hint.as_ref(), preferred_source);
    let mut replies = handle.route().get(message).execute();
    let reply = match replies.try_next().await {
        Ok(reply) => reply.ok_or(SystemError::RouteNotFound { destination })?,
        Err(error) => {
            let unowned_source = unowned_preferred_source(&handle, preferred_source, &error).await;
            return Err(refine_route_lookup_error(
                destination,
                interface_hint.as_ref(),
                unowned_source,
                error,
            ));
        }
    };

    let mut output_index = None;
    let mut selected_source = None;
    let mut next_hop = None;
    let mut route_mtu = None;
    let mut multipath = None;
    for attribute in &reply.attributes {
        match attribute {
            RouteAttribute::Oif(index) => output_index = Some(*index),
            RouteAttribute::PrefSource(address) => selected_source = route_address(address),
            RouteAttribute::Gateway(address) => next_hop = route_address(address),
            RouteAttribute::Metrics(metrics) => {
                route_mtu = metrics.iter().find_map(|metric| match metric {
                    RouteMetric::Mtu(mtu) => Some(*mtu),
                    _ => None,
                });
            }
            RouteAttribute::MultiPath(next_hops) => {
                multipath = next_hops.iter().find(|next_hop| {
                    !next_hop
                        .flags
                        .intersects(RouteNextHopFlags::Dead | RouteNextHopFlags::Linkdown)
                });
            }
            _ => {}
        }
    }
    if let Some(next_hop_entry) = multipath {
        output_index.get_or_insert(next_hop_entry.interface_index);
        if next_hop.is_none() {
            next_hop = next_hop_entry.attributes.iter().find_map(|attribute| {
                if let RouteAttribute::Gateway(address) = attribute {
                    route_address(address)
                } else {
                    None
                }
            });
        }
    }
    let output_index = output_index
        .or_else(|| interface_hint.as_ref().map(|interface| interface.index))
        .ok_or_else(|| SystemError::InvalidResponse {
            message: "Linux route response omitted its output interface".to_owned(),
        })?;
    let interface = query_interface(&handle, output_index, interface_hint.as_ref()).await?;
    let selection_reason = route_selection_reason(&reply.header.kind, next_hop.is_some())
        .ok_or(SystemError::RouteNotFound { destination })?;
    let local_addresses = if needs_local_addresses(
        selection_reason,
        destination,
        preferred_source.or(selected_source),
        &interface,
    ) {
        query_local_addresses(&handle).await?
    } else {
        Vec::new()
    };
    finish_route(
        destination,
        interface_hint.as_ref(),
        preferred_source,
        NativeRouteSnapshot {
            interface,
            local_addresses,
            selected_source,
            next_hop: next_hop.filter(|address| !address.is_unspecified()),
            route_mtu,
            selection_reason,
        },
    )
}

fn netlink_errno(error: &rtnetlink::Error) -> Option<i32> {
    match error {
        rtnetlink::Error::NetlinkError(reply) => reply.raw_code().checked_abs(),
        _ => None,
    }
}

/// The kernel refuses an IPv4 lookup whose preferred source no interface owns
/// with ENETUNREACH (EINVAL for a source that can never be local), which would
/// otherwise read as a missing route. Returns that source when a local-address
/// query confirms nothing owns it.
async fn unowned_preferred_source(
    handle: &Handle,
    preferred_source: Option<IpAddr>,
    error: &rtnetlink::Error,
) -> Option<IpAddr> {
    let source = preferred_source?;
    if !matches!(netlink_errno(error), Some(libc::ENETUNREACH | libc::EINVAL)) {
        return None;
    }
    let local = query_local_addresses(handle).await.ok()?;
    (!local.contains(&source)).then_some(source)
}

/// Reports a failed lookup the way the other targets do: an unowned preferred
/// source as `SourceUnavailable` and a vanished hinted interface as
/// `InterfaceNotFound`, before the generic errno translation.
fn refine_route_lookup_error(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    unowned_source: Option<IpAddr>,
    error: rtnetlink::Error,
) -> SystemError {
    if let Some(preferred_source) = unowned_source {
        return SystemError::SourceUnavailable {
            preferred_source,
            interface: interface_hint
                .map_or_else(|| "any interface".to_owned(), |hint| hint.name.clone()),
        };
    }
    if let Some(hint) = interface_hint
        && netlink_errno(&error) == Some(libc::ENODEV)
    {
        return SystemError::InterfaceNotFound {
            name: hint.name.clone(),
            index: hint.index,
        };
    }
    route_lookup_error(destination, error)
}

/// Reports the kernel's "no route" errnos as `RouteNotFound`, so an
/// unreachable destination classifies as `io.route_not_found` on every target.
fn route_lookup_error(destination: IpAddr, error: rtnetlink::Error) -> SystemError {
    const NO_ROUTE: [i32; 4] = [
        libc::ENETUNREACH,
        libc::EHOSTUNREACH,
        libc::ENOENT,
        libc::ESRCH,
    ];
    if netlink_errno(&error).is_some_and(|errno| NO_ROUTE.contains(&errno)) {
        return SystemError::RouteNotFound { destination };
    }
    os_error("RTM_GETROUTE", error)
}

/// `finish_route` consults `local_addresses` only for a local route whose
/// source is absent from the output interface — and only after the family's
/// mismatch check — so every other decision skips collecting all local addresses.
fn needs_local_addresses(
    selection_reason: SelectionReason,
    destination: IpAddr,
    resolved_source: Option<IpAddr>,
    interface: &interface::Info,
) -> bool {
    selection_reason == SelectionReason::Local
        && resolved_source.is_some_and(|source| {
            source.is_ipv4() == destination.is_ipv4()
                && !interface
                    .addresses
                    .iter()
                    .any(|assigned| assigned.address == source)
        })
}

fn route_selection_reason(kind: &RouteType, has_next_hop: bool) -> Option<SelectionReason> {
    match kind {
        RouteType::Local => Some(SelectionReason::Local),
        RouteType::Broadcast => Some(SelectionReason::Broadcast),
        // The kernel answers a multicast destination with RTN_MULTICAST and
        // the output interface the group is sent on.
        RouteType::Unicast | RouteType::Anycast | RouteType::Multicast => Some({
            if has_next_hop {
                SelectionReason::Gateway
            } else {
                SelectionReason::OnLink
            }
        }),
        _ => None,
    }
}

pub(super) async fn query_interfaces(handle: &Handle) -> Result<Vec<interface::Info>, SystemError> {
    let mut interfaces = query_links(handle, None).await?;
    query_addresses(handle, None, &mut interfaces).await?;
    Ok(interfaces.into_values().collect())
}

/// Resolves the one interface a route landed on: a filtered link get answers
/// with a single reply. The address iterator filters the host-wide kernel dump
/// in userspace, retaining only addresses belonging to that interface.
async fn query_interface(
    handle: &Handle,
    index: u32,
    interface_hint: Option<&InterfaceId>,
) -> Result<interface::Info, SystemError> {
    let not_found = || SystemError::InterfaceNotFound {
        name: interface_hint.map_or_else(|| format!("index-{index}"), |hint| hint.name.clone()),
        index,
    };
    let mut interfaces = query_links(handle, Some(index))
        .await
        .map_err(|error| match error {
            // Attach the hinted name to the ENODEV translation.
            SystemError::InterfaceNotFound { .. } => not_found(),
            error => error,
        })?;
    query_addresses(handle, Some(index), &mut interfaces).await?;
    interfaces.remove(&index).ok_or_else(not_found)
}

async fn query_local_addresses(handle: &Handle) -> Result<Vec<IpAddr>, SystemError> {
    Ok(query_interfaces(handle)
        .await?
        .into_iter()
        .flat_map(|interface| {
            interface
                .addresses
                .into_iter()
                .map(|assigned| assigned.address)
        })
        .collect())
}

async fn query_links(
    handle: &Handle,
    index_filter: Option<u32>,
) -> Result<BTreeMap<u32, interface::Info>, SystemError> {
    let request = handle.link().get();
    let mut links = match index_filter {
        Some(index) => request.match_index(index).execute(),
        None => request.execute(),
    };
    let mut interfaces = BTreeMap::new();
    while let Some(message) = links
        .try_next()
        .await
        .map_err(|error| link_lookup_error(index_filter, error))?
    {
        let mut name = None;
        let mut description = None;
        let mut mac_address = None;
        let mut mtu = None;
        for attribute in message.attributes {
            match attribute {
                LinkAttribute::IfName(value) => name = Some(value),
                LinkAttribute::IfAlias(value) if !value.is_empty() => description = Some(value),
                LinkAttribute::Address(value) if value.len() == 6 => {
                    let mut address = [0_u8; 6];
                    address.copy_from_slice(&value);
                    mac_address = Some(MacAddress(address));
                }
                LinkAttribute::Mtu(value) => mtu = Some(value),
                _ => {}
            }
        }
        let name = name.ok_or_else(|| SystemError::InvalidResponse {
            message: format!("Linux link {} has no interface name", message.header.index),
        })?;
        let loopback = message.header.flags.contains(LinkFlags::Loopback)
            || message.header.link_layer_type == LinkLayerType::Loopback;
        let ethernet = message.header.link_layer_type == LinkLayerType::Ether;
        interfaces.insert(
            message.header.index,
            interface::Info {
                id: InterfaceId {
                    name,
                    index: message.header.index,
                },
                description,
                mac_address,
                addresses: Vec::new(),
                flags: interface::Flags {
                    up: message.header.flags.contains(LinkFlags::Up),
                    broadcast: message.header.flags.contains(LinkFlags::Broadcast),
                    loopback,
                    point_to_point: message.header.flags.contains(LinkFlags::Pointopoint),
                    multicast: message.header.flags.contains(LinkFlags::Multicast),
                },
                mtu,
                capability: if ethernet && mac_address.is_some() {
                    Capability::Layer2AndLayer3
                } else {
                    Capability::Layer3
                },
                link_type: if ethernet {
                    LinkType::ETHERNET
                } else {
                    LinkType::RAW
                },
            },
        );
    }
    Ok(interfaces)
}

/// A filtered link get reports an interface that vanished since the route
/// lookup as ENODEV, matching the full dump that would have omitted it.
fn link_lookup_error(index_filter: Option<u32>, error: rtnetlink::Error) -> SystemError {
    if let Some(index) = index_filter
        && let rtnetlink::Error::NetlinkError(reply) = &error
        && reply.raw_code().checked_abs() == Some(libc::ENODEV)
    {
        return SystemError::InterfaceNotFound {
            name: format!("index-{index}"),
            index,
        };
    }
    os_error("RTM_GETLINK", error)
}

async fn query_addresses(
    handle: &Handle,
    index_filter: Option<u32>,
    interfaces: &mut BTreeMap<u32, interface::Info>,
) -> Result<(), SystemError> {
    let request = handle.address().get();
    let mut addresses = match index_filter {
        Some(index) => request.set_link_index_filter(index).execute(),
        None => request.execute(),
    };
    while let Some(message) = addresses
        .try_next()
        .await
        .map_err(|error| os_error("RTM_GETADDR", error))?
    {
        let Some(interface) = interfaces.get_mut(&message.header.index) else {
            continue;
        };
        let address = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                AddressAttribute::Local(address) => Some(*address),
                _ => None,
            })
            .or_else(|| {
                message
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        AddressAttribute::Address(address) => Some(*address),
                        _ => None,
                    })
            });
        if let Some(address) = address {
            let assigned = interface::Address {
                address,
                prefix_length: message.header.prefix_len,
            };
            if !interface.addresses.contains(&assigned) {
                interface.addresses.push(assigned);
            }
        }
    }
    Ok(())
}

// u32::BITS and u128::BITS are 32 and 128, so each host-route prefix length fits the 8-bit field
// rtnetlink expects
fn route_request(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> rtnetlink::packet_route::route::RouteMessage {
    match destination {
        IpAddr::V4(destination) => {
            let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(destination, u32::BITS as u8);
            if let Some(interface) = interface_hint {
                builder = builder.output_interface(interface.index);
            }
            if let Some(IpAddr::V4(source)) = preferred_source {
                builder = builder.source_prefix(source, u32::BITS as u8);
            }
            builder.build()
        }
        IpAddr::V6(destination) => {
            let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(destination, u128::BITS as u8);
            if let Some(interface) = interface_hint {
                builder = builder.output_interface(interface.index);
            }
            if let Some(IpAddr::V6(source)) = preferred_source {
                builder = builder.source_prefix(source, u128::BITS as u8);
            }
            builder.build()
        }
    }
}

fn route_address(address: &RouteAddress) -> Option<IpAddr> {
    match address {
        RouteAddress::Inet(address) => Some(IpAddr::V4(*address)),
        RouteAddress::Inet6(address) => Some(IpAddr::V6(*address)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroI32;

    use rtnetlink::packet_core::ErrorMessage;

    use super::*;

    fn netlink_error(code: i32) -> rtnetlink::Error {
        let mut reply = ErrorMessage::default();
        reply.code = NonZeroI32::new(code);
        rtnetlink::Error::NetlinkError(reply)
    }

    #[test]
    fn kernel_no_route_errnos_classify_as_a_missing_route() {
        let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        for errno in [
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::ENOENT,
            libc::ESRCH,
        ] {
            assert!(matches!(
                route_lookup_error(destination, netlink_error(-errno)),
                SystemError::RouteNotFound { destination: actual } if actual == destination
            ));
        }

        assert!(matches!(
            route_lookup_error(destination, netlink_error(-libc::EPERM)),
            SystemError::OperatingSystem {
                operation: "RTM_GETROUTE",
                ..
            }
        ));
        assert!(matches!(
            route_lookup_error(destination, rtnetlink::Error::RequestFailed),
            SystemError::OperatingSystem {
                operation: "RTM_GETROUTE",
                ..
            }
        ));
    }

    #[test]
    fn a_filtered_link_get_maps_a_missing_interface_to_not_found() {
        assert!(matches!(
            link_lookup_error(Some(4), netlink_error(-libc::ENODEV)),
            SystemError::InterfaceNotFound { index: 4, .. }
        ));
        assert!(matches!(
            link_lookup_error(None, netlink_error(-libc::ENODEV)),
            SystemError::OperatingSystem {
                operation: "RTM_GETLINK",
                ..
            }
        ));
        assert!(matches!(
            link_lookup_error(Some(4), netlink_error(-libc::EPERM)),
            SystemError::OperatingSystem {
                operation: "RTM_GETLINK",
                ..
            }
        ));
    }

    #[test]
    fn local_address_dump_only_serves_an_off_interface_local_source() {
        let interface = interface::Info {
            id: InterfaceId {
                name: "fixture0".to_owned(),
                index: 7,
            },
            description: None,
            mac_address: None,
            addresses: vec![interface::Address {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                prefix_length: 24,
            }],
            flags: interface::Flags::default(),
            mtu: Some(1_500),
            capability: Capability::Layer3,
            link_type: LinkType::RAW,
        };
        let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let on_interface = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let off_interface = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

        assert!(needs_local_addresses(
            SelectionReason::Local,
            destination,
            Some(off_interface),
            &interface
        ));
        // On-interface sources resolve as `assigned_to_output` first.
        assert!(!needs_local_addresses(
            SelectionReason::Local,
            destination,
            Some(on_interface),
            &interface
        ));
        // A fallback-resolved source is always on the output interface.
        assert!(!needs_local_addresses(
            SelectionReason::Local,
            destination,
            None,
            &interface
        ));
        assert!(!needs_local_addresses(
            SelectionReason::Gateway,
            destination,
            Some(off_interface),
            &interface
        ));
        // A family mismatch fails before `local_addresses` is consulted.
        assert!(!needs_local_addresses(
            SelectionReason::Local,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            Some(off_interface),
            &interface
        ));
    }

    #[test]
    fn lookup_failures_name_an_unowned_source_or_a_vanished_hint() {
        let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
        let hint = InterfaceId {
            name: "fixture0".to_owned(),
            index: 9,
        };
        assert!(matches!(
            refine_route_lookup_error(
                destination,
                None,
                Some(source),
                netlink_error(-libc::ENETUNREACH)
            ),
            SystemError::SourceUnavailable { preferred_source, ref interface }
                if preferred_source == source && interface == "any interface"
        ));
        assert!(matches!(
            refine_route_lookup_error(
                destination,
                Some(&hint),
                Some(source),
                netlink_error(-libc::ENETUNREACH)
            ),
            SystemError::SourceUnavailable { ref interface, .. } if interface == "fixture0"
        ));
        assert!(matches!(
            refine_route_lookup_error(
                destination,
                Some(&hint),
                None,
                netlink_error(-libc::ENODEV)
            ),
            SystemError::InterfaceNotFound { ref name, index: 9 } if name == "fixture0"
        ));
        assert!(matches!(
            refine_route_lookup_error(destination, None, None, netlink_error(-libc::ENETUNREACH)),
            SystemError::RouteNotFound { .. }
        ));
    }

    #[test]
    fn linux_route_type_preserves_broadcast_before_native_normalization() {
        assert_eq!(
            route_selection_reason(&RouteType::Broadcast, false),
            Some(SelectionReason::Broadcast)
        );
        assert_eq!(
            route_selection_reason(&RouteType::Unicast, false),
            Some(SelectionReason::OnLink)
        );
        assert_eq!(
            route_selection_reason(&RouteType::Unicast, true),
            Some(SelectionReason::Gateway)
        );
        assert_eq!(
            route_selection_reason(&RouteType::Multicast, false),
            Some(SelectionReason::OnLink)
        );
        assert_eq!(route_selection_reason(&RouteType::Unreachable, false), None);
    }
}
