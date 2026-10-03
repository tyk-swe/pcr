// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::TryStreamExt;
use rtnetlink::{
    Handle, RouteMessageBuilder,
    packet_route::route::{
        RouteAddress, RouteAttribute, RouteMetric, RouteNextHopFlags, RouteType,
    },
};

use crate::platform::common::os_error;
use crate::platform::interface::netlink::{query_interface, query_local_addresses};
use crate::route::normalize::{NativeRouteSnapshot, finish_route};
use crate::{
    interface::{self, Id as InterfaceId},
    route::{self, Decision, SelectionReason},
};

pub(in crate::platform) async fn query_route(
    handle: Handle,
    destination: IpAddr,
    interface_hint: Option<InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<Decision, route::Error> {
    let message = route_request(destination, interface_hint.as_ref(), preferred_source);
    let mut replies = handle.route().get(message).execute();
    let reply = match replies.try_next().await {
        Ok(reply) => reply.ok_or(route::Error::RouteNotFound { destination })?,
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
        .ok_or_else(|| route::Error::InvalidResponse {
            message: "Linux route response omitted its output interface".to_owned(),
        })?;
    let interface = query_interface(&handle, output_index, interface_hint.as_ref()).await?;
    let selection_reason = route_selection_reason(&reply.header.kind, next_hop.is_some())
        .ok_or(route::Error::RouteNotFound { destination })?;
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

/// The kernel refuses an IPv4 lookup whose preferred source no interface owns with ENETUNREACH.
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

fn refine_route_lookup_error(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    unowned_source: Option<IpAddr>,
    error: rtnetlink::Error,
) -> route::Error {
    if let Some(preferred_source) = unowned_source {
        return route::Error::SourceUnavailable {
            preferred_source,
            interface: interface_hint
                .map_or_else(|| "any interface".to_owned(), |hint| hint.name.clone()),
        };
    }
    if let Some(hint) = interface_hint
        && netlink_errno(&error) == Some(libc::ENODEV)
    {
        return route::Error::InterfaceNotFound {
            name: hint.name.clone(),
            index: hint.index,
        };
    }
    route_lookup_error(destination, error)
}

fn route_lookup_error(destination: IpAddr, error: rtnetlink::Error) -> route::Error {
    const NO_ROUTE: [i32; 4] = [
        libc::ENETUNREACH,
        libc::EHOSTUNREACH,
        libc::ENOENT,
        libc::ESRCH,
    ];
    if netlink_errno(&error).is_some_and(|errno| NO_ROUTE.contains(&errno)) {
        return route::Error::RouteNotFound { destination };
    }
    os_error("RTM_GETROUTE", error)
}

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

    use super::*;

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
