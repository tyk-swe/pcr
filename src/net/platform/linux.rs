// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Linux route and interface adapter backed by route netlink.

#[cfg(feature = "native-route")]
use std::collections::BTreeMap;
#[cfg(feature = "native-route")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(feature = "native-route")]
use futures_util::TryStreamExt;
#[cfg(feature = "native-route")]
use rtnetlink::packet_route::{
    address::AddressAttribute,
    link::{LinkAttribute, LinkFlags, LinkLayerType},
    route::{RouteAddress, RouteAttribute, RouteMetric, RouteNextHopFlags, RouteType},
};
#[cfg(feature = "native-route")]
use rtnetlink::{Handle, RouteMessageBuilder, new_connection};

#[cfg(feature = "native-route")]
use super::{
    NativeRouteSnapshot, find_interface, finish_route, interface_decision,
    validate_preferred_source_family,
};
#[cfg(feature = "native-route")]
use crate::capture::LinkType;
#[cfg(feature = "native-route")]
use crate::net::{
    InterfaceAddress, InterfaceFlags, InterfaceId, InterfaceInfo, LinkCapability, MacAddress,
    NativeRouteError, RouteDecision, RouteSelectionReason,
};

#[cfg(feature = "native-route")]
pub(super) fn interfaces() -> Result<Vec<InterfaceInfo>, NativeRouteError> {
    with_netlink(|handle| async move { query_interfaces(&handle).await })
}

#[cfg(feature = "native-route")]
pub(super) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    validate_preferred_source_family(destination, preferred_source)?;
    let interface_hint = interface_hint.cloned();
    with_netlink(move |handle| async move {
        let message = route_request(destination, interface_hint.as_ref(), preferred_source);
        let mut replies = handle.route().get(message).execute();
        let reply = replies
            .try_next()
            .await
            .map_err(|error| os_error("RTM_GETROUTE", error))?
            .ok_or(NativeRouteError::RouteNotFound { destination })?;

        let mut output_index = None;
        let mut selected_address = None;
        let mut next_hop = None;
        let mut route_mtu = None;
        let mut multipath = None;
        for attribute in &reply.attributes {
            match attribute {
                RouteAttribute::Oif(index) => output_index = Some(*index),
                RouteAttribute::PrefSource(address) => selected_address = route_address(address),
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
            .ok_or_else(|| NativeRouteError::InvalidResponse {
                message: "Linux route response omitted its output interface".to_owned(),
            })?;
        let interfaces = query_interfaces(&handle).await?;
        let interface = interfaces
            .into_iter()
            .find(|interface| interface.id.index == output_index)
            .ok_or_else(|| NativeRouteError::InterfaceNotFound {
                name: interface_hint
                    .as_ref()
                    .map_or_else(|| format!("index-{output_index}"), |hint| hint.name.clone()),
                index: output_index,
            })?;
        let selection_reason = match reply.header.kind {
            RouteType::Local => RouteSelectionReason::Local,
            RouteType::Unicast | RouteType::Broadcast | RouteType::Anycast => {
                if next_hop.is_some() {
                    RouteSelectionReason::Gateway
                } else {
                    RouteSelectionReason::OnLink
                }
            }
            _ => return Err(NativeRouteError::RouteNotFound { destination }),
        };
        finish_route(
            destination,
            interface_hint.as_ref(),
            preferred_source,
            NativeRouteSnapshot {
                interface,
                selected_address,
                next_hop: next_hop.filter(|address| !address.is_unspecified()),
                route_mtu,
                selection_reason,
            },
        )
    })
}

#[cfg(feature = "native-route")]
pub(super) fn interface_route(requested: &InterfaceId) -> Result<RouteDecision, NativeRouteError> {
    interface_decision(find_interface(interfaces()?, requested)?)
}

#[cfg(feature = "native-route")]
fn with_netlink<F, Fut, T>(operation: F) -> Result<T, NativeRouteError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, NativeRouteError>> + Send + 'static,
    T: Send + 'static,
{
    // The public route API is synchronous. Run its private async netlink
    // machinery on a dedicated thread so callers already inside any Tokio
    // runtime never nest Runtime::block_on on that runtime's worker.
    std::thread::Builder::new()
        .name("packetcraftr-netlink".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .map_err(|error| os_error("create Tokio netlink runtime", error))?;
            runtime.block_on(async move {
                let (connection, handle, _) = new_connection()
                    .map_err(|error| os_error("open route netlink socket", error))?;
                let connection = tokio::spawn(connection);
                let result = operation(handle).await;
                connection.abort();
                result
            })
        })
        .map_err(|error| os_error("spawn netlink worker", error))?
        .join()
        .map_err(|_| NativeRouteError::InvalidResponse {
            message: "Linux netlink worker panicked".to_owned(),
        })?
}

#[cfg(feature = "native-route")]
async fn query_interfaces(handle: &Handle) -> Result<Vec<InterfaceInfo>, NativeRouteError> {
    let mut links = handle.link().get().execute();
    let mut interfaces = BTreeMap::new();
    while let Some(message) = links
        .try_next()
        .await
        .map_err(|error| os_error("RTM_GETLINK", error))?
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
        let name = name.ok_or_else(|| NativeRouteError::InvalidResponse {
            message: format!("Linux link {} has no interface name", message.header.index),
        })?;
        let loopback = message.header.flags.contains(LinkFlags::Loopback)
            || message.header.link_layer_type == LinkLayerType::Loopback;
        let ethernet = message.header.link_layer_type == LinkLayerType::Ether;
        interfaces.insert(
            message.header.index,
            InterfaceInfo {
                id: InterfaceId {
                    name,
                    index: message.header.index,
                },
                description,
                mac_address,
                addresses: Vec::new(),
                flags: InterfaceFlags {
                    up: message.header.flags.contains(LinkFlags::Up),
                    broadcast: message.header.flags.contains(LinkFlags::Broadcast),
                    loopback,
                    point_to_point: message.header.flags.contains(LinkFlags::Pointopoint),
                    multicast: message.header.flags.contains(LinkFlags::Multicast),
                },
                mtu,
                capability: if ethernet && mac_address.is_some() {
                    LinkCapability::Layer2And3
                } else {
                    LinkCapability::Layer3
                },
                link_type: if ethernet {
                    LinkType::ETHERNET
                } else {
                    LinkType::RAW
                },
            },
        );
    }

    let mut addresses = handle.address().get().execute();
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
            let assigned = InterfaceAddress {
                address,
                prefix_length: message.header.prefix_len,
            };
            if !interface.addresses.contains(&assigned) {
                interface.addresses.push(assigned);
            }
        }
    }
    Ok(interfaces.into_values().collect())
}

#[cfg(feature = "native-route")]
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

#[cfg(feature = "native-route")]
fn route_address(address: &RouteAddress) -> Option<IpAddr> {
    match address {
        RouteAddress::Inet(address) => Some(IpAddr::V4(*address)),
        RouteAddress::Inet6(address) => Some(IpAddr::V6(*address)),
        _ => None,
    }
}

#[cfg(feature = "native-route")]
fn os_error(operation: &'static str, error: impl std::fmt::Display) -> NativeRouteError {
    NativeRouteError::OperatingSystem {
        operation,
        message: error.to_string(),
    }
}

#[cfg(all(test, feature = "native-route"))]
mod tests {
    use super::*;
    use crate::net::RouteProvider;

    #[test]
    fn native_linux_provider_finds_loopback_routes_and_interfaces() {
        let interfaces = interfaces().unwrap();
        assert!(interfaces.iter().any(|interface| interface.flags.loopback));

        let provider = crate::net::SystemRouteProvider;
        let ipv4 = provider
            .lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), None)
            .unwrap();
        assert_eq!(ipv4.selection_reason, RouteSelectionReason::Local);
        assert!(ipv4.selected_address.is_some_and(|source| source.is_ipv4()));

        let ipv6 = provider
            .lookup(IpAddr::V6(Ipv6Addr::LOCALHOST), None)
            .unwrap();
        assert_eq!(ipv6.selection_reason, RouteSelectionReason::Local);
        assert!(ipv6.selected_address.is_some_and(|source| source.is_ipv6()));
    }

    #[test]
    fn synchronous_lookup_is_safe_inside_tokio_and_across_concurrent_callers() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::spawn(async {
                crate::net::SystemRouteProvider
                    .lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), None)
                    .unwrap()
            })
            .await
            .unwrap();
        });

        std::thread::scope(|scope| {
            let workers = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        crate::net::SystemRouteProvider
                            .lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), None)
                            .unwrap()
                    })
                })
                .collect::<Vec<_>>();
            for worker in workers {
                worker.join().unwrap();
            }
        });
    }
}
