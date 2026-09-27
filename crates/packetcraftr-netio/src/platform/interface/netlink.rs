// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Linux interface enumeration backed by route netlink link and address
//! dumps, which the route backend also reads for the interface a route
//! leaves through.

use std::{collections::BTreeMap, net::IpAddr};

use futures_util::TryStreamExt;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;
use rtnetlink::{
    Handle,
    packet_route::{
        address::AddressAttribute,
        link::{LinkAttribute, LinkFlags, LinkLayerType},
    },
};

use crate::platform::common::{netlink::with_netlink, os_error};
use crate::{
    interface::{self, Id as InterfaceId},
    link::Capability,
    route,
};

pub(in crate::platform) fn interfaces(
    deadline: &Deadline,
) -> Result<Vec<interface::Info>, interface::Error> {
    snapshot(deadline).map_err(interface::Error::native)
}

/// One link and address dump, which the route backend also reads.
pub(in crate::platform) fn snapshot(
    deadline: &Deadline,
) -> Result<Vec<interface::Info>, route::Error> {
    with_netlink(
        deadline,
        |handle| async move { query_interfaces(&handle).await },
    )
}

pub(in crate::platform) async fn query_interfaces(
    handle: &Handle,
) -> Result<Vec<interface::Info>, route::Error> {
    let mut interfaces = query_links(handle, None).await?;
    query_addresses(handle, None, &mut interfaces).await?;
    Ok(interfaces.into_values().collect())
}

/// Resolves the one interface a route landed on: a filtered link get answers
/// with a single reply. The address iterator filters the host-wide kernel dump
/// in userspace, retaining only addresses belonging to that interface.
pub(in crate::platform) async fn query_interface(
    handle: &Handle,
    index: u32,
    interface_hint: Option<&InterfaceId>,
) -> Result<interface::Info, route::Error> {
    let not_found = || route::Error::InterfaceNotFound {
        name: interface_hint.map_or_else(|| format!("index-{index}"), |hint| hint.name.clone()),
        index,
    };
    let mut interfaces = query_links(handle, Some(index))
        .await
        .map_err(|error| match error {
            // Attach the hinted name to the ENODEV translation.
            route::Error::InterfaceNotFound { .. } => not_found(),
            error => error,
        })?;
    query_addresses(handle, Some(index), &mut interfaces).await?;
    interfaces.remove(&index).ok_or_else(not_found)
}

pub(in crate::platform) async fn query_local_addresses(
    handle: &Handle,
) -> Result<Vec<IpAddr>, route::Error> {
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
) -> Result<BTreeMap<u32, interface::Info>, route::Error> {
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
        let name = name.ok_or_else(|| route::Error::InvalidResponse {
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
fn link_lookup_error(index_filter: Option<u32>, error: rtnetlink::Error) -> route::Error {
    if let Some(index) = index_filter
        && let rtnetlink::Error::NetlinkError(reply) = &error
        && reply.raw_code().checked_abs() == Some(libc::ENODEV)
    {
        return route::Error::InterfaceNotFound {
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
) -> Result<(), route::Error> {
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
    fn a_filtered_link_get_maps_a_missing_interface_to_not_found() {
        assert!(matches!(
            link_lookup_error(Some(4), netlink_error(-libc::ENODEV)),
            route::Error::InterfaceNotFound { index: 4, .. }
        ));
        assert!(matches!(
            link_lookup_error(None, netlink_error(-libc::ENODEV)),
            route::Error::OperatingSystem {
                operation: "RTM_GETLINK",
                ..
            }
        ));
        assert!(matches!(
            link_lookup_error(Some(4), netlink_error(-libc::EPERM)),
            route::Error::OperatingSystem {
                operation: "RTM_GETLINK",
                ..
            }
        ));
    }
}
