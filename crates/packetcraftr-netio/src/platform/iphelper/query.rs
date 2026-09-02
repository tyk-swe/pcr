// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Windows passive route selection backed by `GetBestRoute2`.

#![allow(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{
    ERROR_ADDRESS_NOT_ASSOCIATED, ERROR_HOST_UNREACHABLE, ERROR_NETWORK_UNREACHABLE, ERROR_NO_DATA,
    ERROR_NOT_FOUND, NO_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_IN6_0, SOCKADDR_INET,
};

use super::adapter::{WindowsAdapter, adapter_index_for, find_windows_adapter};
use super::enumeration::{adapter_snapshots, win32_error};
use crate::platform::route_normalize::{
    InterfaceCandidate, NativeRouteSnapshot, constrain_by_preferred_source, finish_route,
    interface_decision, validate_preferred_source_family,
};
use crate::{
    interface::Id as InterfaceId,
    route::{Decision, SelectionReason, SystemError},
};

pub(in crate::platform) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<Decision, SystemError> {
    validate_preferred_source_family(destination, preferred_source)?;

    let available = adapter_snapshots()?;
    let constrained_interface = constrain_interface(&available, interface_hint, preferred_source)?;
    let BestRoute {
        row: best_route,
        source: best_source,
    } = query_best_route(
        destination,
        preferred_source,
        constrained_interface.as_ref(),
    )?;

    let selected_source =
        sockaddr_inet_ip(&best_source).filter(|address| !address.is_unspecified());
    let output_index = best_route.InterfaceIndex;
    let adapter = available
        .iter()
        .find(|adapter| adapter_index_for(adapter, destination) == output_index)
        .cloned()
        .or_else(|| {
            selected_source.and_then(|source| {
                available
                    .iter()
                    .find(|adapter| {
                        adapter
                            .interface
                            .addresses
                            .iter()
                            .any(|assigned| assigned.address == source)
                    })
                    .cloned()
            })
        })
        .ok_or_else(|| SystemError::InterfaceNotFound {
            name: constrained_interface.as_ref().map_or_else(
                || format!("index-{output_index}"),
                |adapter| adapter.interface.id.name.clone(),
            ),
            index: output_index,
        })?;
    let mut interface = adapter.interface;
    // Use the family-specific IP Helper index with portable adapter metadata.
    interface.id.index = output_index;
    let normalized_constraint = constrained_interface.as_ref().map(|adapter| InterfaceId {
        name: adapter.interface.id.name.clone(),
        index: adapter_index_for(adapter, destination),
    });
    let next_hop =
        sockaddr_inet_ip(&best_route.NextHop).filter(|address| !address.is_unspecified());
    finish_route(
        destination,
        normalized_constraint.as_ref(),
        preferred_source,
        NativeRouteSnapshot {
            interface,
            selected_source,
            next_hop,
            route_mtu: None,
            selection_reason: if best_route.Loopback {
                SelectionReason::Local
            } else if next_hop.is_some() {
                SelectionReason::Gateway
            } else {
                SelectionReason::OnLink
            },
        },
    )
}

fn constrain_interface(
    available: &[WindowsAdapter],
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<Option<WindowsAdapter>, SystemError> {
    let requested = interface_hint
        .map(|requested| find_windows_adapter(available, requested))
        .transpose()?;
    constrain_by_preferred_source(available, interface_hint, requested, preferred_source)
}

impl InterfaceCandidate for WindowsAdapter {
    fn interface(&self) -> &crate::interface::Info {
        &self.interface
    }

    fn is_same(&self, other: &Self) -> bool {
        self.ipv4_index == other.ipv4_index && self.ipv6_index == other.ipv6_index
    }
}

struct BestRoute {
    row: MIB_IPFORWARD_ROW2,
    source: SOCKADDR_INET,
}

fn query_best_route(
    destination: IpAddr,
    preferred_source: Option<IpAddr>,
    constrained_interface: Option<&WindowsAdapter>,
) -> Result<BestRoute, SystemError> {
    let interface_index =
        constrained_interface.map_or(0, |adapter| adapter_index_for(adapter, destination));
    let destination_address = encode_address(destination, interface_index);
    let source_address = preferred_source.map(|source| encode_address(source, interface_index));
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: all pointers refer to initialized input/output structures for
    // the duration of this synchronous IP Helper call.
    let result = unsafe {
        GetBestRoute2(
            constrained_interface.map(|adapter| &adapter.luid as *const NET_LUID_LH),
            interface_index,
            source_address.as_ref().map(|source| source as *const _),
            &destination_address,
            0,
            &mut row,
            &mut source,
        )
    };
    if result != NO_ERROR {
        if matches!(
            result,
            ERROR_NOT_FOUND
                | ERROR_NO_DATA
                | ERROR_NETWORK_UNREACHABLE
                | ERROR_HOST_UNREACHABLE
                | ERROR_ADDRESS_NOT_ASSOCIATED
        ) {
            return Err(SystemError::RouteNotFound { destination });
        }
        return Err(win32_error("GetBestRoute2", result));
    }
    Ok(BestRoute { row, source })
}

pub(in crate::platform) fn interface_route(
    requested: &InterfaceId,
) -> Result<Decision, SystemError> {
    let adapters = adapter_snapshots()?;
    interface_decision(find_windows_adapter(&adapters, requested)?.interface)
}

pub(super) fn encode_address(address: IpAddr, scope_id: u32) -> SOCKADDR_INET {
    match address {
        IpAddr::V4(address) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(address.octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        IpAddr::V6(address) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 {
                    // GetBestRoute2 accepts a scope ID only for link-local or multicast IPv6.
                    sin6_scope_id: if address.is_unicast_link_local() || address.is_multicast() {
                        scope_id
                    } else {
                        0
                    },
                },
            },
        },
    }
}

pub(super) fn sockaddr_inet_ip(address: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: the family field is common to every SOCKADDR_INET union member.
    let family = unsafe { address.si_family };
    match family {
        AF_INET => {
            // SAFETY: AF_INET identifies the active IPv4 union member and its
            // active IN_ADDR scalar representation.
            let bytes = unsafe { address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes() };
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        AF_INET6 => {
            // SAFETY: AF_INET6 identifies the active IPv6 union member and its
            // active byte-array address representation.
            let bytes = unsafe { address.Ipv6.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}
