// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Windows route and interface adapter backed by IP Helper. `GetBestRoute2`
//! supplies route/source selection and `GetAdaptersAddresses` supplies the
//! portable interface snapshot. Neither API emits neighbor traffic.

#![allow(unsafe_code)]

use std::mem::{align_of, size_of};
#[cfg(feature = "native-route")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(feature = "native-route")]
use windows::Win32::Foundation::{
    ERROR_ADDRESS_NOT_ASSOCIATED, ERROR_HOST_UNREACHABLE, ERROR_NETWORK_UNREACHABLE, ERROR_NO_DATA,
    ERROR_NOT_FOUND,
};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH,
};
#[cfg(feature = "native-route")]
use windows::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
#[cfg(feature = "native-route")]
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::AF_UNSPEC;
#[cfg(feature = "native-route")]
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_IN6_0, SOCKADDR_INET,
};

use self::adapter::{BufferBounds, WindowsAdapter, parse_adapters};
#[cfg(feature = "native-route")]
use self::adapter::{adapter_index_for, find_windows_adapter};
#[cfg(feature = "native-route")]
use super::{
    NativeRouteSnapshot, finish_route, interface_decision, validate_preferred_source_family,
};
#[cfg(feature = "native-route")]
use crate::route::InterfaceId;
#[cfg(feature = "native-route")]
use crate::route::{RouteDecision, RouteSelectionReason};
use crate::{interface::InterfaceInfo, route::NativeRouteError};

mod adapter;

pub(super) fn interfaces() -> Result<Vec<InterfaceInfo>, NativeRouteError> {
    Ok(adapter_snapshots()?
        .into_iter()
        .map(|adapter| adapter.interface)
        .collect())
}

fn adapter_snapshots() -> Result<Vec<WindowsAdapter>, NativeRouteError> {
    const FLAGS: GET_ADAPTERS_ADDRESSES_FLAGS = GET_ADAPTERS_ADDRESSES_FLAGS(
        GAA_FLAG_INCLUDE_PREFIX.0
            | GAA_FLAG_SKIP_ANYCAST.0
            | GAA_FLAG_SKIP_MULTICAST.0
            | GAA_FLAG_SKIP_DNS_SERVER.0,
    );
    let mut required = 0_u32;
    // SAFETY: this documented sizing call has null output storage and a valid
    // size pointer. No linked-list pointer is dereferenced.
    let sizing =
        unsafe { GetAdaptersAddresses(u32::from(AF_UNSPEC.0), FLAGS, None, None, &mut required) };
    if sizing != ERROR_BUFFER_OVERFLOW.0 && sizing != NO_ERROR.0 {
        return Err(win32_error(
            "GetAdaptersAddresses(size)",
            WIN32_ERROR(sizing),
        ));
    }

    for _ in 0..4 {
        let word_count = usize::try_from(required)
            .ok()
            .and_then(|bytes| bytes.checked_add(align_of::<usize>() - 1))
            .map(|bytes| bytes / align_of::<usize>())
            .filter(|words| *words != 0)
            .ok_or_else(|| NativeRouteError::InvalidResponse {
                message: "Windows reported an invalid adapter buffer size".to_owned(),
            })?;
        // A usize vector supplies alignment at least as strict as every IP
        // Helper structure while keeping the backing allocation initialized.
        let mut storage = vec![0_usize; word_count];
        let head = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut supplied = required;
        // SAFETY: `storage` is writable for at least `supplied` bytes and is
        // suitably aligned for IP_ADAPTER_ADDRESSES_LH.
        let result = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                FLAGS,
                None,
                Some(head),
                &mut supplied,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW.0 {
            required = supplied;
            continue;
        }
        if result != NO_ERROR.0 {
            return Err(win32_error("GetAdaptersAddresses", WIN32_ERROR(result)));
        }
        let initialized =
            usize::try_from(supplied).map_err(|_| NativeRouteError::InvalidResponse {
                message: "Windows returned an unrepresentable adapter buffer length".to_owned(),
            })?;
        let allocated = storage
            .len()
            .checked_mul(size_of::<usize>())
            .ok_or_else(|| NativeRouteError::InvalidResponse {
                message: "Windows adapter buffer size overflowed".to_owned(),
            })?;
        if initialized == 0 || initialized > allocated {
            return Err(NativeRouteError::InvalidResponse {
                message: format!(
                    "Windows initialized {initialized} bytes of a {allocated}-byte adapter buffer"
                ),
            });
        }
        let bounds = BufferBounds::new(storage.as_ptr().cast(), initialized)?;
        return parse_adapters(head, bounds);
    }
    Err(NativeRouteError::OperatingSystem {
        operation: "GetAdaptersAddresses",
        message: "adapter list changed during four consecutive reads".to_owned(),
    })
}

#[cfg(feature = "native-route")]
pub(super) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    validate_preferred_source_family(destination, preferred_source)?;

    let available = adapter_snapshots()?;
    let mut constrained_interface = interface_hint
        .map(|requested| find_windows_adapter(&available, requested))
        .transpose()?;
    if let Some(source) = preferred_source {
        let source_interface = available
            .iter()
            .find(|adapter| {
                adapter
                    .interface
                    .addresses
                    .iter()
                    .any(|assigned| assigned.address == source)
            })
            .cloned()
            .ok_or_else(|| NativeRouteError::SourceUnavailable {
                preferred_source: source,
                interface: interface_hint
                    .map_or_else(|| "any interface".to_owned(), |hint| hint.name.clone()),
            })?;
        if let Some(requested) = &constrained_interface {
            if requested.ipv4_index != source_interface.ipv4_index
                || requested.ipv6_index != source_interface.ipv6_index
            {
                return Err(NativeRouteError::SourceUnavailable {
                    preferred_source: source,
                    interface: requested.interface.id.name.clone(),
                });
            }
        } else {
            constrained_interface = Some(source_interface);
        }
    }

    let interface_index = constrained_interface
        .as_ref()
        .map_or(0, |adapter| adapter_index_for(adapter, destination));
    let destination_address = encode_address(destination, interface_index);
    let source_address = preferred_source.map(|source| encode_address(source, interface_index));
    let mut best_route = MIB_IPFORWARD_ROW2::default();
    let mut best_source = SOCKADDR_INET::default();
    // SAFETY: all pointers refer to initialized input/output structures for
    // the duration of this synchronous IP Helper call.
    let result = unsafe {
        GetBestRoute2(
            constrained_interface
                .as_ref()
                .map(|adapter| &adapter.luid as *const NET_LUID_LH),
            interface_index,
            source_address.as_ref().map(|source| source as *const _),
            &destination_address,
            0,
            &mut best_route,
            &mut best_source,
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
            return Err(NativeRouteError::RouteNotFound { destination });
        }
        return Err(win32_error("GetBestRoute2", result));
    }

    let selected_address =
        sockaddr_inet_ip(&best_source).filter(|address| !address.is_unspecified());
    let output_index = best_route.InterfaceIndex;
    let adapter = available
        .iter()
        .find(|adapter| adapter_index_for(adapter, destination) == output_index)
        .cloned()
        .or_else(|| {
            selected_address.and_then(|source| {
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
        .ok_or_else(|| NativeRouteError::InterfaceNotFound {
            name: constrained_interface.as_ref().map_or_else(
                || format!("index-{output_index}"),
                |adapter| adapter.interface.id.name.clone(),
            ),
            index: output_index,
        })?;
    let mut interface = adapter.interface;
    // The route decision always reports the family-specific index returned by
    // IP Helper while retaining the adapter's portable metadata.
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
            selected_address,
            next_hop,
            route_mtu: None,
            selection_reason: if best_route.Loopback {
                RouteSelectionReason::Local
            } else if next_hop.is_some() {
                RouteSelectionReason::Gateway
            } else {
                RouteSelectionReason::OnLink
            },
        },
    )
}

#[cfg(feature = "native-route")]
pub(super) fn interface_route(requested: &InterfaceId) -> Result<RouteDecision, NativeRouteError> {
    let adapters = adapter_snapshots()?;
    interface_decision(find_windows_adapter(&adapters, requested)?.interface)
}

#[cfg(feature = "native-route")]
fn encode_address(address: IpAddr, scope_id: u32) -> SOCKADDR_INET {
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
                    // A zone index is meaningful only for scoped IPv6
                    // destinations. GetBestRoute2 rejects a non-zero scope on
                    // loopback and global addresses with ERROR_INVALID_PARAMETER.
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

#[cfg(feature = "native-route")]
fn sockaddr_inet_ip(address: &SOCKADDR_INET) -> Option<IpAddr> {
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

fn win32_error(operation: &'static str, error: WIN32_ERROR) -> NativeRouteError {
    NativeRouteError::OperatingSystem {
        operation,
        message: format!(
            "{} (Win32 error {})",
            std::io::Error::from_raw_os_error(error.0.cast_signed()),
            error.0
        ),
    }
}

#[cfg(all(test, feature = "native-route"))]
mod tests {
    use crate::{interface::InterfaceFlags, link::LinkCapability};
    use packetcraftr_core::frame::LinkType;

    use super::*;
    use crate::route::Provider as RouteProvider;

    #[test]
    fn adapter_buffer_bounds_reject_misaligned_and_out_of_range_pointers() {
        let storage = [0_u64; 8];
        let bounds =
            BufferBounds::new(storage.as_ptr().cast(), std::mem::size_of_val(&storage)).unwrap();
        assert!(bounds.contains(storage.as_ptr()));

        // SAFETY: the arithmetic creates inert test pointers only; neither is
        // dereferenced.
        let misaligned = unsafe { storage.as_ptr().cast::<u8>().add(1) }.cast::<u64>();
        assert!(!bounds.contains(misaligned));
        // SAFETY: this constructs the one-past-the-end sentinel pointer for a
        // bounds check only; it is not dereferenced.
        let end = unsafe {
            storage
                .as_ptr()
                .cast::<u8>()
                .add(std::mem::size_of_val(&storage))
        };
        assert!(!bounds.contains_bytes(end, 1));
    }

    #[test]
    fn native_windows_provider_finds_loopback_routes_and_interfaces() {
        let interfaces = interfaces().unwrap();
        assert!(interfaces.iter().any(|interface| interface.flags.loopback));

        let provider = crate::route::SystemProvider;
        let ipv4 = provider
            .lookup_with_preferences(IpAddr::V4(Ipv4Addr::LOCALHOST), None, None)
            .unwrap();
        assert_eq!(ipv4.selection_reason, RouteSelectionReason::Local);
        assert!(ipv4.selected_address.is_some_and(|source| source.is_ipv4()));

        let ipv6 = provider
            .lookup_with_preferences(IpAddr::V6(Ipv6Addr::LOCALHOST), None, None)
            .unwrap();
        assert_eq!(ipv6.selection_reason, RouteSelectionReason::Local);
        assert!(ipv6.selected_address.is_some_and(|source| source.is_ipv6()));
    }

    #[test]
    fn ipv6_scope_id_is_only_encoded_for_scoped_addresses() {
        let loopback = encode_address(IpAddr::V6(Ipv6Addr::LOCALHOST), 42);
        let global = encode_address(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()), 42);
        let link_local = encode_address(IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()), 42);

        // SAFETY: each value was constructed with its IPv6 union member active.
        assert_eq!(unsafe { loopback.Ipv6.Anonymous.sin6_scope_id }, 0);
        // SAFETY: each value was constructed with its IPv6 union member active.
        assert_eq!(unsafe { global.Ipv6.Anonymous.sin6_scope_id }, 0);
        // SAFETY: each value was constructed with its IPv6 union member active.
        assert_eq!(unsafe { link_local.Ipv6.Anonymous.sin6_scope_id }, 42);
    }

    #[test]
    fn family_specific_adapter_indices_are_preserved_and_selected() {
        let adapter = WindowsAdapter {
            interface: InterfaceInfo {
                id: InterfaceId {
                    name: "synthetic".to_owned(),
                    index: 4,
                },
                description: None,
                mac_address: None,
                addresses: Vec::new(),
                flags: InterfaceFlags::default(),
                mtu: Some(1500),
                capability: LinkCapability::Layer3,
                link_type: LinkType::RAW,
            },
            ipv4_index: 4,
            ipv6_index: 9,
            luid: NET_LUID_LH::default(),
        };
        assert_eq!(
            adapter_index_for(&adapter, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            4
        );
        assert_eq!(
            adapter_index_for(&adapter, IpAddr::V6(Ipv6Addr::LOCALHOST)),
            9
        );
        assert_eq!(
            find_windows_adapter(
                std::slice::from_ref(&adapter),
                &InterfaceId {
                    name: "synthetic".to_owned(),
                    index: 9,
                },
            )
            .unwrap()
            .ipv6_index,
            9
        );
    }
}

#[cfg(test)]
mod default_profile_tests {
    use super::*;

    #[test]
    fn default_live_profile_enumerates_windows_interfaces() {
        let interfaces = interfaces().unwrap();
        assert!(!interfaces.is_empty());
        assert!(
            interfaces
                .iter()
                .all(|interface| interface.id.index != 0 && !interface.id.name.is_empty())
        );
    }
}
