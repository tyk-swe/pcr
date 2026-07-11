// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Windows route and interface adapter backed by IP Helper. `GetBestRoute2`
//! supplies route/source selection and `GetAdaptersAddresses` supplies the
//! portable interface snapshot. Neither API emits neighbor traffic.

#[cfg(feature = "native-route")]
use std::mem::{align_of, size_of};
#[cfg(feature = "native-route")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(feature = "native-route")]
use windows::Win32::Foundation::{
    ERROR_ADDRESS_NOT_ASSOCIATED, ERROR_BUFFER_OVERFLOW, ERROR_HOST_UNREACHABLE,
    ERROR_NETWORK_UNREACHABLE, ERROR_NOT_FOUND, ERROR_NO_DATA, NO_ERROR, WIN32_ERROR,
};
#[cfg(feature = "native-route")]
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetBestRoute2, GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS,
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_PPP, IF_TYPE_SOFTWARE_LOOPBACK,
    IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_NO_MULTICAST, MIB_IPFORWARD_ROW2,
};
#[cfg(feature = "native-route")]
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
#[cfg(feature = "native-route")]
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0,
    SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};

#[cfg(feature = "native-route")]
use super::{find_interface, finish_route, interface_decision, NativeRouteSnapshot};
#[cfg(feature = "native-route")]
use crate::capture::LinkType;
#[cfg(feature = "native-route")]
use crate::net::{
    InterfaceAddress, InterfaceFlags, InterfaceId, InterfaceInfo, LinkCapability, MacAddress,
    NativeRouteError, RouteDecision, RouteSelectionReason,
};

#[cfg(feature = "native-route")]
pub(super) fn interfaces() -> Result<Vec<InterfaceInfo>, NativeRouteError> {
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
        return parse_adapters(head);
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
    if preferred_source.is_some_and(|source| source.is_ipv4() != destination.is_ipv4()) {
        return Err(NativeRouteError::SourceFamilyMismatch {
            preferred_source: preferred_source.expect("checked source"),
            destination,
        });
    }

    let available = interfaces()?;
    let mut constrained_interface = interface_hint
        .map(|requested| find_interface(available.clone(), requested))
        .transpose()?;
    if let Some(source) = preferred_source {
        let source_interface = available
            .iter()
            .find(|interface| {
                interface
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
            if requested.id != source_interface.id {
                return Err(NativeRouteError::SourceUnavailable {
                    preferred_source: source,
                    interface: requested.id.name.clone(),
                });
            }
        } else {
            constrained_interface = Some(source_interface);
        }
    }

    let interface_index = constrained_interface
        .as_ref()
        .map_or(0, |interface| interface.id.index);
    let destination_address = encode_address(
        destination,
        constrained_interface
            .as_ref()
            .map_or(0, |interface| interface.id.index),
    );
    let source_address = preferred_source.map(|source| encode_address(source, interface_index));
    let mut best_route = MIB_IPFORWARD_ROW2::default();
    let mut best_source = SOCKADDR_INET::default();
    // SAFETY: all pointers refer to initialized input/output structures for
    // the duration of this synchronous IP Helper call.
    let result = unsafe {
        GetBestRoute2(
            None,
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
    let mut interface = available
        .iter()
        .find(|interface| interface.id.index == output_index)
        .cloned()
        .or_else(|| {
            selected_address.and_then(|source| {
                available
                    .iter()
                    .find(|interface| {
                        interface
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
                |interface| interface.id.name.clone(),
            ),
            index: output_index,
        })?;
    if constrained_interface.is_none() && interface.id.index != output_index {
        // IPv4 and IPv6 interface indices can differ for the same adapter.
        // The route decision always reports the exact index returned by IP
        // Helper, while retaining the adapter's portable metadata.
        interface.id.index = output_index;
    }
    let next_hop =
        sockaddr_inet_ip(&best_route.NextHop).filter(|address| !address.is_unspecified());
    finish_route(
        destination,
        constrained_interface
            .as_ref()
            .map(|interface| &interface.id),
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
    interface_decision(find_interface(interfaces()?, requested)?)
}

#[cfg(feature = "native-route")]
fn parse_adapters(
    head: *mut IP_ADAPTER_ADDRESSES_LH,
) -> Result<Vec<InterfaceInfo>, NativeRouteError> {
    let mut interfaces = Vec::new();
    let mut current = head;
    for _ in 0..4096 {
        if current.is_null() {
            return Ok(interfaces);
        }
        // SAFETY: IP Helper constructed this node in the still-live backing
        // allocation. The list is traversed only until its null terminator.
        let adapter = unsafe { &*current };
        // SAFETY: these are the active documented fields of the generated C
        // unions in IP_ADAPTER_ADDRESSES_LH.
        let ipv4_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let flags = unsafe { adapter.Anonymous2.Flags };
        let index = if ipv4_index != 0 {
            ipv4_index
        } else {
            adapter.Ipv6IfIndex
        };
        if index != 0 {
            let friendly_name = wide_string(adapter.FriendlyName).unwrap_or_default();
            let name = if friendly_name.is_empty() {
                format!("index-{index}")
            } else {
                friendly_name
            };
            let description = wide_string(adapter.Description).filter(|value| !value.is_empty());
            let mac_address = if adapter.PhysicalAddressLength == 6 {
                let mut bytes = [0_u8; 6];
                bytes.copy_from_slice(&adapter.PhysicalAddress[..6]);
                Some(MacAddress(bytes))
            } else {
                None
            };
            let loopback = adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK;
            let ethernet = matches!(adapter.IfType, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211)
                && mac_address.is_some();
            interfaces.push(InterfaceInfo {
                id: InterfaceId { name, index },
                description,
                mac_address,
                addresses: parse_unicast_addresses(adapter.FirstUnicastAddress)?,
                flags: InterfaceFlags {
                    up: adapter.OperStatus == IfOperStatusUp,
                    broadcast: ethernet,
                    loopback,
                    point_to_point: adapter.IfType == IF_TYPE_PPP,
                    multicast: flags & IP_ADAPTER_NO_MULTICAST == 0,
                },
                mtu: (adapter.Mtu != 0).then_some(adapter.Mtu),
                capability: if ethernet {
                    LinkCapability::Layer2And3
                } else {
                    LinkCapability::Layer3
                },
                link_type: if ethernet {
                    LinkType::ETHERNET
                } else {
                    LinkType::RAW
                },
            });
        }
        current = adapter.Next;
    }
    Err(NativeRouteError::InvalidResponse {
        message: "Windows adapter list exceeded its traversal bound".to_owned(),
    })
}

#[cfg(feature = "native-route")]
fn parse_unicast_addresses(
    mut current: *mut windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH,
) -> Result<Vec<InterfaceAddress>, NativeRouteError> {
    let mut addresses = Vec::new();
    for _ in 0..16_384 {
        if current.is_null() {
            return Ok(addresses);
        }
        // SAFETY: each node belongs to the live adapter buffer and the pointer
        // is advanced using the OS-created linked list.
        let unicast = unsafe { &*current };
        if let Some(address) = socket_address_ip(&unicast.Address) {
            let assigned = InterfaceAddress {
                address,
                prefix_length: unicast.OnLinkPrefixLength,
            };
            if !addresses.contains(&assigned) {
                addresses.push(assigned);
            }
        }
        current = unicast.Next;
    }
    Err(NativeRouteError::InvalidResponse {
        message: "Windows unicast-address list exceeded its traversal bound".to_owned(),
    })
}

#[cfg(feature = "native-route")]
fn wide_string(value: windows::core::PWSTR) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: IP Helper guarantees a NUL-terminated UTF-16 string within the
    // live adapter buffer.
    unsafe { value.to_string().ok() }
}

#[cfg(feature = "native-route")]
fn socket_address_ip(
    address: &windows::Win32::Networking::WinSock::SOCKET_ADDRESS,
) -> Option<IpAddr> {
    if address.lpSockaddr.is_null() || address.iSockaddrLength < size_of::<ADDRESS_FAMILY>() as i32
    {
        return None;
    }
    // SAFETY: the socket-address length establishes at least the family field.
    let family = unsafe { (*address.lpSockaddr).sa_family };
    match family {
        AF_INET if address.iSockaddrLength >= size_of::<SOCKADDR_IN>() as i32 => {
            // SAFETY: family and length establish a complete SOCKADDR_IN.
            let value = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN>() };
            // SAFETY: S_addr is the active IN_ADDR representation.
            let bytes = unsafe { value.sin_addr.S_un.S_addr.to_ne_bytes() };
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        AF_INET6 if address.iSockaddrLength >= size_of::<SOCKADDR_IN6>() as i32 => {
            // SAFETY: family and length establish a complete SOCKADDR_IN6.
            let value = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN6>() };
            // SAFETY: Byte is the active byte representation of IN6_ADDR.
            let bytes = unsafe { value.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
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

#[cfg(feature = "native-route")]
fn win32_error(operation: &'static str, error: WIN32_ERROR) -> NativeRouteError {
    NativeRouteError::OperatingSystem {
        operation,
        message: format!(
            "{} (Win32 error {})",
            std::io::Error::from_raw_os_error(error.0 as i32),
            error.0
        ),
    }
}

#[cfg(all(test, feature = "native-route"))]
mod tests {
    use super::*;
    use crate::net::RouteProvider;

    #[test]
    fn native_windows_provider_finds_loopback_routes_and_interfaces() {
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
}
