// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Windows route and interface adapter backed by IP Helper. `GetBestRoute2`
//! supplies route/source selection and `GetAdaptersAddresses` supplies the
//! portable interface snapshot. Neither API emits neighbor traffic.

#[cfg(any(feature = "live", feature = "native-route"))]
use std::mem::{align_of, size_of};
#[cfg(any(feature = "live", feature = "native-route"))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(feature = "native-route")]
use windows::Win32::Foundation::{
    ERROR_ADDRESS_NOT_ASSOCIATED, ERROR_HOST_UNREACHABLE, ERROR_NETWORK_UNREACHABLE, ERROR_NO_DATA,
    ERROR_NOT_FOUND,
};
#[cfg(any(feature = "live", feature = "native-route"))]
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR, WIN32_ERROR};
#[cfg(any(feature = "live", feature = "native-route"))]
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses,
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_PPP, IF_TYPE_SOFTWARE_LOOPBACK,
    IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_NO_MULTICAST,
};
#[cfg(feature = "native-route")]
use windows::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
#[cfg(any(feature = "live", feature = "native-route"))]
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
#[cfg(feature = "native-route")]
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
#[cfg(any(feature = "live", feature = "native-route"))]
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
};
#[cfg(feature = "native-route")]
use windows::Win32::Networking::WinSock::{
    IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6_0, SOCKADDR_INET,
};

#[cfg(feature = "native-route")]
use super::{
    NativeRouteSnapshot, finish_route, interface_decision, validate_preferred_source_family,
};
#[cfg(any(feature = "live", feature = "native-route"))]
use crate::capture::LinkType;
#[cfg(feature = "native-route")]
use crate::net::route::{RouteDecision, RouteSelectionReason};
#[cfg(any(feature = "live", feature = "native-route"))]
use crate::net::{
    interface::{InterfaceAddress, InterfaceFlags, InterfaceInfo},
    link::{LinkCapability, MacAddress},
    route::{InterfaceId, NativeRouteError},
};

#[cfg(any(feature = "live", feature = "native-route"))]
pub(super) fn interfaces() -> Result<Vec<InterfaceInfo>, NativeRouteError> {
    Ok(adapter_snapshots()?
        .into_iter()
        .map(|adapter| adapter.interface)
        .collect())
}

#[cfg(any(feature = "live", feature = "native-route"))]
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

#[cfg(any(feature = "live", feature = "native-route"))]
#[derive(Clone)]
struct WindowsAdapter {
    interface: InterfaceInfo,
    #[cfg(feature = "native-route")]
    ipv4_index: u32,
    #[cfg(feature = "native-route")]
    ipv6_index: u32,
    #[cfg(feature = "native-route")]
    luid: NET_LUID_LH,
}

#[cfg(any(feature = "live", feature = "native-route"))]
#[derive(Clone, Copy)]
struct BufferBounds {
    start: usize,
    end: usize,
}

#[cfg(any(feature = "live", feature = "native-route"))]
impl BufferBounds {
    fn new(start: *const u8, length: usize) -> Result<Self, NativeRouteError> {
        let start = start as usize;
        let end = start
            .checked_add(length)
            .ok_or_else(|| NativeRouteError::InvalidResponse {
                message: "Windows adapter buffer address range overflowed".to_owned(),
            })?;
        Ok(Self { start, end })
    }

    fn contains<T>(self, pointer: *const T) -> bool {
        let address = pointer as usize;
        !pointer.is_null()
            && address.is_multiple_of(align_of::<T>())
            && address >= self.start
            && address
                .checked_add(size_of::<T>())
                .is_some_and(|end| end <= self.end)
    }

    fn contains_bytes(self, pointer: *const u8, length: usize) -> bool {
        let address = pointer as usize;
        !pointer.is_null()
            && address >= self.start
            && address
                .checked_add(length)
                .is_some_and(|end| end <= self.end)
    }
}

#[cfg(feature = "native-route")]
fn adapter_index_for(adapter: &WindowsAdapter, destination: IpAddr) -> u32 {
    if destination.is_ipv4() {
        adapter.ipv4_index
    } else {
        adapter.ipv6_index
    }
}

#[cfg(feature = "native-route")]
fn find_windows_adapter(
    adapters: &[WindowsAdapter],
    requested: &InterfaceId,
) -> Result<WindowsAdapter, NativeRouteError> {
    if let Some(adapter) = adapters.iter().find(|adapter| {
        adapter.interface.id.name == requested.name
            && matches!(
                requested.index,
                index if index == adapter.interface.id.index
                    || index == adapter.ipv4_index
                    || index == adapter.ipv6_index
            )
    }) {
        return Ok(adapter.clone());
    }
    if let Some(actual) = adapters.iter().find(|adapter| {
        adapter.interface.id.name == requested.name
            || requested.index == adapter.interface.id.index
            || requested.index == adapter.ipv4_index
            || requested.index == adapter.ipv6_index
    }) {
        return Err(NativeRouteError::InterfaceMismatch {
            requested: requested.name.clone(),
            requested_index: requested.index,
            actual: actual.interface.id.name.clone(),
            actual_index: actual.interface.id.index,
        });
    }
    Err(NativeRouteError::InterfaceNotFound {
        name: requested.name.clone(),
        index: requested.index,
    })
}

#[cfg(any(feature = "live", feature = "native-route"))]
fn parse_adapters(
    head: *mut IP_ADAPTER_ADDRESSES_LH,
    bounds: BufferBounds,
) -> Result<Vec<WindowsAdapter>, NativeRouteError> {
    let mut interfaces = Vec::new();
    let mut current = head;
    for _ in 0..4096 {
        if current.is_null() {
            return Ok(interfaces);
        }
        if !bounds.contains(current) {
            return Err(NativeRouteError::InvalidResponse {
                message: "Windows adapter list contained an out-of-buffer or misaligned node"
                    .to_owned(),
            });
        }
        // SAFETY: IP Helper constructed this node in the still-live backing
        // allocation, and `bounds` established a complete aligned node.
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
            let friendly_name = wide_string(adapter.FriendlyName, bounds)?.unwrap_or_default();
            let name = if friendly_name.is_empty() {
                format!("index-{index}")
            } else {
                friendly_name
            };
            let description =
                wide_string(adapter.Description, bounds)?.filter(|value| !value.is_empty());
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
            interfaces.push(WindowsAdapter {
                interface: InterfaceInfo {
                    id: InterfaceId { name, index },
                    description,
                    mac_address,
                    addresses: parse_unicast_addresses(adapter.FirstUnicastAddress, bounds)?,
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
                },
                #[cfg(feature = "native-route")]
                ipv4_index,
                #[cfg(feature = "native-route")]
                ipv6_index: adapter.Ipv6IfIndex,
                #[cfg(feature = "native-route")]
                luid: adapter.Luid,
            });
        }
        current = adapter.Next;
    }
    Err(NativeRouteError::InvalidResponse {
        message: "Windows adapter list exceeded its traversal bound".to_owned(),
    })
}

#[cfg(any(feature = "live", feature = "native-route"))]
fn parse_unicast_addresses(
    mut current: *mut windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH,
    bounds: BufferBounds,
) -> Result<Vec<InterfaceAddress>, NativeRouteError> {
    let mut addresses = Vec::new();
    for _ in 0..16_384 {
        if current.is_null() {
            return Ok(addresses);
        }
        if !bounds.contains(current) {
            return Err(NativeRouteError::InvalidResponse {
                message:
                    "Windows unicast-address list contained an out-of-buffer or misaligned node"
                        .to_owned(),
            });
        }
        // SAFETY: each node belongs to the live adapter buffer and the pointer
        // was checked to cover a complete aligned structure.
        let unicast = unsafe { &*current };
        if let Some(address) = socket_address_ip(&unicast.Address, bounds)? {
            let maximum_prefix = if address.is_ipv4() { 32 } else { 128 };
            if unicast.OnLinkPrefixLength > maximum_prefix {
                return Err(NativeRouteError::InvalidResponse {
                    message: format!(
                        "Windows returned invalid prefix length {} for {address}",
                        unicast.OnLinkPrefixLength
                    ),
                });
            }
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

#[cfg(any(feature = "live", feature = "native-route"))]
fn wide_string(
    value: windows::core::PWSTR,
    bounds: BufferBounds,
) -> Result<Option<String>, NativeRouteError> {
    if value.is_null() {
        return Ok(None);
    }
    let pointer = value.as_ptr();
    if !(pointer as usize).is_multiple_of(align_of::<u16>())
        || !bounds.contains_bytes(pointer.cast(), 2)
    {
        return Err(NativeRouteError::InvalidResponse {
            message: "Windows adapter string pointed outside its response buffer".to_owned(),
        });
    }
    let available = (bounds.end - pointer as usize) / size_of::<u16>();
    // SAFETY: the checked pointer is aligned and `available` ends at the
    // response buffer boundary. We search only this initialized range.
    let units = unsafe { std::slice::from_raw_parts(pointer, available) };
    let length = units.iter().position(|unit| *unit == 0).ok_or_else(|| {
        NativeRouteError::InvalidResponse {
            message: "Windows adapter string was not terminated within its response buffer"
                .to_owned(),
        }
    })?;
    Ok(String::from_utf16(&units[..length]).ok())
}

#[cfg(any(feature = "live", feature = "native-route"))]
fn socket_address_ip(
    address: &windows::Win32::Networking::WinSock::SOCKET_ADDRESS,
    bounds: BufferBounds,
) -> Result<Option<IpAddr>, NativeRouteError> {
    if address.lpSockaddr.is_null() || address.iSockaddrLength < size_of::<ADDRESS_FAMILY>() as i32
    {
        return Ok(None);
    }
    let length = usize::try_from(address.iSockaddrLength).map_err(|_| {
        NativeRouteError::InvalidResponse {
            message: "Windows returned a negative socket-address length".to_owned(),
        }
    })?;
    if !bounds.contains_bytes(address.lpSockaddr.cast(), length) {
        return Err(NativeRouteError::InvalidResponse {
            message: "Windows socket address extended outside its response buffer".to_owned(),
        });
    }
    // SAFETY: the checked byte range contains the family field; use an
    // unaligned read before the family-specific alignment checks below.
    let family = unsafe { std::ptr::read_unaligned(address.lpSockaddr.cast::<ADDRESS_FAMILY>()) };
    match family {
        AF_INET if address.iSockaddrLength >= size_of::<SOCKADDR_IN>() as i32 => {
            if !bounds.contains(address.lpSockaddr.cast::<SOCKADDR_IN>()) {
                return Err(NativeRouteError::InvalidResponse {
                    message: "Windows returned a misaligned IPv4 socket address".to_owned(),
                });
            }
            // SAFETY: family, length, bounds, and alignment establish a
            // complete SOCKADDR_IN.
            let value = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN>() };
            // SAFETY: S_addr is the active IN_ADDR representation.
            let bytes = unsafe { value.sin_addr.S_un.S_addr.to_ne_bytes() };
            Ok(Some(IpAddr::V4(Ipv4Addr::from(bytes))))
        }
        AF_INET6 if address.iSockaddrLength >= size_of::<SOCKADDR_IN6>() as i32 => {
            if !bounds.contains(address.lpSockaddr.cast::<SOCKADDR_IN6>()) {
                return Err(NativeRouteError::InvalidResponse {
                    message: "Windows returned a misaligned IPv6 socket address".to_owned(),
                });
            }
            // SAFETY: family, length, bounds, and alignment establish a
            // complete SOCKADDR_IN6.
            let value = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN6>() };
            // SAFETY: Byte is the active byte representation of IN6_ADDR.
            let bytes = unsafe { value.sin6_addr.u.Byte };
            Ok(Some(IpAddr::V6(Ipv6Addr::from(bytes))))
        }
        _ => Ok(None),
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

#[cfg(any(feature = "live", feature = "native-route"))]
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
    use crate::net::route::Provider as RouteProvider;

    #[test]
    fn adapter_buffer_bounds_reject_misaligned_and_out_of_range_pointers() {
        let storage = [0_u64; 8];
        let bounds =
            BufferBounds::new(storage.as_ptr().cast(), std::mem::size_of_val(&storage)).unwrap();
        assert!(bounds.contains(storage.as_ptr()));

        // The arithmetic creates inert test pointers only; neither is
        // dereferenced.
        let misaligned = unsafe { storage.as_ptr().cast::<u8>().add(1) }.cast::<u64>();
        assert!(!bounds.contains(misaligned));
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

        let provider = crate::net::route::SystemProvider;
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

#[cfg(all(test, feature = "live"))]
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
