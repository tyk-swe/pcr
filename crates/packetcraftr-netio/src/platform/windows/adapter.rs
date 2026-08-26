// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded parsing of initialized `GetAdaptersAddresses` response buffers.

#![allow(unsafe_code)]

use std::{
    mem::{align_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[cfg(feature = "native-route")]
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::{
    NetworkManagement::{
        IpHelper::{
            IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_PPP, IF_TYPE_SOFTWARE_LOOPBACK,
            IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_NO_MULTICAST, IP_ADAPTER_UNICAST_ADDRESS_LH,
        },
        Ndis::IfOperStatusUp,
    },
    Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6},
};

use crate::{
    interface::{self, Id as InterfaceId},
    link::{Capability, MacAddress},
    route::SystemError,
};
use packetcraftr_core::frame::LinkType;

#[derive(Clone)]
pub(super) struct WindowsAdapter {
    pub(super) interface: interface::Info,
    #[cfg(feature = "native-route")]
    pub(super) ipv4_index: u32,
    #[cfg(feature = "native-route")]
    pub(super) ipv6_index: u32,
    #[cfg(feature = "native-route")]
    pub(super) luid: NET_LUID_LH,
}

#[derive(Clone, Copy)]
pub(super) struct BufferBounds {
    start: usize,
    end: usize,
}

impl BufferBounds {
    pub(super) fn new(start: *const u8, length: usize) -> Result<Self, SystemError> {
        let start = start as usize;
        let end = start
            .checked_add(length)
            .ok_or_else(|| SystemError::InvalidResponse {
                message: "Windows adapter buffer address range overflowed".to_owned(),
            })?;
        Ok(Self { start, end })
    }

    pub(super) fn contains<T>(self, pointer: *const T) -> bool {
        let address = pointer as usize;
        !pointer.is_null()
            && address.is_multiple_of(align_of::<T>())
            && address >= self.start
            && address
                .checked_add(size_of::<T>())
                .is_some_and(|end| end <= self.end)
    }

    pub(super) fn contains_bytes(self, pointer: *const u8, length: usize) -> bool {
        let address = pointer as usize;
        !pointer.is_null()
            && address >= self.start
            && address
                .checked_add(length)
                .is_some_and(|end| end <= self.end)
    }
}

#[cfg(feature = "native-route")]
pub(super) fn adapter_index_for(adapter: &WindowsAdapter, destination: IpAddr) -> u32 {
    if destination.is_ipv4() {
        adapter.ipv4_index
    } else {
        adapter.ipv6_index
    }
}

#[cfg(feature = "native-route")]
pub(super) fn find_windows_adapter(
    adapters: &[WindowsAdapter],
    requested: &InterfaceId,
) -> Result<WindowsAdapter, SystemError> {
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
        return Err(SystemError::InterfaceMismatch {
            requested: requested.name.clone(),
            requested_index: requested.index,
            actual: actual.interface.id.name.clone(),
            actual_index: actual.interface.id.index,
        });
    }
    Err(SystemError::InterfaceNotFound {
        name: requested.name.clone(),
        index: requested.index,
    })
}

pub(super) fn parse_adapters(
    head: *mut IP_ADAPTER_ADDRESSES_LH,
    bounds: BufferBounds,
) -> Result<Vec<WindowsAdapter>, SystemError> {
    let mut interfaces = Vec::new();
    let mut current = head;
    for _ in 0..4096 {
        if current.is_null() {
            return Ok(interfaces);
        }
        if !bounds.contains(current) {
            return Err(SystemError::InvalidResponse {
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
        // SAFETY: Flags is the active documented field of the second generated
        // C union in IP_ADAPTER_ADDRESSES_LH.
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
                interface: interface::Info {
                    id: InterfaceId { name, index },
                    description,
                    mac_address,
                    addresses: parse_unicast_addresses(adapter.FirstUnicastAddress, bounds)?,
                    flags: interface::Flags {
                        up: adapter.OperStatus == IfOperStatusUp,
                        broadcast: ethernet,
                        loopback,
                        point_to_point: adapter.IfType == IF_TYPE_PPP,
                        multicast: flags & IP_ADAPTER_NO_MULTICAST == 0,
                    },
                    mtu: (adapter.Mtu != 0).then_some(adapter.Mtu),
                    capability: if ethernet {
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
    Err(SystemError::InvalidResponse {
        message: "Windows adapter list exceeded its traversal bound".to_owned(),
    })
}

fn parse_unicast_addresses(
    mut current: *mut IP_ADAPTER_UNICAST_ADDRESS_LH,
    bounds: BufferBounds,
) -> Result<Vec<interface::Address>, SystemError> {
    let mut addresses = Vec::new();
    for _ in 0..16_384 {
        if current.is_null() {
            return Ok(addresses);
        }
        if !bounds.contains(current) {
            return Err(SystemError::InvalidResponse {
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
                return Err(SystemError::InvalidResponse {
                    message: format!(
                        "Windows returned invalid prefix length {} for {address}",
                        unicast.OnLinkPrefixLength
                    ),
                });
            }
            let assigned = interface::Address {
                address,
                prefix_length: unicast.OnLinkPrefixLength,
            };
            if !addresses.contains(&assigned) {
                addresses.push(assigned);
            }
        }
        current = unicast.Next;
    }
    Err(SystemError::InvalidResponse {
        message: "Windows unicast-address list exceeded its traversal bound".to_owned(),
    })
}

fn wide_string(
    value: windows::core::PWSTR,
    bounds: BufferBounds,
) -> Result<Option<String>, SystemError> {
    if value.is_null() {
        return Ok(None);
    }
    let pointer = value.as_ptr();
    if !(pointer as usize).is_multiple_of(align_of::<u16>())
        || !bounds.contains_bytes(pointer.cast(), 2)
    {
        return Err(SystemError::InvalidResponse {
            message: "Windows adapter string pointed outside its response buffer".to_owned(),
        });
    }
    let available = bounds
        .end
        .saturating_sub(pointer as usize)
        .checked_div(size_of::<u16>())
        .unwrap_or(0);
    // SAFETY: the checked pointer is aligned and `available` ends at the
    // response buffer boundary. We search only this initialized range.
    let units = unsafe { std::slice::from_raw_parts(pointer, available) };
    let length =
        units
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| SystemError::InvalidResponse {
                message: "Windows adapter string was not terminated within its response buffer"
                    .to_owned(),
            })?;
    Ok(units
        .get(..length)
        .and_then(|units| String::from_utf16(units).ok()))
}

fn socket_address_ip(
    address: &windows::Win32::Networking::WinSock::SOCKET_ADDRESS,
    bounds: BufferBounds,
) -> Result<Option<IpAddr>, SystemError> {
    if address.lpSockaddr.is_null() {
        return Ok(None);
    }
    let length =
        usize::try_from(address.iSockaddrLength).map_err(|_| SystemError::InvalidResponse {
            message: "Windows returned a negative socket-address length".to_owned(),
        })?;
    if length < size_of::<ADDRESS_FAMILY>() {
        return Ok(None);
    }
    if !bounds.contains_bytes(address.lpSockaddr.cast(), length) {
        return Err(SystemError::InvalidResponse {
            message: "Windows socket address extended outside its response buffer".to_owned(),
        });
    }
    // SAFETY: the checked byte range contains the family field; use an
    // unaligned read before the family-specific alignment checks below.
    let family = unsafe { std::ptr::read_unaligned(address.lpSockaddr.cast::<ADDRESS_FAMILY>()) };
    match family {
        AF_INET if length >= size_of::<SOCKADDR_IN>() => {
            if !bounds.contains(address.lpSockaddr.cast::<SOCKADDR_IN>()) {
                return Err(SystemError::InvalidResponse {
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
        AF_INET6 if length >= size_of::<SOCKADDR_IN6>() => {
            if !bounds.contains(address.lpSockaddr.cast::<SOCKADDR_IN6>()) {
                return Err(SystemError::InvalidResponse {
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
