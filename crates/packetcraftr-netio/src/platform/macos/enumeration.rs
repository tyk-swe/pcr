// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! macOS interface enumeration via `getifaddrs(3)`.

#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::mem::size_of;
use std::net::IpAddr;
use std::ptr;

use super::parser::sockaddr_ip;
use crate::{
    interface::{self, Id as InterfaceId},
    link::{Capability, MacAddress},
    route::SystemError,
};
use packetcraftr_core::frame::LinkType;

pub(in crate::platform) fn interfaces() -> Result<Vec<interface::Info>, SystemError> {
    let mut head = ptr::null_mut();
    // SAFETY: `head` is a valid output pointer and a successful call owns a
    // linked list that remains valid until the matching `freeifaddrs` below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(last_os_error("getifaddrs"));
    }
    let guard = IfAddrsGuard(head);
    let mut by_index = BTreeMap::<u32, interface::Info>::new();
    let mut current = guard.0;
    while !current.is_null() {
        // SAFETY: every node is part of the live list owned by `guard`.
        let entry = unsafe { &*current };
        if !entry.ifa_name.is_null() {
            // SAFETY: `ifa_name` is a NUL-terminated name owned by the list.
            let name = unsafe { CStr::from_ptr(entry.ifa_name) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: the C string is valid for this call.
            let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
            if index != 0 {
                let flags = entry.ifa_flags;
                let interface = by_index.entry(index).or_insert_with(|| interface::Info {
                    id: InterfaceId {
                        name: name.clone(),
                        index,
                    },
                    description: None,
                    mac_address: None,
                    addresses: Vec::new(),
                    flags: interface_flags(flags),
                    mtu: None,
                    capability: Capability::Layer3,
                    link_type: LinkType::RAW,
                });
                interface.flags = interface_flags(flags);

                if !entry.ifa_addr.is_null() {
                    // SAFETY: `ifa_addr` points to a sockaddr whose length is
                    // recorded in its first byte for the list lifetime.
                    let address = unsafe { &*entry.ifa_addr };
                    let length = usize::from(address.sa_len);
                    match i32::from(address.sa_family) {
                        libc::AF_INET | libc::AF_INET6 => {
                            // SAFETY: the live getifaddrs entry owns at least
                            // the declared sockaddr bytes for this iteration.
                            let bytes = unsafe {
                                std::slice::from_raw_parts(entry.ifa_addr.cast::<u8>(), length)
                            };
                            if let Some(ip) = sockaddr_ip(bytes) {
                                let prefix_length = if entry.ifa_netmask.is_null() {
                                    if ip.is_ipv4() { 32 } else { 128 }
                                } else {
                                    sockaddr_prefix(entry.ifa_netmask, ip)
                                        .unwrap_or(if ip.is_ipv4() { 32 } else { 128 })
                                };
                                let assigned = interface::Address {
                                    address: ip,
                                    prefix_length,
                                };
                                if !interface.addresses.contains(&assigned) {
                                    interface.addresses.push(assigned);
                                }
                            }
                        }
                        libc::AF_LINK => {
                            if let Some(mtu) = link_mtu(address.sa_family, entry.ifa_data) {
                                interface.mtu = Some(mtu);
                            }
                            interface.mac_address = link_address(entry.ifa_addr, length);
                            if interface.mac_address.is_some() && !interface.flags.loopback {
                                interface.capability = Capability::Layer2AndLayer3;
                                interface.link_type = LinkType::ETHERNET;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        current = entry.ifa_next;
    }
    Ok(by_index.into_values().collect())
}

struct IfAddrsGuard(*mut libc::ifaddrs);

impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this is the list returned by `getifaddrs`, freed once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}

fn interface_flags(flags: libc::c_uint) -> interface::Flags {
    interface::Flags {
        up: flags & libc::IFF_UP as u32 != 0,
        broadcast: flags & libc::IFF_BROADCAST as u32 != 0,
        loopback: flags & libc::IFF_LOOPBACK as u32 != 0,
        point_to_point: flags & libc::IFF_POINTOPOINT as u32 != 0,
        multicast: flags & libc::IFF_MULTICAST as u32 != 0,
    }
}

pub(super) fn link_mtu(family: libc::sa_family_t, data: *const libc::c_void) -> Option<u32> {
    if i32::from(family) != libc::AF_LINK || data.is_null() {
        return None;
    }
    // SAFETY: Darwin defines AF_LINK ifa_data as a live if_data object. The
    // family gate above is the audited conversion boundary.
    let data = unsafe { ptr::read_unaligned(data.cast::<libc::if_data>()) };
    (data.ifi_mtu != 0).then_some(data.ifi_mtu)
}

pub(super) fn sockaddr_prefix(
    address: *const libc::sockaddr,
    interface_address: IpAddr,
) -> Option<u8> {
    if address.is_null() {
        return None;
    }
    // SAFETY: a live sockaddr always contains its leading length byte, and
    // getifaddrs owns the declared record for this call.
    let length = usize::from(unsafe { *address.cast::<u8>() });
    // SAFETY: getifaddrs owns the live record for this call, and its leading
    // length byte bounds the complete sockaddr allocation.
    let bytes = unsafe { std::slice::from_raw_parts(address.cast::<u8>(), length) };
    let ip = sockaddr_ip(bytes)?;
    match (interface_address, ip) {
        (IpAddr::V4(_), IpAddr::V4(mask)) => contiguous_prefix(&mask.octets()),
        (IpAddr::V6(_), IpAddr::V6(mask)) => contiguous_prefix(&mask.octets()),
        _ => None,
    }
}

fn contiguous_prefix(bytes: &[u8]) -> Option<u8> {
    let mut prefix = 0_u32;
    let mut reached_suffix = false;
    for &byte in bytes {
        let leading = byte.leading_ones();
        if (reached_suffix && byte != 0) || byte.count_ones() != leading {
            return None;
        }
        prefix = prefix.checked_add(leading)?;
        reached_suffix |= leading != u8::BITS;
    }
    u8::try_from(prefix).ok()
}

fn link_address(address: *const libc::sockaddr, length: usize) -> Option<MacAddress> {
    if length < size_of::<libc::sockaddr_dl>() {
        return None;
    }
    // SAFETY: AF_LINK plus the checked length establishes the fixed portion.
    let link = unsafe { ptr::read_unaligned(address.cast::<libc::sockaddr_dl>()) };
    if link.sdl_alen != 6 {
        return None;
    }
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "sdl_data is a field of sockaddr_dl, so its length never exceeds the struct size"
    )]
    let data_offset = size_of::<libc::sockaddr_dl>() - link.sdl_data.len();
    let address_offset = data_offset.checked_add(usize::from(link.sdl_nlen))?;
    if address_offset.checked_add(6)? > length {
        return None;
    }
    let mut bytes = [0_u8; 6];
    // SAFETY: bounds above keep the six-byte copy within this sockaddr_dl.
    unsafe {
        ptr::copy_nonoverlapping(
            address.cast::<u8>().add(address_offset),
            bytes.as_mut_ptr(),
            6,
        )
    };
    Some(MacAddress(bytes))
}

fn last_os_error(operation: &'static str) -> SystemError {
    os_error(operation, std::io::Error::last_os_error())
}

pub(super) fn os_error(operation: &'static str, error: impl std::fmt::Display) -> SystemError {
    SystemError::OperatingSystem {
        operation,
        message: error.to_string(),
    }
}
