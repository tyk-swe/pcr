// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pure bounded parsers for Darwin socket-address records.

#![forbid(unsafe_code)]

use std::{
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::route::NativeRouteError;

pub(super) fn sockaddr_ip(bytes: &[u8]) -> Option<IpAddr> {
    // Darwin sockaddr stores `sa_family` after its leading length byte.
    let family = *bytes.get(1)? as libc::sa_family_t;
    match i32::from(family) {
        libc::AF_INET if bytes.len() >= size_of::<libc::sockaddr_in>() => {
            let offset = offset_of!(libc::sockaddr_in, sin_addr);
            let octets: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        libc::AF_INET6 if bytes.len() >= size_of::<libc::sockaddr_in6>() => {
            let offset = offset_of!(libc::sockaddr_in6, sin6_addr);
            let octets: [u8; 16] = bytes
                .get(offset..offset.checked_add(16)?)?
                .try_into()
                .ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

pub(super) fn parse_route_addresses(
    bytes: &[u8],
    mask: libc::c_int,
) -> Result<[Option<IpAddr>; libc::RTAX_MAX as usize], NativeRouteError> {
    let mut output = [None; libc::RTAX_MAX as usize];
    let address_slots = output.len();
    let mut offset = 0;
    for (index, slot) in output.iter_mut().enumerate() {
        if mask & (1 << index) == 0 {
            continue;
        }
        let Some(&length_byte) = bytes.get(offset) else {
            return Err(NativeRouteError::InvalidResponse {
                message: "macOS route response truncated its sockaddr list".to_owned(),
            });
        };
        let length = usize::from(length_byte);
        if length < 2 {
            return Err(NativeRouteError::InvalidResponse {
                message: format!(
                    "macOS route response sockaddr index {index} is too short for sa_family: length={length}"
                ),
            });
        }
        let stride = roundup(length);
        let Some(address_end) = offset.checked_add(length) else {
            return Err(NativeRouteError::InvalidResponse {
                message: "macOS route response sockaddr length overflowed".to_owned(),
            });
        };
        if address_end > bytes.len() {
            return Err(NativeRouteError::InvalidResponse {
                message: format!(
                    "macOS route response truncated sockaddr index {index}: offset={offset} length={length} bytes={}",
                    bytes.len()
                ),
            });
        }
        let padded_end = offset.checked_add(stride);
        let has_later_address = ((index + 1)..address_slots).any(|later| mask & (1 << later) != 0);
        let next_offset = match padded_end {
            Some(end) if end <= bytes.len() => end,
            // Darwin may omit the unused alignment trailer after the final sockaddr.
            _ if !has_later_address && address_end == bytes.len() => address_end,
            _ => {
                return Err(NativeRouteError::InvalidResponse {
                    message: format!(
                        "macOS route response contained an invalid sockaddr at index {index}: offset={offset} length={length} stride={stride} bytes={}",
                        bytes.len()
                    ),
                });
            }
        };
        *slot = sockaddr_ip(&bytes[offset..address_end]);
        offset = next_offset;
    }
    Ok(output)
}

pub(super) fn roundup(length: usize) -> usize {
    // Darwin routing sockets use 32-bit sockaddr alignment, not pointer-width alignment.
    let alignment = size_of::<u32>();
    if length == 0 {
        alignment
    } else {
        (length + alignment - 1) & !(alignment - 1)
    }
}
