// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pure bounded parsers for Darwin socket-address records.

use std::{
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::route::SystemError;

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

/// Decodes an interface netmask sockaddr for an address of the interface's
/// family. XNU trims trailing zero bytes from netmask sockaddrs and records
/// the shortened length (255.255.255.0 arrives with length 7), so the mask
/// is zero-extended to the family's address width instead of requiring a
/// complete sockaddr, and the mask's own family byte is not relied on.
pub(super) fn netmask_prefix(bytes: &[u8], interface_address: IpAddr) -> Option<u8> {
    let (offset, width) = match interface_address {
        IpAddr::V4(_) => (offset_of!(libc::sockaddr_in, sin_addr), 4),
        IpAddr::V6(_) => (offset_of!(libc::sockaddr_in6, sin6_addr), 16),
    };
    let present = bytes.get(offset..).unwrap_or_default();
    let copied = present.len().min(width);
    let mut mask = [0_u8; 16];
    mask[..copied].copy_from_slice(&present[..copied]);
    contiguous_prefix(&mask[..width])
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

pub(super) fn parse_route_addresses(
    bytes: &[u8],
    mask: libc::c_int,
) -> Result<[Option<IpAddr>; libc::RTAX_MAX as usize], SystemError> {
    let mut output = [None; libc::RTAX_MAX as usize];
    let address_slots = output.len();
    let mut offset = 0;
    for (index, slot) in output.iter_mut().enumerate() {
        if mask & (1 << index) == 0 {
            continue;
        }
        let Some(&length_byte) = bytes.get(offset) else {
            return Err(SystemError::InvalidResponse {
                message: "macOS route response truncated its sockaddr list".to_owned(),
            });
        };
        let length = usize::from(length_byte);
        let empty_netmask = index == libc::RTAX_NETMASK as usize && length == 0;
        if length < 2 && !empty_netmask {
            return Err(SystemError::InvalidResponse {
                message: format!(
                    "macOS route response sockaddr index {index} is too short for sa_family: length={length}"
                ),
            });
        }
        let stride = roundup(length);
        let Some(address_end) = offset.checked_add(length) else {
            return Err(SystemError::InvalidResponse {
                message: "macOS route response sockaddr length overflowed".to_owned(),
            });
        };
        if address_end > bytes.len() {
            return Err(SystemError::InvalidResponse {
                message: format!(
                    "macOS route response truncated sockaddr index {index}: offset={offset} length={length} bytes={}",
                    bytes.len()
                ),
            });
        }
        let padded_end = offset.checked_add(stride);
        // index comes from enumerate over output, whose length is RTAX_MAX
        let has_later_address = ((index + 1)..address_slots).any(|later| mask & (1 << later) != 0);
        let next_offset = match padded_end {
            Some(end) if end <= bytes.len() => end,
            // Darwin may omit the unused alignment trailer after the final sockaddr.
            _ if !empty_netmask && !has_later_address && address_end == bytes.len() => address_end,
            _ => {
                return Err(SystemError::InvalidResponse {
                    message: format!(
                        "macOS route response contained an invalid sockaddr at index {index}: offset={offset} length={length} stride={stride} bytes={}",
                        bytes.len()
                    ),
                });
            }
        };
        if empty_netmask {
            if bytes[offset..next_offset].iter().any(|byte| *byte != 0) {
                return Err(SystemError::InvalidResponse {
                    message: "macOS route response zero-length netmask slot contains nonzero bytes"
                        .to_owned(),
                });
            }
        } else {
            *slot = bytes.get(offset..address_end).and_then(sockaddr_ip);
        }
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
        length.next_multiple_of(alignment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_sockaddr(address: Ipv4Addr) -> Vec<u8> {
        let mut bytes = vec![0; size_of::<libc::sockaddr_in>()];
        bytes[0] = u8::try_from(bytes.len()).expect("Darwin sockaddr_in length fits in u8");
        bytes[1] = u8::try_from(libc::AF_INET).expect("Darwin AF_INET fits in u8");
        let address_offset = offset_of!(libc::sockaddr_in, sin_addr);
        bytes[address_offset..address_offset + 4].copy_from_slice(&address.octets());
        bytes
    }

    #[test]
    fn trimmed_netmask_sockaddrs_keep_their_prefix_length() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let inet = u8::try_from(libc::AF_INET).expect("AF_INET fits in u8");
        let inet6 = u8::try_from(libc::AF_INET6).expect("AF_INET6 fits in u8");
        assert_eq!(
            netmask_prefix(&[7, inet, 0, 0, 255, 255, 255], v4),
            Some(24)
        );
        assert_eq!(
            netmask_prefix(&[8, inet, 0, 0, 255, 255, 255, 255], v4),
            Some(32)
        );
        assert_eq!(netmask_prefix(&[5, inet, 0, 0, 0xf0], v4), Some(4));
        assert_eq!(netmask_prefix(&[0], v4), Some(0));
        let full = ipv4_sockaddr(Ipv4Addr::new(255, 255, 254, 0));
        assert_eq!(netmask_prefix(&full, v4), Some(23));
        let mut slash64 = vec![16, inet6, 0, 0, 0, 0, 0, 0];
        slash64.extend_from_slice(&[0xff; 8]);
        assert_eq!(netmask_prefix(&slash64, v6), Some(64));
        assert_eq!(
            netmask_prefix(&[7, inet, 0, 0, 255, 0, 255], v4),
            None,
            "a non-contiguous mask has no prefix length"
        );
    }

    fn mask(indices: &[libc::c_int]) -> libc::c_int {
        indices.iter().fold(0, |mask, index| mask | (1 << *index))
    }

    #[test]
    fn accepts_aligned_zero_length_default_route_netmask() {
        let destination = Ipv4Addr::UNSPECIFIED;
        let gateway = Ipv4Addr::new(192, 0, 2, 1);
        let mut bytes = ipv4_sockaddr(destination);
        bytes.extend(ipv4_sockaddr(gateway));
        bytes.extend([0; size_of::<u32>()]);

        let addresses = parse_route_addresses(
            &bytes,
            mask(&[libc::RTAX_DST, libc::RTAX_GATEWAY, libc::RTAX_NETMASK]),
        )
        .expect("zero-length default-route netmask is valid");

        assert_eq!(
            addresses[libc::RTAX_DST as usize],
            Some(IpAddr::V4(destination))
        );
        assert_eq!(
            addresses[libc::RTAX_GATEWAY as usize],
            Some(IpAddr::V4(gateway))
        );
        assert_eq!(addresses[libc::RTAX_NETMASK as usize], None);
    }

    #[test]
    fn rejects_zero_length_destination_and_gateway_slots() {
        let valid = ipv4_sockaddr(Ipv4Addr::new(192, 0, 2, 1));
        for (bytes, address_mask) in [
            (vec![0; size_of::<u32>()], mask(&[libc::RTAX_DST])),
            (
                {
                    let mut bytes = valid.clone();
                    bytes.extend([0; size_of::<u32>()]);
                    bytes
                },
                mask(&[libc::RTAX_DST, libc::RTAX_GATEWAY]),
            ),
        ] {
            assert!(matches!(
                parse_route_addresses(&bytes, address_mask),
                Err(SystemError::InvalidResponse { .. })
            ));
        }
    }

    #[test]
    fn rejects_truncated_zero_length_netmask_slot() {
        let mut bytes = ipv4_sockaddr(Ipv4Addr::UNSPECIFIED);
        bytes.extend(ipv4_sockaddr(Ipv4Addr::new(192, 0, 2, 1)));
        bytes.push(0);

        assert!(matches!(
            parse_route_addresses(
                &bytes,
                mask(&[libc::RTAX_DST, libc::RTAX_GATEWAY, libc::RTAX_NETMASK])
            ),
            Err(SystemError::InvalidResponse { .. })
        ));
    }

    #[test]
    fn rejects_nonzero_bytes_in_a_zero_length_netmask_slot() {
        let mut bytes = ipv4_sockaddr(Ipv4Addr::UNSPECIFIED);
        bytes.extend(ipv4_sockaddr(Ipv4Addr::new(192, 0, 2, 1)));
        bytes.extend([0, 0, 1, 0]);

        assert!(matches!(
            parse_route_addresses(
                &bytes,
                mask(&[libc::RTAX_DST, libc::RTAX_GATEWAY, libc::RTAX_NETMASK])
            ),
            Err(SystemError::InvalidResponse { .. })
        ));
    }
}
