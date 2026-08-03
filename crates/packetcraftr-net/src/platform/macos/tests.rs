// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(test)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::enumeration::{interfaces, link_mtu, sockaddr_prefix};
use super::parser::{parse_route_addresses, roundup, sockaddr_ip};
use super::query::encode_sockaddr;
use crate::route::{Provider as RouteProvider, RouteSelectionReason};

#[test]
fn native_macos_provider_finds_loopback_routes_and_interfaces() {
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
fn route_address_parser_accepts_only_an_unpadded_final_compact_sockaddr() {
    let mut destination = encode_sockaddr(IpAddr::V4(Ipv4Addr::new(10, 50, 1, 0))).unwrap();
    let compact_mask = [7_u8, 0, 0xff, 0xff, 0xff, 0, 0];
    destination.extend_from_slice(&compact_mask);
    let addresses = parse_route_addresses(&destination, libc::RTA_DST | libc::RTA_NETMASK).unwrap();
    assert_eq!(
        addresses[libc::RTAX_DST as usize],
        Some(IpAddr::V4(Ipv4Addr::new(10, 50, 1, 0)))
    );

    let error =
        parse_route_addresses(&compact_mask, libc::RTA_NETMASK | libc::RTA_IFA).unwrap_err();
    assert!(error.to_string().contains("invalid sockaddr"));
}

#[test]
fn route_address_parser_uses_darwin_32_bit_sockaddr_alignment() {
    let mut message = encode_sockaddr(IpAddr::V4(Ipv4Addr::new(10, 50, 1, 0))).unwrap();
    let mut gateway = [0_u8; 20];
    gateway[0] = u8::try_from(gateway.len()).unwrap();
    gateway[1] = u8::try_from(libc::AF_LINK).unwrap();
    message.extend_from_slice(&gateway);
    message.extend_from_slice(&[7_u8, 0, 0xff, 0xff, 0xff, 0, 0]);

    let addresses = parse_route_addresses(
        &message,
        libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK,
    )
    .unwrap();
    assert_eq!(
        addresses[libc::RTAX_DST as usize],
        Some(IpAddr::V4(Ipv4Addr::new(10, 50, 1, 0)))
    );
    assert_eq!(roundup(20), 20);
    assert_eq!(roundup(7), 8);
}

#[test]
fn sockaddr_parser_checks_two_byte_family_and_exact_family_sizes() {
    assert_eq!(sockaddr_ip(&[]), None);
    assert_eq!(sockaddr_ip(&[1]), None);
    assert_eq!(sockaddr_ip(&[2, 0xff]), None);

    for address in [
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V6("2001:db8::1".parse().unwrap()),
    ] {
        let encoded = encode_sockaddr(address).unwrap();
        assert_eq!(sockaddr_ip(&encoded), Some(address));
        assert_eq!(sockaddr_ip(&encoded[..encoded.len() - 1]), None);
    }

    for bytes in [vec![0], vec![1]] {
        assert!(parse_route_addresses(&bytes, libc::RTA_DST).is_err());
    }
    assert!(parse_route_addresses(&[2, 0xff, 0, 0], libc::RTA_DST).is_ok());
}

#[test]
fn interface_netmask_prefix_requires_contiguous_bits() {
    for (mask, expected) in [
        (IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)), Some(24)),
        (IpAddr::V4(Ipv4Addr::UNSPECIFIED), Some(0)),
        (IpAddr::V4(Ipv4Addr::new(255, 0, 255, 0)), None),
        (IpAddr::V4(Ipv4Addr::new(255, 127, 0, 0)), None),
    ] {
        let encoded = encode_sockaddr(mask).unwrap();
        assert_eq!(
            sockaddr_prefix(
                encoded.as_ptr().cast(),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ),
            expected
        );
    }

    for (mask, expected) in [
        (
            IpAddr::V6("ffff:ffff:ffff:ffff::".parse().unwrap()),
            Some(64),
        ),
        (IpAddr::V6(Ipv6Addr::UNSPECIFIED), Some(0)),
        (IpAddr::V6("ffff:0:ffff::".parse().unwrap()), None),
    ] {
        let encoded = encode_sockaddr(mask).unwrap();
        assert_eq!(
            sockaddr_prefix(encoded.as_ptr().cast(), IpAddr::V6(Ipv6Addr::LOCALHOST)),
            expected
        );
    }
}

#[test]
fn interface_mtu_data_is_interpreted_only_for_af_link() {
    let differently_typed = 0x5a_u8;
    assert_eq!(
        link_mtu(
            libc::sa_family_t::try_from(libc::AF_INET).unwrap(),
            (&differently_typed as *const u8).cast(),
        ),
        None
    );

    // SAFETY: all-zero is a valid baseline for the synthetic C record.
    let mut data: libc::if_data = unsafe { std::mem::zeroed() };
    data.ifi_mtu = 1500;
    assert_eq!(
        link_mtu(
            libc::sa_family_t::try_from(libc::AF_LINK).unwrap(),
            (&data as *const libc::if_data).cast(),
        ),
        Some(1500)
    );
}
