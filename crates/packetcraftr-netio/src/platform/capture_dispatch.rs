// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native capture capability dispatch.

#![forbid(unsafe_code)]

use crate::{
    Error as LiveIoError,
    capture::{CaptureQueueLimits, CaptureSession},
    route::PlannedRoute,
};

#[cfg(all(feature = "native-layer2", windows))]
use super::npcap as capture_backend;
#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos")
))]
use super::pcap_backend as capture_backend;

#[cfg(feature = "native-layer2")]
pub(crate) fn system_capture(
    route: &PlannedRoute,
    limits: CaptureQueueLimits,
    capture_filter: Option<&str>,
) -> Result<Box<dyn CaptureSession>, LiveIoError> {
    let validated_limits = limits.validate()?;
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        if let Some(filter) = capture_filter {
            validate_resolver_free_capture_filter(&route.route.interface, filter)?;
        }
        let interface =
            super::interface_identity::validate_current_interface_identity(&route.route.interface)?;
        let netmask = capture_netmask(route.route.selected_address, &interface);
        let parts = capture_backend::open_capture(
            &route.route.interface,
            validated_limits,
            capture_filter,
            netmask,
        )?;
        Ok(Box::new(super::live_capture::NativeCaptureSession::spawn(
            parts,
            validated_limits,
        )?))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (route, validated_limits, capture_filter);
        Err(LiveIoError::Unsupported {
            message: "native Layer 2 capture is unsupported on this target".to_owned(),
        })
    }
}

#[cfg(not(feature = "native-layer2"))]
pub(crate) fn system_capture(
    _route: &PlannedRoute,
    _limits: CaptureQueueLimits,
    _capture_filter: Option<&str>,
) -> Result<Box<dyn CaptureSession>, LiveIoError> {
    Err(LiveIoError::Unsupported {
        message: "enable the native-layer2 feature for native packet capture".to_owned(),
    })
}

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn validate_resolver_free_capture_filter(
    interface: &crate::route::InterfaceId,
    source: &str,
) -> Result<(), LiveIoError> {
    if capture_filter_has_symbolic_operand(source) {
        return Err(LiveIoError::InvalidCaptureFilter {
            interface: interface.name.clone(),
            message: "symbolic names are disabled because native BPF compilation can resolve them; use numeric address, network, port, and protocol operands".to_owned(),
        });
    }
    Ok(())
}

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn capture_filter_has_symbolic_operand(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut offset = 0;
    let mut ethernet_operand = false;
    while offset < bytes.len() {
        if bytes[offset] == b'\\' {
            return true;
        }
        if bytes[offset].is_ascii_hexdigit() || bytes[offset] == b':' {
            let mut end = offset + 1;
            while end < bytes.len()
                && (bytes[end].is_ascii_hexdigit() || matches!(bytes[end], b':' | b'.'))
            {
                end += 1;
            }
            let atom = &source[offset..end];
            if atom.parse::<std::net::Ipv6Addr>().is_ok() {
                ethernet_operand = false;
                offset = end;
                continue;
            }
            if is_numeric_mac(atom) {
                let allow_ethernet_mac = ethernet_operand;
                ethernet_operand = false;
                if !is_numeric_bpf_atom(atom, allow_ethernet_mac) {
                    return true;
                }
                offset = end;
                continue;
            }
        }
        if bytes[offset].is_ascii_alphanumeric() {
            let start = offset;
            offset += 1;
            while offset < bytes.len()
                && (bytes[offset].is_ascii_alphanumeric()
                    || matches!(bytes[offset], b'_' | b'-' | b'.'))
            {
                offset += 1;
            }
            let atom = &source[start..offset];
            if atom == "ether" {
                ethernet_operand = true;
                continue;
            }
            if ethernet_operand && is_ether_operand_modifier(atom) {
                continue;
            }
            let allow_ethernet_mac = ethernet_operand;
            ethernet_operand = false;
            if !is_bpf_keyword(atom) && !is_numeric_bpf_atom(atom, allow_ethernet_mac) {
                return true;
            }
            continue;
        }
        offset += 1;
    }
    false
}

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn is_numeric_bpf_atom(atom: &str, allow_ethernet_mac: bool) -> bool {
    let numeric_mac = is_numeric_mac(atom);
    if numeric_mac && !allow_ethernet_mac && is_hostname_shaped_mac(atom) {
        return false;
    }
    atom.bytes().all(|byte| byte.is_ascii_digit())
        || atom
            .strip_prefix("0x")
            .or_else(|| atom.strip_prefix("0X"))
            .is_some_and(|digits| {
                !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        || {
            let mut components = atom.split('.');
            let count = components.clone().count();
            (2..=4).contains(&count)
                && components.all(|component| {
                    !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
                })
        }
        || numeric_mac
}

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn is_numeric_mac(atom: &str) -> bool {
    is_plain_mac(atom)
        || is_hex_sequence(atom, ':', 6, 1, 2)
        || is_hex_sequence(atom, '-', 6, 1, 2)
        || is_hex_sequence(atom, '.', 6, 1, 2)
        || is_hex_sequence(atom, '.', 3, 4, 4)
}

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn is_hostname_shaped_mac(atom: &str) -> bool {
    is_plain_mac(atom) || is_hex_sequence(atom, '.', 3, 4, 4) || is_hex_sequence(atom, '-', 6, 1, 2)
}

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn is_plain_mac(atom: &str) -> bool {
    atom.len() == 12 && atom.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn is_hex_sequence(
    atom: &str,
    separator: char,
    component_count: usize,
    minimum_width: usize,
    maximum_width: usize,
) -> bool {
    let mut components = atom.split(separator);
    components.clone().count() == component_count
        && components.all(|component| {
            (minimum_width..=maximum_width).contains(&component.len())
                && component.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn is_ether_operand_modifier(atom: &str) -> bool {
    matches!(
        atom,
        "host" | "src" | "dst" | "addr1" | "addr2" | "address1" | "address2"
    )
}

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn is_bpf_keyword(atom: &str) -> bool {
    // Allow only libpcap 1.0 keywords; extend this list with the supported runtime floor.
    const KEYWORDS: &str = concat!(
        "dst src link ether ppp slip fddi tr wlan arp rarp ip sctp tcp udp icmp igmp igrp pim ",
        "vrrp radio ip6 icmp6 ah esp atalk aarp decnet lat sca moprc mopdl iso esis es-is isis ",
        "is-is l1 l2 iih lsp snp csnp psnp clnp stp ipx netbeui host net mask port portrange ",
        "proto protochain gateway type subtype direction dir address1 addr1 address2 addr2 ",
        "address3 addr3 address4 addr4 less greater byte broadcast multicast and or not len ",
        "length inbound outbound vlan mpls pppoed pppoes lane llc metac bcc oam oamf4 oamf4ec ",
        "oamf4sc sc ilmic vpi vci connectmsg metaconnect on ifname rset ruleset rnr rulenum ",
        "srnr subrulenum reason action fisu lssu lsu msu sio opc dpc sls icmptype icmpcode ",
        "icmp-echoreply icmp-unreach icmp-sourcequench icmp-redirect icmp-echo ",
        "icmp-routeradvert icmp-routersolicit icmp-timxceed icmp-paramprob icmp-tstamp ",
        "icmp-tstampreply icmp-ireq icmp-ireqreply icmp-maskreq icmp-maskreply tcpflags tcp-fin ",
        "tcp-syn tcp-rst tcp-push tcp-ack tcp-urg ",
    );
    KEYWORDS
        .split_ascii_whitespace()
        .any(|keyword| atom == keyword)
}
#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn capture_netmask(
    selected_address: Option<std::net::IpAddr>,
    interface: &crate::interface::InterfaceInfo,
) -> Option<u32> {
    let selected_address = match selected_address {
        Some(std::net::IpAddr::V4(address)) => Some(address),
        _ => None,
    };
    let assigned = selected_address
        .and_then(|selected| {
            interface
                .addresses
                .iter()
                .find(|assigned| assigned.address == std::net::IpAddr::V4(selected))
        })
        .or_else(|| {
            interface
                .addresses
                .iter()
                .find(|assigned| assigned.address.is_ipv4())
        })?;
    let shift = u32::BITS.checked_sub(u32::from(assigned.prefix_length))?;
    Some(u32::MAX.checked_shl(shift).unwrap_or(0).to_be())
}
