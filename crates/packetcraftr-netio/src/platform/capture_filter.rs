// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Resolver-free native capture-filter validation.

#![forbid(unsafe_code)]

use crate::{Error as LiveIoError, interface::Id as InterfaceId};

pub(super) fn validate(interface: &InterfaceId, source: &str) -> Result<(), LiveIoError> {
    if has_symbolic_operand(source) {
        return Err(LiveIoError::InvalidCaptureFilter {
            interface: interface.name.clone(),
            message: "symbolic names are disabled because native BPF compilation can resolve them; use numeric address, network, port, and protocol operands".to_owned(),
        });
    }
    Ok(())
}

#[expect(
    clippy::indexing_slicing,
    reason = "indices stay below bytes.len() and every str slice boundary is an ASCII byte"
)]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "offset and end only advance by one within bytes.len(), which cannot overflow usize"
)]
fn has_symbolic_operand(source: &str) -> bool {
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

fn is_numeric_mac(atom: &str) -> bool {
    is_plain_mac(atom)
        || is_hex_sequence(atom, ':', 6, 1, 2)
        || is_hex_sequence(atom, '-', 6, 1, 2)
        || is_hex_sequence(atom, '.', 6, 1, 2)
        || is_hex_sequence(atom, '.', 3, 4, 4)
}

fn is_hostname_shaped_mac(atom: &str) -> bool {
    is_plain_mac(atom) || is_hex_sequence(atom, '.', 3, 4, 4) || is_hex_sequence(atom, '-', 6, 1, 2)
}

fn is_plain_mac(atom: &str) -> bool {
    atom.len() == 12 && atom.bytes().all(|byte| byte.is_ascii_hexdigit())
}

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

fn is_ether_operand_modifier(atom: &str) -> bool {
    matches!(
        atom,
        "host" | "src" | "dst" | "addr1" | "addr2" | "address1" | "address2"
    )
}

fn is_bpf_keyword(atom: &str) -> bool {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn validator_accepts_only_numeric_operands() {
        let accepted = [
            "arp and ether dst 01:02:03:04:05:06",
            "ip6 and dst host 2001:db8::1",
            "tcp dst port 443",
            "ip net 192.0.2.0/24",
            "ether host 0011.2233.4455",
            "ip proto 0x11",
        ];
        let rejected = [
            "host example.com",
            "tcp port https",
            "gateway router-1",
            "host 0011.2233.4455",
            r"ip host \resolver-name",
        ];

        for filter in accepted {
            assert!(!has_symbolic_operand(filter), "{filter}");
        }
        for filter in rejected {
            assert!(has_symbolic_operand(filter), "{filter}");
        }
    }

    #[test]
    fn failure_preserves_the_selected_interface() {
        let interface = InterfaceId {
            name: "fixture0".to_owned(),
            index: 7,
        };

        let error =
            validate(&interface, "host example.com").expect_err("symbolic host must fail closed");

        assert!(matches!(
            error,
            LiveIoError::InvalidCaptureFilter {
                interface: actual,
                ..
            } if actual == interface.name
        ));
    }
}
