// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{Error, interface::Id as InterfaceId};

pub(super) fn validate(interface: &InterfaceId, source: &str) -> Result<(), Error> {
    if has_symbolic_operand(source) {
        return Err(Error::InvalidCaptureFilter {
            interface: interface.name.clone(),
            message: "symbolic names are disabled because native BPF compilation can resolve them; use numeric address, network, port, and protocol operands".to_owned(),
        });
    }
    Ok(())
}

// The longest IPv6 text is 45 bytes and the longest MAC spelling is 17, so a
// longer run of [hex : .] is never an IPv6 or MAC operand. The scan stops one
// byte past the bound, which is enough to tell.
const MAX_NUMERIC_RUN: usize = 45;

// indices stay below bytes.len() and every str slice boundary is an ASCII byte
fn has_symbolic_operand(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut offset = 0;
    let mut ethernet_operand = false;
    let mut portrange_operand = false;
    while offset < bytes.len() {
        if bytes[offset] == b'\\' {
            return true;
        }
        if bytes[offset].is_ascii_hexdigit() || bytes[offset] == b':' {
            let limit = bytes.len().min(offset + MAX_NUMERIC_RUN + 1);
            let mut end = offset + 1;
            while end < limit
                && (bytes[end].is_ascii_hexdigit() || matches!(bytes[end], b':' | b'.'))
            {
                end += 1;
            }
            let atom = &source[offset..end];
            let may_be_address = end - offset <= MAX_NUMERIC_RUN;
            if may_be_address && atom.parse::<std::net::Ipv6Addr>().is_ok() {
                ethernet_operand = false;
                portrange_operand = false;
                offset = end;
                continue;
            }
            if may_be_address && is_numeric_mac(atom) {
                let allow_ethernet_mac = ethernet_operand;
                ethernet_operand = false;
                portrange_operand = false;
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
            if std::mem::take(&mut portrange_operand) && is_numeric_port_range(atom) {
                continue;
            }
            portrange_operand = atom == "portrange";
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

fn is_numeric_port_range(atom: &str) -> bool {
    atom.split_once('-')
        .is_some_and(|(first, last)| is_port_number(first) && is_port_number(last))
}

fn is_port_number(text: &str) -> bool {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(digits) => u16::from_str_radix(digits, 16),
        None => text.parse::<u16>(),
    }
    .is_ok()
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
    use std::time::{Duration, Instant};

    use super::*;
    use crate::capture::MAX_FILTER_BYTES;

    #[test]
    fn validator_accepts_only_numeric_operands() {
        let accepted = [
            "arp and ether dst 01:02:03:04:05:06",
            "ip6 and dst host 2001:db8::1",
            "ip6 host ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
            "tcp dst port 443",
            "ip net 192.0.2.0/24",
            "ether host 0011.2233.4455",
            "ip proto 0x11",
            "portrange 6000-6010",
            "udp portrange 6000-6010",
            "tcp portrange 0x10-0x20",
            "portrange 6000 - 6010",
        ];
        let rejected = [
            "host example.com",
            "tcp port https",
            "gateway router-1",
            "host 0011.2233.4455",
            r"ip host \resolver-name",
            "portrange 80-http",
            "portrange 1-2 host 3-4",
            "portrange 1-70000",
            "host 1-2",
        ];

        for filter in accepted {
            assert!(!has_symbolic_operand(filter), "{filter}");
        }
        for filter in rejected {
            assert!(has_symbolic_operand(filter), "{filter}");
        }
    }

    #[test]
    fn validator_stays_fast_on_filters_at_the_length_limit() {
        for filter in [
            ":".repeat(MAX_FILTER_BYTES),
            "1:".repeat(MAX_FILTER_BYTES / 2),
        ] {
            let started = Instant::now();
            let symbolic = has_symbolic_operand(&filter);
            let elapsed = started.elapsed();

            assert!(!symbolic);
            assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
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
            Error::InvalidCaptureFilter {
                interface: actual,
                ..
            } if actual == interface.name
        ));
    }
}
