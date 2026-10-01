// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::frame::LinkType;

/// The accepted names, spelled once for every command's `--link-type` help.
macro_rules! names_help {
    () => {
        "by name or number: null (0), ethernet (1), bsd-raw (12), raw (101), loop (108), \
         linux-sll (113), ipv4 (228), ipv6 (229), or linux-sll2 (276); any other \
         decimal DLT is accepted as a number"
    };
}
pub(crate) use names_help;

const NAMES: &str = "null, bsd-null, ethernet, bsd-raw, raw, loop, bsd-loop, linux-sll, sll, \
                     ipv4, ip, ipv6, linux-sll2, sll2";

/// Resolves a link-type name or decimal DLT; the one `--link-type` value parser.
pub(crate) fn parse(input: &str) -> Result<LinkType, String> {
    let normalized = input.trim().to_ascii_lowercase();
    let link_type = match normalized.as_str() {
        "null" | "bsd-null" => Some(LinkType::NULL),
        "ethernet" => Some(LinkType::ETHERNET),
        "bsd-raw" => Some(LinkType::BSD_RAW),
        "raw" => Some(LinkType::RAW),
        "loop" | "bsd-loop" => Some(LinkType::LOOP),
        "linux-sll" | "sll" => Some(LinkType::LINUX_SLL),
        "ipv4" | "ip" => Some(LinkType::IPV4),
        "ipv6" => Some(LinkType::IPV6),
        "linux-sll2" | "sll2" => Some(LinkType::LINUX_SLL2),
        _ => normalized.parse::<u32>().ok().map(LinkType),
    };
    link_type.ok_or_else(|| {
        format!("unknown link type {input:?}; use one of {NAMES} or a decimal number")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_numbers_resolve_to_the_same_link_types() {
        for (name, number) in [
            ("null", 0),
            ("bsd-null", 0),
            ("ethernet", 1),
            ("bsd-raw", 12),
            ("RAW", 101),
            ("loop", 108),
            ("bsd-loop", 108),
            ("linux-sll", 113),
            ("sll", 113),
            ("ipv4", 228),
            ("ip", 228),
            ("ipv6", 229),
            ("linux-sll2", 276),
            ("sll2", 276),
            (" Ethernet ", 1),
        ] {
            assert_eq!(parse(name).unwrap(), LinkType(number), "{name}");
            assert_eq!(parse(&number.to_string()).unwrap(), LinkType(number));
        }
        // Numbers the tool names no root for still parse; callers decide what they accept.
        assert_eq!(parse("147").unwrap(), LinkType(147));
    }

    #[test]
    fn unknown_names_list_the_accepted_ones() {
        for input in ["fddi", "12x", "", "-1", "4294967296"] {
            let message = parse(input).unwrap_err();
            assert!(message.contains(&format!("unknown link type {input:?}")));
            assert!(message.contains("ethernet") && message.contains("linux-sll2"));
        }
    }
}
