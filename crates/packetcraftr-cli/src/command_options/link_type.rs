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
