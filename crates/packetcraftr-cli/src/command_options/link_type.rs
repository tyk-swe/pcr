// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Write as _;

use packetcraftr_core::frame::LinkType;

const NAMES: &[(LinkType, &str, &[&str])] = &[
    (LinkType::NULL, "null", &["bsd-null"]),
    (LinkType::ETHERNET, "ethernet", &[]),
    (LinkType::BSD_RAW, "bsd-raw", &[]),
    (LinkType::RAW, "raw", &[]),
    (LinkType::LOOP, "loop", &["bsd-loop"]),
    (LinkType::LINUX_SLL, "linux-sll", &["sll"]),
    (LinkType::IPV4, "ipv4", &["ip"]),
    (LinkType::IPV6, "ipv6", &[]),
    (LinkType::LINUX_SLL2, "linux-sll2", &["sll2"]),
];

pub(crate) fn names_help() -> String {
    let mut text = String::from("by name or number: ");
    for (index, &(link_type, name, _)) in NAMES.iter().enumerate() {
        if index > 0 {
            text.push_str(if index + 1 == NAMES.len() {
                ", or "
            } else {
                ", "
            });
        }
        let _ = write!(text, "{name} ({link_type})");
    }
    text.push_str("; any other decimal DLT is accepted as a number");
    text
}

pub(crate) fn parse(input: &str) -> Result<LinkType, String> {
    let value = input.trim();
    for &(link_type, name, aliases) in NAMES {
        if name.eq_ignore_ascii_case(value)
            || aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(value))
        {
            return Ok(link_type);
        }
    }
    if value.bytes().all(|byte| byte.is_ascii_digit())
        && let Ok(number) = value.parse::<u32>()
    {
        return Ok(LinkType(number));
    }
    let names = NAMES
        .iter()
        .flat_map(|&(_, name, aliases)| std::iter::once(name).chain(aliases.iter().copied()))
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "unknown link type {input:?}; use one of {names} or a decimal number"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_link_types_require_unsigned_decimal() {
        for invalid in ["+1", "-1", "0x1", "", "4294967296"] {
            assert!(parse(invalid).is_err(), "{invalid:?}");
        }
        assert_eq!(parse(" 4294967295 ").unwrap(), LinkType(u32::MAX));
        assert_eq!(parse("ETHERNET").unwrap(), LinkType::ETHERNET);
    }

    #[test]
    fn aliases_select_the_expected_capture_roots() {
        for (name, expected) in [
            ("bsd-null", LinkType::NULL),
            ("bsd-Loop", LinkType::LOOP),
            (" SLL ", LinkType::LINUX_SLL),
            ("Ip", LinkType::IPV4),
            ("sll2", LinkType::LINUX_SLL2),
            ("bsd-raw", LinkType::BSD_RAW),
            ("RAW", LinkType::RAW),
        ] {
            assert_eq!(parse(name).unwrap(), expected, "{name}");
        }
    }
}
