// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::interface::parse_interface_description;
use crate::LinkType;
use crate::pcap::error::Error;
use crate::pcap::model::{Endianness, TimestampResolution};
use crate::pcap::wire::{PCAPNG_OPTION_IF_TSOFFSET, PCAPNG_OPTION_IF_TSRESOL};

fn body(options: &[u8]) -> Vec<u8> {
    let mut body = Vec::from([101, 0, 0, 0, 0xff, 0xff, 0, 0]);
    body.extend_from_slice(options);
    body
}

fn option(code: u16, value: &[u8]) -> Vec<u8> {
    let mut option = Vec::new();
    option.extend_from_slice(&code.to_le_bytes());
    option.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
    option.extend_from_slice(value);
    option.resize(option.len().next_multiple_of(4), 0);
    option
}

#[test]
fn interface_without_options_uses_default_timestamp_metadata() {
    let interface = parse_interface_description(&body(&[]), Endianness::Little).unwrap();
    assert_eq!(interface.link_type, LinkType::RAW);
    assert_eq!(interface.snap_len, 65_535);
    assert_eq!(
        interface.timestamp_resolution,
        TimestampResolution::Decimal(6)
    );
    assert_eq!(interface.timestamp_offset, 0);
}

#[test]
fn interface_timestamp_resolution_supports_decimal_and_binary_encodings() {
    for (encoded, expected) in [
        (9, TimestampResolution::Decimal(9)),
        (0x8a, TimestampResolution::Binary(10)),
    ] {
        let interface = parse_interface_description(
            &body(&option(PCAPNG_OPTION_IF_TSRESOL, &[encoded])),
            Endianness::Little,
        )
        .unwrap();
        assert_eq!(interface.timestamp_resolution, expected);
    }
}

#[test]
fn interface_timestamp_offset_preserves_negative_values() {
    let offset = -1_234_i64;
    let interface = parse_interface_description(
        &body(&option(PCAPNG_OPTION_IF_TSOFFSET, &offset.to_le_bytes())),
        Endianness::Little,
    )
    .unwrap();
    assert_eq!(interface.timestamp_offset, offset);
}

#[test]
fn short_interface_description_is_rejected() {
    assert!(matches!(
        parse_interface_description(&[0; 7], Endianness::Little),
        Err(Error::InvalidData { .. })
    ));
}

#[test]
fn duplicate_timestamp_options_are_rejected() {
    for code in [PCAPNG_OPTION_IF_TSRESOL, PCAPNG_OPTION_IF_TSOFFSET] {
        let value = if code == PCAPNG_OPTION_IF_TSRESOL {
            vec![6]
        } else {
            0_i64.to_le_bytes().to_vec()
        };
        let mut options = option(code, &value);
        options.extend_from_slice(&option(code, &value));
        assert!(matches!(
            parse_interface_description(&body(&options), Endianness::Little),
            Err(Error::InvalidData { .. })
        ));
    }
}

#[test]
fn timestamp_options_require_their_exact_wire_widths() {
    for (code, value) in [
        (PCAPNG_OPTION_IF_TSRESOL, vec![1, 2]),
        (PCAPNG_OPTION_IF_TSOFFSET, vec![0; 7]),
    ] {
        assert!(matches!(
            parse_interface_description(&body(&option(code, &value)), Endianness::Little),
            Err(Error::InvalidData { .. })
        ));
    }
}

#[test]
fn unknown_interface_options_are_ignored() {
    assert!(
        parse_interface_description(&body(&option(65_000, &[1, 2, 3])), Endianness::Little).is_ok()
    );
}
