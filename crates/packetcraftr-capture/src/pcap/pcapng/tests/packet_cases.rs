// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::Direction;
use crate::pcap::error::Error;
use crate::pcap::model::Endianness;
use crate::pcap::pcapng::packet::parse_packet_direction;
use crate::pcap::wire::PCAPNG_OPTION_EPB_FLAGS;

fn option(code: u16, value: &[u8], endianness: Endianness) -> Vec<u8> {
    let mut option = Vec::new();
    let length = u16::try_from(value.len()).unwrap();
    match endianness {
        Endianness::Little => {
            option.extend_from_slice(&code.to_le_bytes());
            option.extend_from_slice(&length.to_le_bytes());
        }
        Endianness::Big => {
            option.extend_from_slice(&code.to_be_bytes());
            option.extend_from_slice(&length.to_be_bytes());
        }
    }
    option.extend_from_slice(value);
    option.resize(option.len().next_multiple_of(4), 0);
    option
}

#[test]
fn absent_or_unknown_packet_flags_leave_direction_absent() {
    assert_eq!(
        parse_packet_direction(&[], Endianness::Little).unwrap(),
        None
    );
    assert_eq!(
        parse_packet_direction(
            &option(65_000, &[0, 0, 0, 0], Endianness::Little),
            Endianness::Little
        )
        .unwrap(),
        None
    );
}

#[test]
fn packet_direction_decodes_all_wire_values() {
    for (wire, expected) in [
        (0_u32, Direction::Unknown),
        (1, Direction::Inbound),
        (2, Direction::Outbound),
        (3, Direction::Unknown),
    ] {
        let value = wire.to_le_bytes();
        assert_eq!(
            parse_packet_direction(
                &option(PCAPNG_OPTION_EPB_FLAGS, &value, Endianness::Little),
                Endianness::Little
            )
            .unwrap(),
            Some(expected)
        );
    }
}

#[test]
fn packet_flags_require_exactly_four_bytes() {
    for value in [&[1, 0, 0][..], &[1, 0, 0, 0, 0][..]] {
        assert!(matches!(
            parse_packet_direction(
                &option(PCAPNG_OPTION_EPB_FLAGS, value, Endianness::Little),
                Endianness::Little
            ),
            Err(Error::InvalidData { .. })
        ));
    }
}

#[test]
fn duplicate_packet_flags_are_rejected() {
    let mut options = option(
        PCAPNG_OPTION_EPB_FLAGS,
        &1_u32.to_le_bytes(),
        Endianness::Little,
    );
    options.extend_from_slice(&option(
        PCAPNG_OPTION_EPB_FLAGS,
        &2_u32.to_le_bytes(),
        Endianness::Little,
    ));
    assert!(matches!(
        parse_packet_direction(&options, Endianness::Little),
        Err(Error::InvalidData { .. })
    ));
}
