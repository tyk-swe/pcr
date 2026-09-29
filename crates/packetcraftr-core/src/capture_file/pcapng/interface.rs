// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::frame::LinkType;

use super::options::{parse_options, unique_option};
use crate::capture_file::{
    error::Error,
    format::{Endianness, Format, TimestampResolution},
    header::{Interface, PcapNgOption},
    wire::{
        DEFAULT_TIMESTAMP_RESOLUTION, PCAPNG_OPTION_IF_TSOFFSET, PCAPNG_OPTION_IF_TSRESOL,
        decode_i64, decode_u16, decode_u32,
    },
};

pub(in crate::capture_file) fn parse_interface_description(
    body: &[u8],
    endianness: Endianness,
) -> Result<(Interface, Vec<PcapNgOption>), Error> {
    if body.len() < 8 {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "interface description block is shorter than 8 bytes",
        });
    }
    let link_type = LinkType(u32::from(decode_u16(endianness, body)?));
    // the length guard leaves at least eight bytes
    let snap_len = decode_u32(endianness, &body[4..8])?;
    let options = parse_options(&body[8..], endianness, "pcapng interface options")?;
    let timestamp_resolution = match unique_option(
        &options,
        PCAPNG_OPTION_IF_TSRESOL,
        "if_tsresol option appears more than once",
    )? {
        None => DEFAULT_TIMESTAMP_RESOLUTION,
        Some(&[tsresol]) => TimestampResolution::from_tsresol(tsresol),
        Some(_) => {
            return Err(Error::InvalidData {
                format: Format::PcapNg,
                reason: "if_tsresol option must contain one byte",
            });
        }
    };
    let timestamp_offset = match unique_option(
        &options,
        PCAPNG_OPTION_IF_TSOFFSET,
        "if_tsoffset option appears more than once",
    )? {
        None => 0,
        Some(value) if value.len() == 8 => decode_i64(endianness, value)?,
        Some(_) => {
            return Err(Error::InvalidData {
                format: Format::PcapNg,
                reason: "if_tsoffset option must contain eight bytes",
            });
        }
    };
    let interface = Interface {
        link_type,
        snap_len,
        timestamp_resolution,
        timestamp_offset,
    };
    Ok((interface, options))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(options: &[u8]) -> Result<(Interface, Vec<PcapNgOption>), Error> {
        let mut body = vec![1, 0, 0, 0, 0xff, 0xff, 0, 0];
        body.extend_from_slice(options);
        parse_interface_description(&body, Endianness::Little)
    }

    #[test]
    fn timestamp_options_set_the_interface_clock_and_stay_in_the_option_list() {
        let (interface, options) = parse(&[
            12, 0, 2, 0, b'o', b's', 0, 0, // if_os
            9, 0, 1, 0, 0x86, 0, 0, 0, // if_tsresol: 2^-6
            14, 0, 8, 0, 0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // if_tsoffset: -5
        ])
        .unwrap();
        assert_eq!(
            interface.timestamp_resolution,
            TimestampResolution::Binary(6)
        );
        assert_eq!(interface.timestamp_offset, -5);
        let codes: Vec<_> = options.iter().map(|option| option.code).collect();
        assert_eq!(codes, [12, 9, 14]);

        let (interface, options) = parse(&[]).unwrap();
        assert_eq!(interface.timestamp_resolution, DEFAULT_TIMESTAMP_RESOLUTION);
        assert_eq!(interface.timestamp_offset, 0);
        assert!(options.is_empty());
    }

    #[test]
    fn repeated_or_mis_sized_timestamp_options_are_rejected() {
        let resolution = [9, 0, 1, 0, 6, 0, 0, 0];
        let offset = [14, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let cases: [(Vec<u8>, &str); 4] = [
            (
                [resolution.as_slice(), &resolution].concat(),
                "if_tsresol option appears more than once",
            ),
            (
                [offset.as_slice(), &offset].concat(),
                "if_tsoffset option appears more than once",
            ),
            (
                vec![9, 0, 2, 0, 6, 6, 0, 0],
                "if_tsresol option must contain one byte",
            ),
            (
                vec![14, 0, 4, 0, 0, 0, 0, 0],
                "if_tsoffset option must contain eight bytes",
            ),
        ];
        for (options, expected) in cases {
            assert!(
                matches!(
                    parse(&options),
                    Err(Error::InvalidData { format: Format::PcapNg, reason }) if reason == expected
                ),
                "{expected}"
            );
        }
    }

    #[test]
    fn a_malformed_option_list_is_reported_before_a_malformed_timestamp_option() {
        let bad_resolution = vec![9, 0, 2, 0, 6, 6, 0, 0];
        let repeated_offset = [[14, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0]; 2].concat();
        for timestamp_error in [bad_resolution, repeated_offset] {
            assert!(matches!(
                parse(&[timestamp_error.as_slice(), &[1, 0]].concat()),
                Err(Error::Truncated {
                    context: "pcapng interface options",
                    ..
                })
            ));
            assert!(matches!(
                parse(&[timestamp_error.as_slice(), &[0, 0, 0, 0, 1, 0, 0, 0]].concat()),
                Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "non-zero bytes follow the end-of-options marker",
                })
            ));
        }
    }

    #[test]
    fn a_body_shorter_than_the_fixed_fields_is_rejected() {
        for length in 0..8 {
            assert!(
                matches!(
                    parse_interface_description(&vec![0; length], Endianness::Little),
                    Err(Error::InvalidData {
                        format: Format::PcapNg,
                        reason: "interface description block is shorter than 8 bytes",
                    })
                ),
                "{length} bytes"
            );
        }
    }
}
