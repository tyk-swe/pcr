// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded option framing.

use super::super::{
    models::{Endianness, Error, Format},
    wire::{PCAPNG_OPTION_END, align_to_usize, decode_u16},
};

pub(super) fn visit_options<F>(
    options: &[u8],
    endianness: Endianness,
    context: &'static str,
    mut visitor: F,
) -> Result<(), Error>
where
    F: FnMut(u16, &[u8]) -> Result<(), Error>,
{
    let mut offset = 0_usize;
    while offset < options.len() {
        if options.len() - offset < 4 {
            return Err(Error::Truncated {
                context,
                expected: offset + 4,
                actual: options.len(),
            });
        }
        let code = decode_u16(endianness, &options[offset..offset + 2]);
        let length = usize::from(decode_u16(endianness, &options[offset + 2..offset + 4]));
        offset += 4;
        if code == PCAPNG_OPTION_END {
            if length != 0 {
                return Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "end-of-options marker has a non-zero length",
                });
            }
            if options[offset..].iter().any(|byte| *byte != 0) {
                return Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "non-zero bytes follow the end-of-options marker",
                });
            }
            return Ok(());
        }
        let padded_length = align_to_usize(length)?;
        let end = offset
            .checked_add(padded_length)
            .ok_or(Error::InvalidData {
                format: Format::PcapNg,
                reason: "option length overflow",
            })?;
        if end > options.len() {
            return Err(Error::Truncated {
                context,
                expected: end,
                actual: options.len(),
            });
        }
        visitor(code, &options[offset..offset + length])?;
        offset = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::super::models::{Endianness, Error, Format};
    use super::visit_options;

    #[test]
    fn options_visitor_decodes_little_endian_values_and_ignores_zero_padding() {
        let options = [1, 0, 3, 0, 0xaa, 0xbb, 0xcc, 0];
        let mut visited = Vec::new();
        visit_options(
            &options,
            Endianness::Little,
            "test options",
            |code, value| {
                visited.push((code, value.to_vec()));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(visited, vec![(1, vec![0xaa, 0xbb, 0xcc])]);
    }

    #[test]
    fn options_visitor_decodes_big_endian_values() {
        let options = [0, 2, 0, 1, 0x7f, 0, 0, 0];
        let mut visited = None;
        visit_options(&options, Endianness::Big, "test options", |code, value| {
            visited = Some((code, value.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(visited, Some((2, vec![0x7f])));
    }

    #[test]
    fn end_marker_stops_visiting_zero_filled_tail() {
        let options = [0, 0, 0, 0, 0, 0, 0, 0];
        let mut calls = 0;
        visit_options(&options, Endianness::Little, "test options", |_, _| {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 0);
    }

    #[test]
    fn truncated_option_header_and_value_are_rejected() {
        for options in [&[1, 0, 1][..], &[1, 0, 5, 0, 1, 2, 3, 4][..]] {
            assert!(matches!(
                visit_options(options, Endianness::Little, "test options", |_, _| Ok(())),
                Err(Error::Truncated {
                    context: "test options",
                    ..
                })
            ));
        }
    }

    #[test]
    fn malformed_end_markers_and_trailing_bytes_are_rejected() {
        for options in [&[0, 0, 1, 0, 0, 0, 0, 0][..], &[0, 0, 0, 0, 1, 0, 0, 0][..]] {
            assert!(matches!(
                visit_options(options, Endianness::Little, "test options", |_, _| Ok(())),
                Err(Error::InvalidData {
                    format: Format::PcapNg,
                    ..
                })
            ));
        }
    }

    #[test]
    fn option_padding_contents_are_ignored() {
        let options = [1, 0, 1, 0, 0xaa, 0, 1, 0];
        assert!(visit_options(&options, Endianness::Little, "test options", |_, _| Ok(())).is_ok());
    }
}
