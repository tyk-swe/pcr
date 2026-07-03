// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use super::error::{SpecError, SpecResult};

pub(crate) const MAX_HEX_INPUT_BYTES: usize = 2048;

pub(crate) fn parse_ip_address(value: &str) -> SpecResult<IpAddr> {
    value
        .parse::<IpAddr>()
        .map_err(|source| SpecError::IpAddressParse {
            value: value.to_string(),
            source,
        })
}

pub(crate) fn parse_hex_bytes(hex: &str) -> SpecResult<Vec<u8>> {
    let cleaned: String = hex.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let cleaned = if cleaned.starts_with("0x") || cleaned.starts_with("0X") {
        &cleaned[2..]
    } else {
        &cleaned
    };

    if !cleaned.len().is_multiple_of(2) {
        return Err(SpecError::HexStringOddLength);
    }

    let byte_len = cleaned.len() / 2;
    if byte_len > MAX_HEX_INPUT_BYTES {
        return Err(SpecError::HexStringTooLong {
            max_bytes: MAX_HEX_INPUT_BYTES,
        });
    }

    let mut bytes = Vec::new();
    for chunk in cleaned.as_bytes().chunks(2) {
        let high = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| SpecError::InvalidHexDigit {
                digit: chunk[0] as char,
            })?;
        let low = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| SpecError::InvalidHexDigit {
                digit: chunk[1] as char,
            })?;
        bytes.push(((high << 4) | low) as u8);
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_address_rejects_invalid_ipv4_and_preserves_value() {
        let err = parse_ip_address("999.0.2.1").unwrap_err();

        assert!(matches!(
            err,
            SpecError::IpAddressParse { ref value, .. } if value == "999.0.2.1"
        ));
    }

    #[test]
    fn parse_ip_address_rejects_empty_input() {
        let err = parse_ip_address("").unwrap_err();

        assert!(matches!(
            err,
            SpecError::IpAddressParse { ref value, .. } if value.is_empty()
        ));
    }

    #[test]
    fn parse_hex_bytes_ignores_ascii_whitespace() {
        assert_eq!(
            parse_hex_bytes("de ad\nbe\tef").unwrap(),
            [0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn parse_hex_bytes_accepts_upper_and_lower_prefixes() {
        assert_eq!(parse_hex_bytes("0xCAFE").unwrap(), [0xca, 0xfe]);
        assert_eq!(parse_hex_bytes("0Xcafe").unwrap(), [0xca, 0xfe]);
    }

    #[test]
    fn parse_hex_bytes_rejects_odd_length_after_cleanup() {
        let err = parse_hex_bytes("0xabc").unwrap_err();

        assert!(matches!(err, SpecError::HexStringOddLength));
    }

    #[test]
    fn parse_hex_bytes_reports_invalid_high_digit() {
        let err = parse_hex_bytes("zg").unwrap_err();

        assert!(matches!(err, SpecError::InvalidHexDigit { digit: 'z' }));
    }

    #[test]
    fn parse_hex_bytes_reports_invalid_low_digit() {
        let err = parse_hex_bytes("0g").unwrap_err();

        assert!(matches!(err, SpecError::InvalidHexDigit { digit: 'g' }));
    }

    #[test]
    fn parse_hex_bytes_accepts_empty_input() {
        assert_eq!(parse_hex_bytes("").unwrap(), Vec::<u8>::new());
        assert_eq!(parse_hex_bytes("0x").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn parse_hex_bytes_accepts_exact_max_and_rejects_too_long_input() {
        let exact = "aa".repeat(MAX_HEX_INPUT_BYTES);
        let too_long = "aa".repeat(MAX_HEX_INPUT_BYTES + 1);

        assert_eq!(parse_hex_bytes(&exact).unwrap().len(), MAX_HEX_INPUT_BYTES);
        assert!(matches!(
            parse_hex_bytes(&too_long).unwrap_err(),
            SpecError::HexStringTooLong {
                max_bytes: MAX_HEX_INPUT_BYTES
            }
        ));
    }
}
