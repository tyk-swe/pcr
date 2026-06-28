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
    fn parse_ip_address_accepts_ip_literals_and_rejects_invalid_input() {
        for input in ["192.168.1.1", "2001:db8::1", "::1"] {
            assert_eq!(
                parse_ip_address(input).unwrap(),
                input.parse::<IpAddr>().unwrap()
            );
        }

        for input in ["not-an-ip", "", "256.1.1.1"] {
            assert!(parse_ip_address(input).is_err(), "{input}");
        }
    }

    #[test]
    fn parse_hex_bytes_accepts_common_renderings() {
        let cases = [
            ("48656c6c6f", b"Hello".to_vec()),
            ("DEADBEEF", vec![0xde, 0xad, 0xbe, 0xef]),
            ("DeAdBeEf", vec![0xde, 0xad, 0xbe, 0xef]),
            ("48 65\t6c\n6c\r6f", b"Hello".to_vec()),
            ("0xDEADBEEF", vec![0xde, 0xad, 0xbe, 0xef]),
            ("", Vec::new()),
            ("    ", Vec::new()),
            ("ff", vec![0xff]),
        ];

        for (input, expected) in cases {
            assert_eq!(parse_hex_bytes(input).unwrap(), expected, "{input:?}");
        }
    }

    #[test]
    fn parse_hex_bytes_rejects_malformed_input() {
        assert!(matches!(
            parse_hex_bytes("123"),
            Err(SpecError::HexStringOddLength)
        ));

        for input in ["12zz", "12!@"] {
            assert!(matches!(
                parse_hex_bytes(input),
                Err(SpecError::InvalidHexDigit { .. })
            ));
        }
    }

    #[test]
    fn parse_hex_bytes_enforces_max_decoded_size() {
        let max = "ff".repeat(MAX_HEX_INPUT_BYTES);
        assert_eq!(parse_hex_bytes(&max).unwrap().len(), MAX_HEX_INPUT_BYTES);

        let too_long = "ff".repeat(MAX_HEX_INPUT_BYTES + 1);
        assert!(matches!(
            parse_hex_bytes(&too_long),
            Err(SpecError::HexStringTooLong { .. })
        ));
    }
}
