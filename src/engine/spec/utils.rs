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
