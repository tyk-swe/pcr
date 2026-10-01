// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::expression::Error;
use crate::field::{FieldValue, parse_mac};

pub(super) fn parse_scalar(base: usize, input: &str) -> Result<FieldValue, Error> {
    if input.eq_ignore_ascii_case("true") {
        return Ok(FieldValue::Bool(true));
    }
    if input.eq_ignore_ascii_case("false") {
        return Ok(FieldValue::Bool(false));
    }
    if let Ok(value) = Ipv4Addr::from_str(input) {
        return Ok(FieldValue::Ipv4(value));
    }
    if let Ok(value) = Ipv6Addr::from_str(input) {
        return Ok(FieldValue::Ipv6(value));
    }
    if let Some(digits) = strip_hex_prefix(input) {
        return parse_radix_integer(base, input, digits, 16, "hexadecimal");
    }
    // Binary and octal prefixes only claim digit-only tails, so text such as
    // a MAC address that begins `0b:` is left to the later parsers.
    for (prefixes, radix, name) in [(["0b", "0B"], 2, "binary"), (["0o", "0O"], 8, "octal")] {
        if let Some(digits) = prefixes
            .iter()
            .find_map(|prefix| input.strip_prefix(prefix))
            && !digits.is_empty()
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'_')
        {
            return parse_radix_integer(base, input, digits, radix, name);
        }
    }
    if let Some(value) = parse_separated_decimal(base, input)? {
        return Ok(value);
    }
    if let Ok(value) = input.parse::<u64>() {
        return Ok(FieldValue::Unsigned(value));
    }
    if let Ok(value) = input.parse::<i64>() {
        return Ok(FieldValue::Signed(value));
    }
    if let Some(mac) = parse_mac(input) {
        return Ok(FieldValue::Mac(mac));
    }
    Ok(FieldValue::Text(input.to_owned()))
}

fn parse_radix_integer(
    base: usize,
    input: &str,
    digits: &str,
    radix: u32,
    name: &str,
) -> Result<FieldValue, Error> {
    let invalid = || Error::Syntax {
        offset: base,
        message: format!("invalid {name} integer {input}"),
    };
    let digits = without_separators(digits, radix).ok_or_else(invalid)?;
    u64::from_str_radix(&digits, radix)
        .map(FieldValue::Unsigned)
        .map_err(|_| invalid())
}

/// Decimal integers spelled with `_` separators, such as `1_000`. A token made
/// only of digits and underscores that misplaces one is an error rather than
/// text, so a typo cannot silently become a string.
fn parse_separated_decimal(base: usize, input: &str) -> Result<Option<FieldValue>, Error> {
    let (negative, digits) = match input.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, input),
    };
    if !digits.contains('_')
        || !digits.bytes().any(|byte| byte.is_ascii_digit())
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'_')
    {
        return Ok(None);
    }
    let invalid = || Error::Syntax {
        offset: base,
        message: format!("invalid decimal integer {input}"),
    };
    let digits = without_separators(digits, 10).ok_or_else(invalid)?;
    let value = if negative {
        format!("-{digits}")
            .parse::<i64>()
            .map(FieldValue::Signed)
            .map_err(|_| invalid())?
    } else {
        digits
            .parse::<u64>()
            .map(FieldValue::Unsigned)
            .map_err(|_| invalid())?
    };
    Ok(Some(value))
}

/// The digits of `text` without its `_` separators; `None` when a separator
/// is not between two digits, or any other character is not a digit in `radix`.
fn without_separators(text: &str, radix: u32) -> Option<String> {
    let bytes = text.as_bytes();
    let mut digits = String::with_capacity(text.len());
    for (offset, byte) in bytes.iter().copied().enumerate() {
        if byte == b'_' {
            let between_digits = offset
                .checked_sub(1)
                .and_then(|previous| bytes.get(previous))
                .zip(bytes.get(offset.saturating_add(1)))
                .is_some_and(|(before, after)| *before != b'_' && *after != b'_');
            if !between_digits {
                return None;
            }
        } else if char::from(byte).is_digit(radix) {
            digits.push(char::from(byte));
        } else {
            return None;
        }
    }
    (!digits.is_empty()).then_some(digits)
}

fn strip_hex_prefix(input: &str) -> Option<&str> {
    input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
}
