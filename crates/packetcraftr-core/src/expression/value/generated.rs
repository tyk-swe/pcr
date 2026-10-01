// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::expression::Error;
use crate::field::FieldValue;

use super::super::syntax::{split_top_level_bounded, trim_at};
use super::Parser;
use super::scalar::parse_scalar;

/// The pattern `cyclic(...)` can emit before it would repeat: 26 uppercase,
/// 26 lowercase, and 10 digit positions of three bytes each.
pub(super) const CYCLIC_PATTERN_BYTES: usize = 26 * 26 * 10 * 3;

#[derive(Clone, Copy)]
pub(super) enum Generator {
    Repeat,
    Zeros,
    Cyclic,
}

impl Generator {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Repeat => "repeat",
            Self::Zeros => "zeros",
            Self::Cyclic => "cyclic",
        }
    }

    const fn arguments(self) -> usize {
        match self {
            Self::Repeat => 2,
            Self::Zeros | Self::Cyclic => 1,
        }
    }
}

/// `repeat(BYTE,COUNT)`, `zeros(COUNT)`, and `cyclic(LENGTH)`. The count is
/// charged to the expression's generated-byte budget before the bytes exist.
pub(super) fn parse_generated(
    base: usize,
    generator: Generator,
    body: &str,
    bounds: &mut Parser,
) -> Result<FieldValue, Error> {
    let name = generator.name();
    let arguments = body.strip_suffix(')').ok_or_else(|| Error::Syntax {
        offset: base,
        message: format!("unterminated {name}() generator"),
    })?;
    let arguments_base = base.saturating_add(name.len()).saturating_add(1);
    let parts = if arguments.trim().is_empty() {
        Vec::new()
    } else {
        split_top_level_bounded(arguments_base, arguments, ',', None)?
    };
    if parts.len() != generator.arguments() {
        return Err(Error::Syntax {
            offset: base,
            message: format!(
                "{name}() takes {} argument(s), got {}",
                generator.arguments(),
                parts.len()
            ),
        });
    }
    let integer = |index: usize| {
        let (part_base, text) = trim_at(parts[index].0, parts[index].1);
        match parse_scalar(part_base, text)? {
            FieldValue::Unsigned(value) => Ok((part_base, value)),
            _ => Err(Error::Syntax {
                offset: part_base,
                message: format!("{name}() arguments must be unsigned integers"),
            }),
        }
    };
    let bytes = match generator {
        Generator::Repeat => {
            let (byte_base, byte) = integer(0)?;
            let byte = u8::try_from(byte).map_err(|_| Error::Syntax {
                offset: byte_base,
                message: format!("repeat() byte {byte} is not in 0..=255"),
            })?;
            let count = bounds.reserve_generated(integer(1)?.1)?;
            vec![byte; count]
        }
        Generator::Zeros => vec![0; bounds.reserve_generated(integer(0)?.1)?],
        Generator::Cyclic => {
            let (length_base, length) = integer(0)?;
            if length > CYCLIC_PATTERN_BYTES as u64 {
                return Err(Error::Syntax {
                    offset: length_base,
                    message: format!(
                        "cyclic() length {length} exceeds the {CYCLIC_PATTERN_BYTES}-byte pattern"
                    ),
                });
            }
            cyclic_pattern(bounds.reserve_generated(length)?)
        }
    };
    Ok(FieldValue::Bytes(bytes.into()))
}

/// The leading `length` bytes of the Metasploit-style pattern `Aa0Aa1Aa2...`,
/// where every three-byte group is an uppercase letter, a lowercase letter and
/// a digit, with the digit varying fastest.
fn cyclic_pattern(length: usize) -> Vec<u8> {
    (0..length)
        .map(|offset| {
            let group = offset / 3;
            match offset % 3 {
                0 => b'A' + u8::try_from(group / 260 % 26).unwrap_or(0),
                1 => b'a' + u8::try_from(group / 10 % 26).unwrap_or(0),
                _ => b'0' + u8::try_from(group % 10).unwrap_or(0),
            }
        })
        .collect()
}
