// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical and compressed DNS name handling.

use bytes::Bytes;

use super::super::error::WireError as DnsWireError;
use super::super::model::{Limits as DnsLimits, Name as DnsName};

/// Canonicalizes a bounded ASCII DNS name for wire construction and
/// case-insensitive correlation. The returned form always has a trailing dot.
pub fn canonical_query_name(value: &str) -> Result<String, DnsWireError> {
    if value == "." {
        return Ok(".".to_owned());
    }
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() {
        return Err(DnsWireError::InvalidName {
            message: "must not be empty".to_owned(),
        });
    }
    let mut wire_length = 1usize;
    for label in value.split('.') {
        if label.is_empty() {
            return Err(DnsWireError::InvalidName {
                message: "contains an empty label".to_owned(),
            });
        }
        if label.len() > 63 {
            return Err(DnsWireError::InvalidName {
                message: "contains a label longer than 63 bytes".to_owned(),
            });
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'*'))
        {
            return Err(DnsWireError::InvalidName {
                message: "labels must use ASCII letters, digits, hyphens, underscores, or wildcard asterisks"
                    .to_owned(),
            });
        }
        wire_length = wire_length
            .checked_add(label.len() + 1)
            .ok_or(DnsWireError::NameTooLong)?;
    }
    if wire_length > 255 {
        return Err(DnsWireError::NameTooLong);
    }
    Ok(format!("{}.", value.to_ascii_lowercase()))
}

pub(super) fn encode_name(name: &str, output: &mut Vec<u8>) -> Result<(), DnsWireError> {
    if name == "." {
        output.push(0);
        return Ok(());
    }
    for label in name.trim_end_matches('.').split('.') {
        output.push(u8::try_from(label.len()).map_err(|_| DnsWireError::NameTooLong)?);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

pub(super) fn decode_name(
    message: &[u8],
    offset: usize,
    limits: DnsLimits,
) -> Result<(DnsName, usize), DnsWireError> {
    let mut cursor = offset;
    let mut resume = None;
    let mut labels = Vec::new();
    let mut visited = Vec::new();
    let mut pointer_count = 0usize;
    let mut wire_length = 1usize;
    loop {
        let length = *message.get(cursor).ok_or(DnsWireError::TruncatedField {
            field: "name label length",
            offset: cursor,
        })?;
        if length & 0xc0 == 0xc0 {
            let second = *message
                .get(cursor + 1)
                .ok_or(DnsWireError::TruncatedPointer { offset: cursor })?;
            let pointer = usize::from((u16::from(length & 0x3f) << 8) | u16::from(second));
            if pointer >= message.len() {
                return Err(DnsWireError::PointerOutOfBounds {
                    pointer,
                    length: message.len(),
                });
            }
            if pointer == cursor {
                return Err(DnsWireError::PointerLoop { offset: pointer });
            }
            if pointer > cursor {
                return Err(DnsWireError::ForwardPointer {
                    offset: cursor,
                    pointer,
                });
            }
            pointer_count += 1;
            if pointer_count > limits.max_name_pointers {
                return Err(DnsWireError::PointerLimit {
                    limit: limits.max_name_pointers,
                });
            }
            if visited.contains(&pointer) {
                return Err(DnsWireError::PointerLoop { offset: pointer });
            }
            visited.push(pointer);
            resume.get_or_insert(cursor + 2);
            cursor = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsWireError::ReservedLabelLength { offset: cursor });
        }
        cursor += 1;
        if length == 0 {
            let next = resume.unwrap_or(cursor);
            return Ok((DnsName { labels }, next));
        }
        let length = usize::from(length);
        if length > 63 {
            return Err(DnsWireError::LabelTooLong {
                offset: cursor - 1,
                actual: length,
            });
        }
        let label = message.get(cursor..cursor.saturating_add(length)).ok_or(
            DnsWireError::TruncatedField {
                field: "name label",
                offset: cursor,
            },
        )?;
        wire_length = wire_length
            .checked_add(length + 1)
            .ok_or(DnsWireError::NameTooLong)?;
        if wire_length > 255 {
            return Err(DnsWireError::NameTooLong);
        }
        labels.push(Bytes::copy_from_slice(label));
        cursor += length;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_names_reject_self_and_forward_pointers() {
        assert!(matches!(
            decode_name(&[0xc0, 0], 0, DnsLimits::default()),
            Err(DnsWireError::PointerLoop { offset: 0 })
        ));
        assert!(matches!(
            decode_name(&[0xc0, 2, 0], 0, DnsLimits::default()),
            Err(DnsWireError::ForwardPointer {
                offset: 0,
                pointer: 2
            })
        ));
    }
}
