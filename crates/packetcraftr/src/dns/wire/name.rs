// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical and compressed DNS name handling.

use bytes::Bytes;

/// Canonicalizes a bounded ASCII DNS name for wire construction and
/// case-insensitive correlation. The returned form always has a trailing dot.
pub fn canonical_query_name(value: &str) -> Result<String, crate::dns::WireError> {
    if value == "." {
        return Ok(".".to_owned());
    }
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() {
        return Err(crate::dns::WireError::InvalidName {
            message: "must not be empty".to_owned(),
        });
    }
    let mut wire_length = 1usize;
    for label in value.split('.') {
        if label.is_empty() {
            return Err(crate::dns::WireError::InvalidName {
                message: "contains an empty label".to_owned(),
            });
        }
        if label.len() > 63 {
            return Err(crate::dns::WireError::InvalidName {
                message: "contains a label longer than 63 bytes".to_owned(),
            });
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'*'))
        {
            return Err(crate::dns::WireError::InvalidName {
                message: "labels must use ASCII letters, digits, hyphens, underscores, or wildcard asterisks"
                    .to_owned(),
            });
        }
        wire_length = wire_length
            .checked_add(label.len())
            .and_then(|length| length.checked_add(1))
            .ok_or(crate::dns::WireError::NameTooLong)?;
    }
    if wire_length > 255 {
        return Err(crate::dns::WireError::NameTooLong);
    }
    Ok(format!("{}.", value.to_ascii_lowercase()))
}

pub(super) fn encode_name(name: &str, output: &mut Vec<u8>) -> Result<(), crate::dns::WireError> {
    if name == "." {
        output.push(0);
        return Ok(());
    }
    for label in name.trim_end_matches('.').split('.') {
        output.push(u8::try_from(label.len()).map_err(|_| crate::dns::WireError::NameTooLong)?);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

pub(super) fn decode_name(
    message: &[u8],
    offset: usize,
    limits: crate::dns::Limits,
) -> Result<(crate::dns::Name, usize), crate::dns::WireError> {
    let mut cursor = offset;
    let mut resume = None;
    let mut labels = Vec::new();
    let mut visited = Vec::new();
    let mut pointer_count = 0usize;
    let mut wire_length = 1usize;
    loop {
        let length = *message
            .get(cursor)
            .ok_or(crate::dns::WireError::TruncatedField {
                field: "name label length",
                offset: cursor,
            })?;
        if length & 0xc0 == 0xc0 {
            let second = *cursor
                .checked_add(1)
                .and_then(|next| message.get(next))
                .ok_or(crate::dns::WireError::TruncatedPointer { offset: cursor })?;
            let pointer = usize::from((u16::from(length & 0x3f) << 8) | u16::from(second));
            if pointer >= message.len() {
                return Err(crate::dns::WireError::PointerOutOfBounds {
                    pointer,
                    length: message.len(),
                });
            }
            if pointer == cursor {
                return Err(crate::dns::WireError::PointerLoop { offset: pointer });
            }
            if pointer > cursor {
                return Err(crate::dns::WireError::ForwardPointer {
                    offset: cursor,
                    pointer,
                });
            }
            pointer_count = pointer_count.saturating_add(1);
            if pointer_count > limits.max_name_pointers {
                return Err(crate::dns::WireError::PointerLimit {
                    limit: limits.max_name_pointers,
                });
            }
            if visited.contains(&pointer) {
                return Err(crate::dns::WireError::PointerLoop { offset: pointer });
            }
            visited.push(pointer);
            let resume_offset = cursor
                .checked_add(2)
                .ok_or(crate::dns::WireError::TruncatedPointer { offset: cursor })?;
            resume.get_or_insert(resume_offset);
            cursor = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(crate::dns::WireError::ReservedLabelLength { offset: cursor });
        }
        let length_offset = cursor;
        cursor = cursor.saturating_add(1);
        if length == 0 {
            let next = resume.unwrap_or(cursor);
            return Ok((crate::dns::Name { labels }, next));
        }
        let length = usize::from(length);
        if length > 63 {
            return Err(crate::dns::WireError::LabelTooLong {
                offset: length_offset,
                actual: length,
            });
        }
        let label_end = cursor.saturating_add(length);
        let label =
            message
                .get(cursor..label_end)
                .ok_or(crate::dns::WireError::TruncatedField {
                    field: "name label",
                    offset: cursor,
                })?;
        wire_length = wire_length
            .checked_add(length)
            .and_then(|length| length.checked_add(1))
            .ok_or(crate::dns::WireError::NameTooLong)?;
        if wire_length > 255 {
            return Err(crate::dns::WireError::NameTooLong);
        }
        labels.push(Bytes::copy_from_slice(label));
        cursor = label_end;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn compressed_names_reject_self_and_forward_pointers() {
        assert!(matches!(
            decode_name(&[0xc0, 0], 0, crate::dns::Limits::default()),
            Err(crate::dns::WireError::PointerLoop { offset: 0 })
        ));
        assert!(matches!(
            decode_name(&[0xc0, 2, 0], 0, crate::dns::Limits::default()),
            Err(crate::dns::WireError::ForwardPointer {
                offset: 0,
                pointer: 2
            })
        ));
    }
}
