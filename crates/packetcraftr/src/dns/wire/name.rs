// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical and compressed DNS name handling.

use packetcraftr_core::protocol::application::dns::name::{
    MAX_LABEL_LEN, MAX_NAME_LEN, decompress,
};

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
        if label.len() > MAX_LABEL_LEN {
            return Err(crate::dns::WireError::InvalidName {
                message: format!("contains a label longer than {MAX_LABEL_LEN} bytes"),
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
    if wire_length > MAX_NAME_LEN {
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
    limits: crate::dns::MessageLimits,
) -> Result<(crate::dns::Name, usize), crate::dns::WireError> {
    let expanded = decompress(message, offset, limits.max_name_pointers)?;
    Ok((
        crate::dns::Name {
            labels: expanded.labels,
        },
        expanded.resume,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn compressed_names_reject_self_and_forward_pointers() {
        assert!(matches!(
            decode_name(&[0xc0, 0], 0, crate::dns::MessageLimits::default()),
            Err(crate::dns::WireError::PointerLoop { offset: 0 })
        ));
        assert!(matches!(
            decode_name(&[0xc0, 2, 0], 0, crate::dns::MessageLimits::default()),
            Err(crate::dns::WireError::ForwardPointer {
                offset: 0,
                pointer: 2
            })
        ));
    }
}
