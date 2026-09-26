// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::protocol::application::dns::{MAX_LABEL_LEN, MAX_NAME_LEN};

/// Canonicalizes a bounded ASCII DNS name for wire construction and
/// case-insensitive correlation. The returned form always has a trailing dot.
pub fn canonical_query_name(value: &str) -> Result<String, super::Error> {
    if value == "." {
        return Ok(".".to_owned());
    }
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() {
        return Err(super::Error::InvalidName {
            message: "must not be empty".to_owned(),
        });
    }
    let mut wire_length = 1usize;
    for label in value.split('.') {
        if label.is_empty() {
            return Err(super::Error::InvalidName {
                message: "contains an empty label".to_owned(),
            });
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(super::Error::InvalidName {
                message: format!("contains a label longer than {MAX_LABEL_LEN} bytes"),
            });
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'*'))
        {
            return Err(super::Error::InvalidName {
                message: "labels must use ASCII letters, digits, hyphens, underscores, or wildcard asterisks"
                    .to_owned(),
            });
        }
        wire_length = wire_length
            .checked_add(label.len())
            .and_then(|length| length.checked_add(1))
            .ok_or(super::Error::NameTooLong)?;
    }
    if wire_length > MAX_NAME_LEN {
        return Err(super::Error::NameTooLong);
    }
    Ok(format!("{}.", value.to_ascii_lowercase()))
}
