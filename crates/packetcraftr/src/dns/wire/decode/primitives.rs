// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fixed-width bounded reads used by DNS decoding stages.

use packetcraftr_core::protocol::application::dns::DecodeError;

pub(super) fn read_u16(
    message: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u16, crate::dns::error::WireError> {
    let bytes: [u8; 2] = message
        .get(offset..offset.saturating_add(2))
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .ok_or(crate::dns::error::WireError::Decode(
            DecodeError::TruncatedField {
                field,
                offset,
                needed: offset.saturating_add(2),
            },
        ))?;
    Ok(u16::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn truncation_reports_the_minimum_message_extent() {
        let error = read_u16(&[0; 4], 3, "test field").unwrap_err();
        assert!(matches!(
            error,
            crate::dns::error::WireError::Decode(DecodeError::TruncatedField {
                offset: 3,
                needed: 5,
                ..
            })
        ));
        assert_eq!(read_u16(&[0, 0, 0, 1, 2], 3, "test field").unwrap(), 0x0102);
    }
}
