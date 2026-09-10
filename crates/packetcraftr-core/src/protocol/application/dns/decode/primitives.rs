// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fixed-width bounded reads used by DNS decoding stages.

/// Reads the big-endian `u16` at `offset`.
///
/// Fails with [`DecodeError::TruncatedField`] naming `field` when the message
/// ends before the value does.
///
/// [`DecodeError::TruncatedField`]: super::super::DecodeError::TruncatedField
pub fn read_u16(
    message: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u16, super::super::DecodeError> {
    let bytes: [u8; 2] = message
        .get(offset..offset.saturating_add(2))
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .ok_or(super::super::DecodeError::TruncatedField {
            field,
            offset,
            needed: offset.saturating_add(2),
        })?;
    Ok(u16::from_be_bytes(bytes))
}

/// Reads the big-endian `u32` at `offset`.
///
/// Fails with [`DecodeError::TruncatedField`] naming `field` when the message
/// ends before the value does.
///
/// [`DecodeError::TruncatedField`]: super::super::DecodeError::TruncatedField
pub fn read_u32(
    message: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u32, super::super::DecodeError> {
    let bytes: [u8; 4] = message
        .get(offset..offset.saturating_add(4))
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .ok_or(super::super::DecodeError::TruncatedField {
            field,
            offset,
            needed: offset.saturating_add(4),
        })?;
    Ok(u32::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_reports_the_minimum_message_extent() {
        let error = read_u16(&[0; 4], 3, "test field").unwrap_err();
        assert!(matches!(
            error,
            super::super::super::DecodeError::TruncatedField {
                offset: 3,
                needed: 5,
                ..
            }
        ));
        assert_eq!(read_u16(&[0, 0, 0, 1, 2], 3, "test field").unwrap(), 0x0102);
        assert_eq!(
            read_u32(&[0, 1, 2, 3, 4], 1, "test field").unwrap(),
            0x0102_0304
        );
    }
}
