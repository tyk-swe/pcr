// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::protocol::application::dns::{Error, MAX_LABEL_LEN, MAX_NAME_LEN};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Decompressed {
    pub(super) labels: Vec<Bytes>,
    /// For a compressed name, `resume` is two bytes past the *first* pointer.
    pub(super) resume: usize,
}

/// The loop-detection scan is quadratic in `max_pointers`, so pass a small constant.
pub(super) fn decompress(
    message: &Bytes,
    offset: usize,
    max_pointers: usize,
) -> Result<Decompressed, Error> {
    let mut cursor = offset;
    let mut resume = None;
    let mut labels = Vec::new();
    let mut visited = Vec::new();
    let mut pointers = 0usize;
    let mut wire_length = 1usize;
    loop {
        // Every `saturating_add` below is reached only after this `get`
        // succeeded, so `cursor < message.len()` and the sums cannot saturate.
        let length = *message
            .get(cursor)
            .ok_or(Error::TruncatedLabelLength { offset: cursor })?;
        match length & 0xc0 {
            0xc0 => {
                let second = *message
                    .get(cursor.saturating_add(1))
                    .ok_or(Error::TruncatedPointer { offset: cursor })?;
                let pointer = (usize::from(length & 0x3f) << 8) | usize::from(second);
                if pointer >= message.len() {
                    return Err(Error::PointerOutOfBounds {
                        pointer,
                        length: message.len(),
                    });
                }
                if pointer == cursor {
                    return Err(Error::SelfPointer { offset: cursor });
                }
                if pointer > cursor {
                    return Err(Error::ForwardPointer {
                        offset: cursor,
                        pointer,
                    });
                }
                pointers = pointers.saturating_add(1);
                if pointers > max_pointers {
                    return Err(Error::PointerLimit {
                        limit: max_pointers,
                    });
                }
                if visited.contains(&pointer) {
                    return Err(Error::PointerLoop { offset: pointer });
                }
                visited.push(pointer);
                resume.get_or_insert(cursor.saturating_add(2));
                cursor = pointer;
            }
            0 => {
                let length_offset = cursor;
                cursor = cursor.saturating_add(1);
                if length == 0 {
                    return Ok(Decompressed {
                        labels,
                        resume: resume.unwrap_or(cursor),
                    });
                }
                let length = usize::from(length);
                if length > MAX_LABEL_LEN {
                    return Err(Error::LabelTooLong {
                        offset: length_offset,
                        actual: length,
                    });
                }
                let end = cursor.saturating_add(length);
                let label = message.get(cursor..end).ok_or(Error::TruncatedLabel {
                    offset: cursor,
                    end,
                })?;
                wire_length = wire_length
                    .checked_add(length)
                    .and_then(|total| total.checked_add(1))
                    .ok_or(Error::NameTooLong)?;
                if wire_length > MAX_NAME_LEN {
                    return Err(Error::NameTooLong);
                }
                labels.push(message.slice_ref(label));
                cursor = end;
            }
            _ => return Err(Error::ReservedLabelLength { offset: cursor }),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn an_offset_is_never_expanded_twice() {
        let message = [0, 1, b'a', 0xc0, 0x01, 0xc0, 0x01];
        assert!(matches!(
            decompress(&Bytes::copy_from_slice(&message), 5, 32),
            Err(Error::PointerLoop { offset: 1 })
        ));
    }

    #[test]
    fn reserved_and_truncated_encodings_are_refused() {
        assert!(matches!(
            decompress(&Bytes::from_static(&[0x40, 0]), 0, 32),
            Err(Error::ReservedLabelLength { offset: 0 })
        ));
        assert!(matches!(
            decompress(&Bytes::from_static(&[0x80, 0]), 0, 32),
            Err(Error::ReservedLabelLength { offset: 0 })
        ));
        assert!(matches!(
            decompress(&Bytes::from_static(&[]), 0, 32),
            Err(Error::TruncatedLabelLength { offset: 0 })
        ));
        assert!(matches!(
            decompress(&Bytes::from_static(&[0xc0]), 0, 32),
            Err(Error::TruncatedPointer { offset: 0 })
        ));
        assert!(matches!(
            decompress(&Bytes::from_static(&[3, b'a']), 0, 32),
            Err(Error::TruncatedLabel { offset: 1, end: 4 })
        ));
    }
}
