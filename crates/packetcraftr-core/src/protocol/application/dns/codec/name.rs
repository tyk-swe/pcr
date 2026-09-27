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

    fn labels(expanded: &Decompressed) -> Vec<&[u8]> {
        expanded.labels.iter().map(Bytes::as_ref).collect()
    }

    #[test]
    fn an_uncompressed_name_resumes_after_its_root_label() {
        let message = [1, b'a', 3, b'b', b'c', b'd', 0, 0xff];
        let expanded = decompress(&Bytes::copy_from_slice(&message), 0, 32).expect("bounded name");
        assert_eq!(labels(&expanded), vec![b"a".as_slice(), b"bcd".as_slice()]);
        assert_eq!(expanded.resume, 7);
    }

    #[test]
    fn a_root_name_expands_to_no_labels() {
        let expanded = decompress(&Bytes::from_static(&[0]), 0, 32).expect("bounded name");
        assert!(expanded.labels.is_empty());
        assert_eq!(expanded.resume, 1);
    }

    #[test]
    fn a_compressed_name_resumes_past_its_first_pointer() {
        let message = [1, b'a', 0, 1, b'b', 0xc0, 0x00, 0xff];
        let expanded = decompress(&Bytes::copy_from_slice(&message), 3, 32).expect("bounded name");
        assert_eq!(labels(&expanded), vec![b"b".as_slice(), b"a".as_slice()]);
        assert_eq!(expanded.resume, 7);
    }

    #[test]
    fn label_octets_are_preserved_exactly() {
        let message = [3, b'a', 0x20, 0xff, 0];
        let expanded = decompress(&Bytes::copy_from_slice(&message), 0, 32).expect("bounded name");
        assert_eq!(labels(&expanded), vec![[b'a', 0x20, 0xff].as_slice()]);
    }

    #[test]
    fn pointers_must_address_a_strictly_earlier_offset() {
        assert!(matches!(
            decompress(&Bytes::from_static(&[0xc0, 0x00]), 0, 32),
            Err(Error::SelfPointer { offset: 0 })
        ));
        assert!(matches!(
            decompress(&Bytes::from_static(&[0xc0, 0x02, 0x00]), 0, 32),
            Err(Error::ForwardPointer {
                offset: 0,
                pointer: 2
            })
        ));
        assert!(matches!(
            decompress(&Bytes::from_static(&[0xc0, 0x09]), 0, 32),
            Err(Error::PointerOutOfBounds {
                pointer: 9,
                length: 2
            })
        ));
    }

    #[test]
    fn an_offset_is_never_expanded_twice() {
        let message = [0, 1, b'a', 0xc0, 0x01, 0xc0, 0x01];
        assert!(matches!(
            decompress(&Bytes::copy_from_slice(&message), 5, 32),
            Err(Error::PointerLoop { offset: 1 })
        ));
    }

    #[test]
    fn the_pointer_ceiling_bounds_the_hop_count() {
        let mut message = vec![0u8];
        let mut previous = 0usize;
        for _ in 0..33 {
            let offset = message.len();
            let pointer = u16::try_from(previous).expect("small offset") | 0xc000;
            message.extend_from_slice(&pointer.to_be_bytes());
            previous = offset;
        }
        assert!(matches!(
            decompress(&Bytes::copy_from_slice(&message), previous, 32),
            Err(Error::PointerLimit { limit: 32 })
        ));
        assert!(decompress(&Bytes::copy_from_slice(&message), previous, 33).is_ok());
        let entry = previous - 2;
        assert_eq!(
            decompress(&Bytes::copy_from_slice(&message), entry, 32)
                .expect("32 hops fit")
                .resume,
            entry + 2
        );
    }

    #[test]
    fn the_expanded_name_is_capped_at_255_wire_octets() {
        let mut message = Vec::new();
        for _ in 0..64 {
            message.extend_from_slice(&[3, b'a', b'b', b'c']);
        }
        message.push(0);
        assert!(matches!(
            decompress(&Bytes::copy_from_slice(&message), 0, 32),
            Err(Error::NameTooLong)
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
