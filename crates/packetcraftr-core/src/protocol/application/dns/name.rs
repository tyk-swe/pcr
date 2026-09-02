// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DNS name decompression.
//!
//! One decompressor serves every DNS reader in the workspace: the built-in
//! DNS-over-UDP dissector in this module's parent, and the DNS workflow's
//! message codec in `packetcraftr`. It answers only the structural question —
//! which label octets a name expands to, and where the reader resumes — so a
//! caller keeps its own presentation escaping and its own error taxonomy while
//! sharing the one place where a decompression bomb has to be refused.
//!
//! The bounds are RFC 1035's: labels of at most [`MAX_LABEL_LEN`] octets, an
//! expanded name of at most [`MAX_NAME_LEN`] wire octets, and a caller-supplied
//! ceiling on how many compression pointers one name may follow. Pointers must
//! address a strictly earlier offset, so a name always terminates.

use bytes::Bytes;

/// The largest label a name may carry, in octets (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// The largest expanded name, in wire octets including each length byte
/// (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;

/// A decompressed DNS name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decompressed {
    /// The label octets in wire order, exactly as they appear in the message.
    /// A root name has no labels. Escaping and case folding are the caller's,
    /// because DNS presentation syntax and DNS equality disagree about which
    /// octets are significant.
    pub labels: Vec<Bytes>,
    /// The offset just past the name's own encoding, which is where the reader
    /// continues. For a compressed name this is two bytes past the *first*
    /// pointer, not past the bytes the pointer reached.
    pub resume: usize,
}

/// Why a DNS name could not be decompressed.
///
/// Deliberately not `#[non_exhaustive]`: both in-workspace callers translate
/// this into their own published error taxonomy with an exhaustive `match`, so
/// a new variant here has to be a compile error at every translation instead of
/// silently falling into a catch-all arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The label-length byte at `offset` is past the end of the message.
    #[error("DNS name label length at byte {offset} is truncated")]
    TruncatedLabelLength { offset: usize },
    /// The second byte of the compression pointer starting at `offset` is
    /// past the end of the message.
    #[error("DNS name compression pointer at byte {offset} is truncated")]
    TruncatedPointer { offset: usize },
    /// The label body starting at `offset` needs octets through `end`, which
    /// the message does not have.
    #[error("DNS name label at byte {offset} is truncated before byte {end}")]
    TruncatedLabel { offset: usize, end: usize },
    /// A compression pointer addresses an offset outside the message.
    #[error("DNS name compression pointer {pointer} is outside the {length}-byte message")]
    PointerOutOfBounds { pointer: usize, length: usize },
    /// A compression pointer addresses itself.
    #[error("DNS name compression pointer at byte {offset} addresses itself")]
    SelfPointer { offset: usize },
    /// A compression pointer addresses a later offset, which cannot terminate.
    #[error("DNS name compression pointer at byte {offset} points forward to byte {pointer}")]
    ForwardPointer { offset: usize, pointer: usize },
    /// A compression pointer returns to an offset this name already expanded.
    #[error("DNS name compression pointer loop was detected at byte {offset}")]
    PointerLoop { offset: usize },
    /// The name follows more compression pointers than the caller allows.
    #[error("DNS name uses more than {limit} compression pointers")]
    PointerLimit { limit: usize },
    /// A label length byte uses one of the two reserved tag values.
    #[error("DNS label at byte {offset} uses a reserved length encoding")]
    ReservedLabelLength { offset: usize },
    /// A label declares more than [`MAX_LABEL_LEN`] octets.
    #[error("DNS label at byte {offset} is {actual} bytes; maximum is {MAX_LABEL_LEN}")]
    LabelTooLong { offset: usize, actual: usize },
    /// The expanded name exceeds [`MAX_NAME_LEN`] wire octets.
    #[error("DNS name exceeds the {MAX_NAME_LEN}-byte wire limit")]
    NameTooLong,
}

/// Expands the possibly-compressed DNS name that starts at `offset` in
/// `message`, following at most `max_pointers` compression pointers.
///
/// Every offset this walks is bounds-checked against `message`, every pointer
/// must address a strictly earlier offset than the one it appears at, no offset
/// is expanded twice, and the expanded name is capped at [`MAX_NAME_LEN`]
/// octets — so the input cannot make this loop forever or allocate without
/// bound.
///
/// `max_pointers` is what bounds the hop count, and the loop-detection scan is
/// quadratic in it, so pass a small constant: the built-in dissector passes 32
/// and the DNS workflow's validated ceiling is 128.
///
/// # Examples
///
/// ```
/// use packetcraftr_core::protocol::application::dns::name;
///
/// // "a" then a pointer back to the root label at offset 0.
/// let message = [0x00, 0x01, b'a', 0xc0, 0x00];
/// let expanded = name::decompress(&message, 1, 32).expect("bounded name");
/// assert_eq!(expanded.labels, vec![bytes::Bytes::from_static(b"a")]);
/// assert_eq!(expanded.resume, 5);
///
/// // A pointer that does not move backward cannot terminate.
/// assert_eq!(
///     name::decompress(&[0xc0, 0x00], 0, 32),
///     Err(name::Error::SelfPointer { offset: 0 }),
/// );
/// ```
pub fn decompress(
    message: &[u8],
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
                // Unreachable while the `0xc0` mask arm above owns every length
                // above 63.
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
                labels.push(Bytes::copy_from_slice(label));
                cursor = end;
            }
            _ => return Err(Error::ReservedLabelLength { offset: cursor }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::*;

    fn labels(expanded: &Decompressed) -> Vec<&[u8]> {
        expanded.labels.iter().map(Bytes::as_ref).collect()
    }

    #[test]
    fn an_uncompressed_name_resumes_after_its_root_label() {
        let message = [1, b'a', 3, b'b', b'c', b'd', 0, 0xff];
        let expanded = decompress(&message, 0, 32).expect("bounded name");
        assert_eq!(labels(&expanded), vec![b"a".as_slice(), b"bcd".as_slice()]);
        assert_eq!(expanded.resume, 7);
    }

    #[test]
    fn a_root_name_expands_to_no_labels() {
        let expanded = decompress(&[0], 0, 32).expect("bounded name");
        assert!(expanded.labels.is_empty());
        assert_eq!(expanded.resume, 1);
    }

    #[test]
    fn a_compressed_name_resumes_past_its_first_pointer() {
        let message = [1, b'a', 0, 1, b'b', 0xc0, 0x00, 0xff];
        let expanded = decompress(&message, 3, 32).expect("bounded name");
        assert_eq!(labels(&expanded), vec![b"b".as_slice(), b"a".as_slice()]);
        assert_eq!(expanded.resume, 7);
    }

    #[test]
    fn label_octets_are_preserved_exactly() {
        let message = [3, b'a', 0x20, 0xff, 0];
        let expanded = decompress(&message, 0, 32).expect("bounded name");
        assert_eq!(labels(&expanded), vec![[b'a', 0x20, 0xff].as_slice()]);
    }

    #[test]
    fn pointers_must_address_a_strictly_earlier_offset() {
        assert_eq!(
            decompress(&[0xc0, 0x00], 0, 32),
            Err(Error::SelfPointer { offset: 0 })
        );
        assert_eq!(
            decompress(&[0xc0, 0x02, 0x00], 0, 32),
            Err(Error::ForwardPointer {
                offset: 0,
                pointer: 2
            })
        );
        assert_eq!(
            decompress(&[0xc0, 0x09], 0, 32),
            Err(Error::PointerOutOfBounds {
                pointer: 9,
                length: 2
            })
        );
    }

    #[test]
    fn an_offset_is_never_expanded_twice() {
        // Enter at 5, hop to 1, read "a", then hop to 1 again.
        let message = [0, 1, b'a', 0xc0, 0x01, 0xc0, 0x01];
        assert_eq!(
            decompress(&message, 5, 32),
            Err(Error::PointerLoop { offset: 1 })
        );
    }

    #[test]
    fn the_pointer_ceiling_bounds_the_hop_count() {
        // A chain of trampolines at increasing offsets, each pointing back one.
        let mut message = vec![0u8];
        let mut previous = 0usize;
        for _ in 0..33 {
            let offset = message.len();
            let pointer = u16::try_from(previous).expect("small offset") | 0xc000;
            message.extend_from_slice(&pointer.to_be_bytes());
            previous = offset;
        }
        assert_eq!(
            decompress(&message, previous, 32),
            Err(Error::PointerLimit { limit: 32 })
        );
        assert!(decompress(&message, previous, 33).is_ok());
        // Entering one trampoline earlier is exactly 32 hops, which fits, and
        // resumes two bytes past the pointer it started on.
        let entry = previous - 2;
        assert_eq!(
            decompress(&message, entry, 32).expect("32 hops fit").resume,
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
        assert_eq!(decompress(&message, 0, 32), Err(Error::NameTooLong));
    }

    #[test]
    fn reserved_and_truncated_encodings_are_refused() {
        assert_eq!(
            decompress(&[0x40, 0], 0, 32),
            Err(Error::ReservedLabelLength { offset: 0 })
        );
        assert_eq!(
            decompress(&[0x80, 0], 0, 32),
            Err(Error::ReservedLabelLength { offset: 0 })
        );
        assert_eq!(
            decompress(&[], 0, 32),
            Err(Error::TruncatedLabelLength { offset: 0 })
        );
        assert_eq!(
            decompress(&[0xc0], 0, 32),
            Err(Error::TruncatedPointer { offset: 0 })
        );
        assert_eq!(
            decompress(&[3, b'a'], 0, 32),
            Err(Error::TruncatedLabel { offset: 1, end: 4 })
        );
    }
}
