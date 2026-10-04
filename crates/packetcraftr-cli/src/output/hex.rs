// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use serde::{Serialize, Serializer};

#[derive(Clone, Copy, Debug)]
pub struct CompactHex<'a>(pub &'a [u8]);

const DIGITS: &[u8; 16] = b"0123456789abcdef";
/// Input bytes encoded per `write_str`, so long values reach the formatter in a few pieces.
const CHUNK: usize = 256;

impl fmt::Display for CompactHex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buffer = [0_u8; CHUNK * 2];
        for chunk in self.0.chunks(CHUNK) {
            for (byte, digits) in chunk.iter().zip(buffer.as_chunks_mut::<2>().0) {
                *digits = [
                    DIGITS[usize::from(byte >> 4)],
                    DIGITS[usize::from(byte & 0xf)],
                ];
            }
            formatter.write_str(ascii(&buffer[..chunk.len() * 2]))?;
        }
        Ok(())
    }
}

/// Lowercase hex pairs separated by single spaces.
pub(crate) struct SpacedHex<'a>(pub(crate) &'a [u8]);

impl fmt::Display for SpacedHex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buffer = [0_u8; CHUNK * 3];
        for (index, chunk) in self.0.chunks(CHUNK).enumerate() {
            for (byte, digits) in chunk.iter().zip(buffer.as_chunks_mut::<3>().0) {
                *digits = [
                    b' ',
                    DIGITS[usize::from(byte >> 4)],
                    DIGITS[usize::from(byte & 0xf)],
                ];
            }
            // Only the first pair of the whole value has no leading separator.
            let skip = usize::from(index == 0);
            formatter.write_str(ascii(&buffer[skip..chunk.len() * 3]))?;
        }
        Ok(())
    }
}

fn ascii(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("hex digits and spaces are ASCII")
}

impl Serialize for CompactHex<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

#[must_use]
pub fn compact_hex(bytes: &[u8]) -> String {
    CompactHex(bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_encodings_match_per_byte_formatting() {
        let bytes: Vec<u8> = (0..=u8::MAX).cycle().take(CHUNK * 2 + 3).collect();
        for length in [0, 1, 2, CHUNK - 1, CHUNK, CHUNK + 1, bytes.len()] {
            let input = &bytes[..length];
            let compact: String = input.iter().map(|byte| format!("{byte:02x}")).collect();
            let spaced = input
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(CompactHex(input).to_string(), compact, "length {length}");
            assert_eq!(SpacedHex(input).to_string(), spaced, "length {length}");
        }
    }
}
