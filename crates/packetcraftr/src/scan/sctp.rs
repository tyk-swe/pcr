// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! SCTP scan modes: `INIT` and `COOKIE-ECHO`, with deterministic non-zero
//! correlation tags per probe sequence.

use bytes::Bytes;

const TAG_IDENTITY: u32 = 0x5043_5231;

/// Which SCTP chunk a raw scan sends to each SCTP scan endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SctpScan {
    #[default]
    Init,
    CookieEcho,
}

impl SctpScan {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::CookieEcho => "cookie_echo",
        }
    }

    pub const fn chunk_type(self) -> u8 {
        match self {
            Self::Init => 1,
            Self::CookieEcho => 10,
        }
    }

    pub const fn is_init(self) -> bool {
        matches!(self, Self::Init)
    }

    /// A non-zero 32-bit correlation tag derived from `sequence`.
    pub(super) const fn tag(sequence: u64) -> u32 {
        let tag = (sequence as u32).wrapping_add(TAG_IDENTITY);
        if tag == 0 { 1 } else { tag }
    }

    /// Common-header verification tag: zero for `INIT`, non-zero per sequence
    /// for `COOKIE-ECHO`.
    pub(super) const fn verification_tag(self, sequence: u64) -> u32 {
        match self {
            Self::Init => 0,
            Self::CookieEcho => Self::tag(sequence),
        }
    }

    /// Minimal RFC 4960 chunk payload for this mode and `sequence`.
    pub(super) fn chunk_bytes(self, sequence: u64) -> Bytes {
        let tag = Self::tag(sequence).to_be_bytes();
        match self {
            Self::Init => {
                let mut chunk = Vec::with_capacity(20);
                chunk.extend_from_slice(&[1, 0, 0, 20]);
                chunk.extend_from_slice(&tag);
                chunk.extend_from_slice(&[0, 1, 0, 0, 0, 10, 0, 10]);
                chunk.extend_from_slice(&tag);
                Bytes::from(chunk)
            }
            Self::CookieEcho => {
                let mut chunk = Vec::with_capacity(8);
                chunk.extend_from_slice(&[10, 0, 0, 8]);
                chunk.extend_from_slice(&tag);
                Bytes::from(chunk)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_carry_exact_chunk_types_and_nonzero_tags() {
        assert_eq!(SctpScan::default(), SctpScan::Init);
        assert_eq!(
            (SctpScan::Init.as_str(), SctpScan::Init.chunk_type()),
            ("init", 1)
        );
        assert_eq!(
            (
                SctpScan::CookieEcho.as_str(),
                SctpScan::CookieEcho.chunk_type()
            ),
            ("cookie_echo", 10)
        );
        for sequence in [
            0,
            1,
            9,
            u64::from(u32::MAX),
            u64::from(u32::MAX - TAG_IDENTITY + 1),
        ] {
            assert_ne!(SctpScan::tag(sequence), 0);
            assert_eq!(SctpScan::Init.verification_tag(sequence), 0);
            assert_eq!(
                SctpScan::CookieEcho.verification_tag(sequence),
                SctpScan::tag(sequence)
            );
            assert_eq!(SctpScan::Init.chunk_bytes(sequence).len(), 20);
            assert_eq!(SctpScan::CookieEcho.chunk_bytes(sequence).len(), 8);
        }
    }
}
