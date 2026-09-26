// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded TLS parsing from byte slices, independent of TCP buffering.
//! [`Outcome::NeedMore`] gives the total input length required; malformed input
//! returns [`Outcome::Malformed`] without panicking.

use bytes::Bytes;

use super::model::{
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC, MAX_LEGACY_VERSION,
    MAX_RECORD_BODY, MIN_LEGACY_VERSION, RECORD_HEADER_LEN, Record,
};
use crate::protocol::common::invalid;

use crate::protocol::BuiltinProtocol;

mod handshake;
pub use handshake::parse_handshake;

const NAME: &str = BuiltinProtocol::Tls.as_str();

type Error = crate::codec::Error;

/// The result of reading one framed item from a byte slice.
#[derive(Debug)]
pub enum Outcome<T> {
    /// A complete item, with the number of input bytes it occupied.
    Complete {
        /// Bytes consumed from the front of the input.
        consumed: usize,
        value: T,
    },
    /// The input is a plausible prefix; `minimum` is the total input length
    /// required before a `Complete` can be produced.
    NeedMore {
        /// Total input length needed, counting the bytes already supplied.
        minimum: usize,
    },
    /// The input cannot be a valid item, whatever follows it. The error
    /// describes which rule or limit it broke.
    Malformed(crate::codec::Error),
}

/// TLS dissection gate: requires a full [`RECORD_HEADER_LEN`], content type
/// `20..=23`, version `0x0300..=0x0304`, and body length `1..=MAX_RECORD_BODY`.
/// Accepts the same headers as [`parse_record`], so a passing record cannot
/// then parse as malformed.
#[must_use]
pub fn looks_like_record_start(input: &[u8]) -> bool {
    input
        .first_chunk::<RECORD_HEADER_LEN>()
        .is_some_and(|header| record_header(header).is_ok())
}

pub fn parse_record(input: &[u8]) -> Outcome<Record> {
    let Some(header) = input.first_chunk::<RECORD_HEADER_LEN>() else {
        return Outcome::NeedMore {
            minimum: RECORD_HEADER_LEN,
        };
    };
    let header = match record_header(header) {
        Ok(header) => header,
        Err(error) => return Outcome::Malformed(error),
    };
    let total = RECORD_HEADER_LEN.saturating_add(header.length);
    let Some(body) = input.get(RECORD_HEADER_LEN..total) else {
        return Outcome::NeedMore { minimum: total };
    };
    Outcome::Complete {
        consumed: total,
        value: Record {
            content_type: header.content_type,
            legacy_version: header.legacy_version,
            body: Bytes::copy_from_slice(body),
        },
    }
}

struct RecordHeader {
    content_type: u8,
    legacy_version: u16,
    length: usize,
}

fn record_header(header: &[u8; RECORD_HEADER_LEN]) -> Result<RecordHeader, Error> {
    let content_type = header[0];
    if !(CONTENT_TYPE_CHANGE_CIPHER_SPEC..=CONTENT_TYPE_APPLICATION_DATA).contains(&content_type) {
        return Err(invalid(
            NAME,
            format!(
                "record content type {content_type} is outside \
                 {CONTENT_TYPE_CHANGE_CIPHER_SPEC}..={CONTENT_TYPE_APPLICATION_DATA}"
            ),
        ));
    }
    let legacy_version = u16::from_be_bytes([header[1], header[2]]);
    if !(MIN_LEGACY_VERSION..=MAX_LEGACY_VERSION).contains(&legacy_version) {
        return Err(invalid(
            NAME,
            format!(
                "record version {legacy_version:#06x} is outside \
                 {MIN_LEGACY_VERSION:#06x}..={MAX_LEGACY_VERSION:#06x}"
            ),
        ));
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length == 0 {
        return Err(invalid(NAME, "record body length is zero"));
    }
    if length > MAX_RECORD_BODY {
        return Err(invalid(
            NAME,
            format!("record body of {length} bytes exceeds the limit of {MAX_RECORD_BODY}"),
        ));
    }
    Ok(RecordHeader {
        content_type,
        legacy_version,
        length,
    })
}

struct Reader<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.cursor)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or_else(|| invalid(NAME, "handshake offset arithmetic overflowed"))?;
        let slice = self.input.get(self.cursor..end).ok_or_else(|| {
            invalid(
                NAME,
                format!(
                    "handshake field needs {len} bytes but only {} remain",
                    self.input.len().saturating_sub(self.cursor)
                ),
            )
        })?;
        self.cursor = end;
        Ok(slice)
    }

    /// Takes a fixed-size field, so callers can index the array without bounds checks.
    fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], Error> {
        let bytes = self.take(N)?;
        <&[u8; N]>::try_from(bytes)
            .map_err(|_| invalid(NAME, format!("handshake field is not {N} bytes")))
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(*self.array::<2>()?))
    }

    fn random(&mut self) -> Result<[u8; 32], Error> {
        Ok(*self.array::<32>()?)
    }

    fn vector8(&mut self) -> Result<&'a [u8], Error> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    fn vector16(&mut self) -> Result<&'a [u8], Error> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
}

#[cfg(test)]
mod tests;
