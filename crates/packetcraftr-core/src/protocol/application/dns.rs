// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, lossless DNS message dissection and resource-record decoding.
//!
//! [`Dns`] and its records live in `model`, the wire decoder, encoder, and
//! layer codec in `codec`, and field reflection in `reflection`. Every wire
//! API returns [`Error`].

mod codec;
mod model;
mod reflection;

pub(crate) use codec::DnsCodec;
pub use codec::decode_name;
pub use model::{Dns, Edns, EdnsOption, Name, Question, Record, RecordValue};

/// Largest accepted [`DecodeLimits::max_message_bytes`] and
/// [`DecodeLimits::max_txt_bytes`]: one DNS message.
pub const MAX_MESSAGE_BYTES: usize = 65_535;
/// Largest accepted [`DecodeLimits::max_records`] and
/// [`DecodeLimits::max_txt_strings`].
pub const MAX_RECORDS: usize = 4_096;
/// Largest accepted [`DecodeLimits::max_name_pointers`].
pub const MAX_NAME_POINTERS: usize = 128;
/// The largest label a name may carry, in octets (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;
/// The largest expanded name, in wire octets including each length byte
/// (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;

/// Per-message resource bounds. Each is at most its `MAX_*` constant, and a
/// message may carry at most 64 questions. [`DecodeLimits::validate`] refuses
/// a larger limit rather than lowering it; zero permits none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_message_bytes: usize,
    pub max_records: usize,
    pub max_name_pointers: usize,
    pub max_txt_strings: usize,
    pub max_txt_bytes: usize,
}
impl DecodeLimits {
    /// Rejects a limit above its `MAX_*` constant.
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value, maximum) in [
            (
                "max_message_bytes",
                self.max_message_bytes,
                MAX_MESSAGE_BYTES,
            ),
            ("max_records", self.max_records, MAX_RECORDS),
            (
                "max_name_pointers",
                self.max_name_pointers,
                MAX_NAME_POINTERS,
            ),
            ("max_txt_strings", self.max_txt_strings, MAX_RECORDS),
            ("max_txt_bytes", self.max_txt_bytes, MAX_MESSAGE_BYTES),
        ] {
            if value > maximum {
                return Err(Error::InvalidLimit {
                    field,
                    value,
                    maximum,
                });
            }
        }
        Ok(())
    }
}
impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: MAX_MESSAGE_BYTES,
            max_records: 512,
            max_name_pointers: 32,
            max_txt_strings: 256,
            max_txt_bytes: 16_384,
        }
    }
}

/// A DNS message, name, or record that the bounded wire codec rejects.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("DNS question count {actual} exceeds limit {limit}")]
    QuestionLimit { actual: usize, limit: usize },
    #[error("DNS name is invalid: {message}")]
    InvalidName { message: String },
    #[error("DNS message is {actual} bytes; expected at least {minimum}")]
    MessageTooShort { actual: usize, minimum: usize },
    #[error("DNS message is {actual} bytes; maximum is {maximum}")]
    MessageTooLarge { actual: usize, maximum: usize },
    #[error("DNS record count {actual} exceeds limit {limit}")]
    RecordLimit { actual: usize, limit: usize },
    #[error("DNS field {field} at byte {offset} is truncated before byte {needed}")]
    TruncatedField {
        field: &'static str,
        offset: usize,
        needed: usize,
    },
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
    #[error("DNS name compression pointer {pointer} is outside the {length}-byte message")]
    PointerOutOfBounds { pointer: usize, length: usize },
    #[error("DNS name compression pointer at byte {offset} addresses itself")]
    SelfPointer { offset: usize },
    /// A compression pointer addresses a later offset, which cannot terminate.
    #[error("DNS name compression pointer at byte {offset} points forward to byte {pointer}")]
    ForwardPointer { offset: usize, pointer: usize },
    #[error("DNS name compression pointer loop was detected at byte {offset}")]
    PointerLoop { offset: usize },
    #[error("DNS name uses more than {limit} compression pointers")]
    PointerLimit { limit: usize },
    /// A label length byte uses one of the two reserved tag values.
    #[error("DNS label at byte {offset} uses a reserved length encoding")]
    ReservedLabelLength { offset: usize },
    /// A label declares more than [`MAX_LABEL_LEN`] octets.
    #[error(
        "DNS label at byte {offset} is {actual} bytes; maximum is {}",
        MAX_LABEL_LEN
    )]
    LabelTooLong { offset: usize, actual: usize },
    /// The expanded name exceeds [`MAX_NAME_LEN`] wire octets.
    #[error("DNS name exceeds the {}-byte wire limit", MAX_NAME_LEN)]
    NameTooLong,
    #[error("DNS EDNS metadata is invalid: {message}")]
    InvalidEdns { message: String },
    #[error("DNS {record_type} RDATA at byte {offset} is invalid: {message}")]
    InvalidRdata {
        record_type: u16,
        offset: usize,
        message: String,
    },
    #[error("DNS TXT record exceeds {limit} string(s)")]
    TxtStringLimit { limit: usize },
    #[error("DNS TXT record exceeds {limit} aggregate byte(s)")]
    TxtByteLimit { limit: usize },
    #[error("DNS message has {remaining} trailing byte(s) after declared sections")]
    TrailingBytes { remaining: usize },
    /// A configured [`DecodeLimits`] field above its ceiling.
    #[error("DNS limit {field}={value} exceeds the maximum of {maximum}")]
    InvalidLimit {
        field: &'static str,
        value: usize,
        maximum: usize,
    },
    /// The message could not be encoded under the strict DNS wire rules.
    #[error("DNS message cannot be encoded")]
    Encode(#[source] crate::codec::Error),
}

impl crate::error::Classified for Error {
    fn classification(&self) -> crate::error::Classification {
        use crate::error::{Classification, Kind};
        match self {
            Self::Encode(source) => source.classification(),
            Self::QuestionLimit { .. }
            | Self::RecordLimit { .. }
            | Self::TxtStringLimit { .. }
            | Self::TxtByteLimit { .. }
            | Self::PointerLimit { .. }
            | Self::MessageTooLarge { .. }
            | Self::InvalidLimit { .. } => Classification::new(
                "policy.dns_limit",
                Kind::Policy,
                Some("raise the finite DNS decode limit or inspect the oversized message"),
            ),
            _ => Classification::new(
                "packet.dns",
                Kind::Packet,
                Some("inspect the DNS message that breaks a wire rule"),
            ),
        }
    }
}

impl Error {
    pub(crate) fn truncation_needed(&self) -> Option<usize> {
        match self {
            Self::MessageTooShort { minimum, .. } => Some(*minimum),
            Self::TruncatedField { needed, .. } => Some(*needed),
            Self::TruncatedLabelLength { offset } => offset.checked_add(1),
            Self::TruncatedPointer { offset } => offset.checked_add(2),
            Self::TruncatedLabel { end, .. } => Some(*end),
            _ => None,
        }
    }
}
