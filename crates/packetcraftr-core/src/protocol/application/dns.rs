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
pub use codec::{decode_name, name, read_u16};
pub use model::{Dns, Edns, EdnsOption, Name, Question, Record, RecordValue};

/// Per-message resource bounds. Absolute ceilings remain 65,535 message/TXT
/// bytes, 4,096 records/TXT strings, 128 name pointers, and 64 questions.
/// Larger supplied limits are tightened to these ceilings; zero permits none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_message_bytes: usize,
    pub max_records: usize,
    pub max_name_pointers: usize,
    pub max_txt_strings: usize,
    pub max_txt_bytes: usize,
}
impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 65_535,
            max_records: 512,
            max_name_pointers: 32,
            max_txt_strings: 256,
            max_txt_bytes: 16_384,
        }
    }
}

/// A DNS message, name, or record that the bounded wire codec rejects.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
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
    #[error("{0}")]
    Name(#[from] name::Error),
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
    /// The message could not be encoded under the strict DNS wire rules.
    #[error("DNS message cannot be encoded")]
    Encode(#[source] crate::codec::Error),
}

impl Error {
    pub(crate) fn truncation_needed(&self) -> Option<usize> {
        match self {
            Self::MessageTooShort { minimum, .. } => Some(*minimum),
            Self::TruncatedField { needed, .. } => Some(*needed),
            Self::Name(name::Error::TruncatedLabelLength { offset }) => offset.checked_add(1),
            Self::Name(name::Error::TruncatedPointer { offset }) => offset.checked_add(2),
            Self::Name(name::Error::TruncatedLabel { end, .. }) => Some(*end),
            _ => None,
        }
    }
}
