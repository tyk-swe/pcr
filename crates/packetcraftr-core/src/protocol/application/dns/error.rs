// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::name;
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
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
    #[error("DNS field {field} is truncated at byte {offset}")]
    TruncatedField { field: &'static str, offset: usize },
    #[error("DNS name compression pointer at byte {offset} is truncated")]
    TruncatedPointer { offset: usize },
    #[error("DNS name compression pointer {pointer} is outside the {length}-byte message")]
    PointerOutOfBounds { pointer: usize, length: usize },
    #[error("DNS name compression pointer at byte {offset} points forward to byte {pointer}")]
    ForwardPointer { offset: usize, pointer: usize },
    #[error("DNS name compression pointer loop was detected at byte {offset}")]
    PointerLoop { offset: usize },
    #[error("DNS name uses more than {limit} compression pointers")]
    PointerLimit { limit: usize },
    #[error("DNS label at byte {offset} uses a reserved length encoding")]
    ReservedLabelLength { offset: usize },
    #[error(
        "DNS label at byte {offset} is {actual} bytes; maximum is {}",
        name::MAX_LABEL_LEN
    )]
    LabelTooLong { offset: usize, actual: usize },
    #[error("DNS EDNS metadata is invalid: {message}")]
    InvalidEdns { message: String },
    #[error("DNS name exceeds the {}-byte wire limit", name::MAX_NAME_LEN)]
    NameTooLong,
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
}

impl From<name::Error> for DecodeError {
    /// Restates a shared decompression failure in this crate's own published
    /// vocabulary. The `match` is exhaustive on purpose: a new decompression
    /// failure has to be given a name here rather than falling into a
    /// catch-all.
    fn from(error: name::Error) -> Self {
        match error {
            name::Error::TruncatedLabelLength { offset } => Self::TruncatedField {
                field: "name label length",
                offset,
            },
            name::Error::TruncatedPointer { offset } => Self::TruncatedPointer { offset },
            name::Error::TruncatedLabel { offset, .. } => Self::TruncatedField {
                field: "name label",
                offset,
            },
            name::Error::PointerOutOfBounds { pointer, length } => {
                Self::PointerOutOfBounds { pointer, length }
            }
            name::Error::SelfPointer { offset } => Self::PointerLoop { offset },
            name::Error::ForwardPointer { offset, pointer } => {
                Self::ForwardPointer { offset, pointer }
            }
            name::Error::PointerLoop { offset } => Self::PointerLoop { offset },
            name::Error::PointerLimit { limit } => Self::PointerLimit { limit },
            name::Error::ReservedLabelLength { offset } => Self::ReservedLabelLength { offset },
            name::Error::LabelTooLong { offset, actual } => Self::LabelTooLong { offset, actual },
            name::Error::NameTooLong => Self::NameTooLong,
        }
    }
}
