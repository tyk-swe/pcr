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
}
