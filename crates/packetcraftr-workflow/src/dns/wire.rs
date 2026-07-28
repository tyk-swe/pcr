// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS wire construction, bounded decoding, relevance, and classification.

pub use classification::{DnsResponseClassification, classify_dns_response, response_code_name};
pub use decode::{decode_dns_response, decode_dns_tcp_frame};
pub use encode::encode_dns_query;
pub use name::canonical_query_name;

pub(super) use classification::raw_payload;

mod classification;
mod decode;
mod encode;
mod name;
mod relevance;
