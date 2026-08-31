// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS wire construction, bounded decoding, and relevance filtering.

pub use decode::{decode_response, decode_tcp_frame};
pub use encode::encode_query;
pub use name::canonical_query_name;

mod decode;
mod encode;
mod name;
mod relevance;
