// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub use decode::{decode_response, decode_tcp_frame};
pub use encode::encode_query;
pub use error::Error;
pub use name::canonical_query_name;

mod decode;
mod encode;
mod error;
mod name;
mod relevance;
