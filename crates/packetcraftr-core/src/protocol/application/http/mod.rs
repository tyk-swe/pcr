// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Cleartext HTTP/1 header dissection and bounded streaming body framing.
mod body;
mod codec;
mod head;
pub use body::{BodyDecoder, Progress};
pub use codec::Http;
pub(crate) use codec::HttpCodec;
pub use head::{
    Body, Error, Head, Header, MAX_HEADER_BYTES, MAX_HEADERS, MAX_START_LINE, StartLine, parse_head,
};
