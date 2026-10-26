// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod error;
mod frame;
mod model;

pub(crate) mod hpack;

pub use error::{Error, Limit};
pub use frame::parse_frame;
pub(crate) use frame::{
    FLAG_ACK, FLAG_END_HEADERS, FLAG_END_STREAM, HEADER_LEN, TYPE_CONTINUATION, TYPE_PRIORITY,
    TYPE_SETTINGS, declared_length, parse_frame_for_analysis,
};
pub use model::{CLIENT_PREFACE, Control, Frame, FrameHeader, Payload, Priority, Setting};
