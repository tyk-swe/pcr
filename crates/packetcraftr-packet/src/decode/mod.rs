// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded packet decoding.

mod engine;

pub use engine::{
    DecodeError as Error, DecodeOptions as Options, DecodedPacket as Result, Dissector as Decoder,
};
pub use engine::{DecodeError, DecodeOptions, DecodedPacket, Dissector};
