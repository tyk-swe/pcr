// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private, canonical interpretation of packet fields used at live boundaries.

use super::Packet;
use super::field::FieldValue;
use super::layer::{Layer, ProtocolId};
#[doc(hidden)]
pub use super::protocol_catalog::{BuiltinProtocol, builtin_protocol_catalog};

pub use ip::*;

mod ip;
