// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture-link header models.

mod bsd;
mod sll;

pub use bsd::{BsdLoop, BsdNull, CaptureByteOrder as ByteOrder};
pub(crate) use bsd::{BsdLoopCodec, BsdNullCodec};
pub use sll::{LinuxSll, LinuxSll2};
pub(crate) use sll::{LinuxSll2Codec, LinuxSllCodec};
