// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact packet construction.

mod engine;

pub use engine::{
    BuildContext as Context, BuildError as Error, BuildMode as Mode, BuildOptions as Options,
    Builder, BuiltPacket as Result, DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE,
};
#[doc(hidden)]
pub use engine::{BuildContext, BuildError, BuildMode, BuildOptions, BuiltPacket};
