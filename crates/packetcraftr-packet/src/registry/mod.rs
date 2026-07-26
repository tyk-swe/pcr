// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic protocol registration.

mod core;

#[doc(hidden)]
pub use super::codec::{CodecError, LayerDecodeContext, LayerEncodeContext};
pub use core::{
    Discriminator, ProtocolModule as Module, ProtocolRegistry as Registry,
    RegistryBuilder as Builder, RegistryError as Error,
};
#[doc(hidden)]
pub use core::{ProtocolModule, ProtocolRegistry, RegistryBuilder, RegistryError};
