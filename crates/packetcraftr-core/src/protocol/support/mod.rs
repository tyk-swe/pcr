// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Built-in codec and capture-root capability information.
//!
//! [`BUILTIN_PROTOCOLS`] distinguishes construction, dissection, exact round
//! trips, response matching, and decode-only support. [`BUILTIN_CAPTURE_ROOTS`]
//! lists the default registry's numeric capture bindings.

mod manifest;

pub use manifest::{
    BUILTIN_CAPTURE_ROOTS, BUILTIN_PROTOCOLS, CaptureRootByteOrder as CaptureByteOrder,
    CaptureRootSupport as CaptureRoot, ProtocolSupport as Protocol,
};
