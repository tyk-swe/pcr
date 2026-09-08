// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Machine representations owned by the PacketcraftR command-line application.
//!
//! JSON compatibility is governed by the published versioned schemas. Rust
//! output types and constructors remain beta APIs and may change between beta
//! releases; importing this crate does not provide a stable workflow facade.
//! Core analysis and native resources keep their canonical owning-crate paths.
#![forbid(unsafe_code)]

pub mod output;
