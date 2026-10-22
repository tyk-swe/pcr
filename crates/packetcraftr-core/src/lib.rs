// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Runtime-neutral packet mechanics and bounded offline analysis.
//!
//! This portable foundation has no resolver, route lookup, live-capture, or transmission seam.
//!
//! # Layers
//!
//! Modules depend only on their own layer or a lower one:
//!
//! | Layer | Modules |
//! | --- | --- |
//! | 1. Kernel | `error`, `diagnostic`, `budget`, `field`, `layer`, `layout`, `codec`, `packet`, `registry`, `matcher`, `frame`, `template` |
//! | 2. Packet mechanics | `protocol`, `build`, `decode`, `expression`, `transform`, `conversation`, `document` |
//! | 3. Captures and filters | `capture_file`, `filter` |
//! | 4. Offline analysis | `analysis`, `security`, `fuzz` |
//!
//! The kernel's data model is deliberately one unit: layers, codecs, fields,
//! packets, and the registry refer to one another, so they are not ordered
//! among themselves.
//!
//! Unit tests stay beside the implementations they exercise.

macro_rules! display_via_as_str {
    ($type:ty) => {
        impl ::std::fmt::Display for $type {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

pub mod analysis;
pub mod budget;
pub mod build;
pub mod capture_file;
pub mod codec;
pub mod conversation;
pub mod decode;
pub mod diagnostic;
pub mod document;
pub mod error;
pub mod expression;
pub mod field;
pub mod filter;
pub mod frame;
pub mod fuzz;
pub mod layer;
pub mod layout;
pub mod matcher;
pub mod packet;
pub mod protocol;
pub mod registry;
pub mod template;
pub mod transform;

/// Bounded security findings and investigation collectors.
pub mod security;
