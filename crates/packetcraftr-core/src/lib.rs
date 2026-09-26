// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Runtime-neutral packet mechanics and bounded offline analysis.
//!
//! This portable foundation has no resolver, route lookup, live-capture, or
//! transmission seam. Provider contracts and native I/O live in
//! `packetcraftr-netio`; authorization-gated live workflows live in
//! `packetcraftr`.
//!
//! # Layers
//!
//! A module depends only on modules in its own layer or a lower one:
//!
//! 1. Support: [`error`], [`budget`], [`diagnostic`].
//! 2. Model: [`field`], [`layer`] (including the opaque [`Raw`](layer::Raw),
//!    [`Padding`](layer::Padding), and [`Malformed`](layer::Malformed)
//!    layers), [`layout`], [`packet`], [`frame`], [`codec`], [`registry`],
//!    and the [`matcher`] contract. Model modules may refer to each other.
//! 3. Protocols: [`protocol`], holding the built-in codecs, the packet
//!    interpretation in [`protocol::semantics`], and the built-in response
//!    matchers; and [`capture_file`], which maps link types to built-in roots.
//! 4. Engines: [`decode`], [`build`], [`transform`], [`filter`],
//!    [`expression`], [`document`], [`template`].
//! 5. Workflows: [`analysis`], [`fuzz`].
//!
//! Properties an engine needs from a protocol, such as whether a link
//! protocol may carry trailing padding, are recorded when the protocol is
//! registered, so custom protocols behave like built-in ones.

#[macro_export]
#[doc(hidden)]
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
mod byte_slice;
pub mod capture_file;
pub mod codec;
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
