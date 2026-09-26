// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Network provider contracts and native I/O adapters.
//!
//! All platform-specific and potentially unsafe I/O is contained here. Higher
//! level transmission and diagnostic workflows remain policy-gated in
//! `packetcraftr`.
//!
//! # Public paths
//!
//! Each capability is a module ([`route`], [`interface`], [`capture`],
//! [`transmit`], [`tcp`]) holding its provider contract and its system
//! provider; shared vocabulary is at the root. Public fields name core types
//! by their core path, such as `packetcraftr_core::packet::MacAddress`.
//!
//! # Errors
//!
//! Every public error implements `packetcraftr_core::error::Classified`.
//! A native failure keeps the platform's own error as its source, stored as
//! `packetcraftr_core::error::Source` when it is type-erased, and its message
//! never repeats that source. [`Error`] is the live-I/O failure capture and
//! transmission share; [`route::Error`], [`interface::Error`], and
//! [`tcp::Error`] are their capabilities' own. A capability this build, target,
//! or device lacks is one [`Unsupported`], which all three live-I/O errors
//! carry and whose [`NativeCapability`] decides its class.

// This crate is the only one permitted to contain `unsafe`. Non-platform
// modules forbid it locally; files under `platform/` that wrap a native API
// may opt out of the workspace lint with their own inner attribute.

#[forbid(unsafe_code)]
pub mod capture;
#[forbid(unsafe_code)]
pub mod deadline;
#[forbid(unsafe_code)]
mod error;
#[forbid(unsafe_code)]
pub mod interface;
#[forbid(unsafe_code)]
pub mod link;
mod platform;
#[forbid(unsafe_code)]
pub mod resources;
#[forbid(unsafe_code)]
pub mod route;
#[forbid(unsafe_code)]
pub mod tcp;
#[forbid(unsafe_code)]
pub mod transmit;
#[forbid(unsafe_code)]
mod unsupported;
#[forbid(unsafe_code)]
mod workers;

pub use error::{Error, SendEvidenceFault};
pub use unsupported::{NativeCapability, Unsupported};
