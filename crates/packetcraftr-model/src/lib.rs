// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Foundational, owned, platform-neutral PacketcraftR models.
//!
//! This crate is the root of the workspace dependency graph. It owns the
//! vocabulary that every other domain shares:
//!
//! - [`error`] holds the classified failure taxonomy crossing API boundaries;
//! - [`frame`] holds complete captured bytes and their link-layer metadata; and
//! - [`identity`] holds the stable owned identifiers used by packet, protocol,
//!   output, and catalog boundaries.
//!
//! Nothing here depends on capture formats, packet construction, native
//! networking, packet engines, or an async runtime.

#![forbid(unsafe_code)]

pub mod error;
pub mod frame;
pub mod identity;

pub use error::{Category, Classification, Classified, Kind};
pub use frame::{DEFAULT_MAX_FRAME_BYTES, Direction, Frame, FrameError, LinkType};
pub use identity::{
    CatalogHash, ComponentId, ContentDigest, ExtensionId, FieldId, IdentityError, PackageId,
    ProtocolId, ProviderId, RegistrationOrigin,
};
