// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic, bounded, offline packet mutation campaigns.
//!
//! This module has no resolver, route, capture, or transmission seam. The
//! live layer consumes a prepared [`Campaign`] and adds those effects only
//! after authorization.

use std::time::Duration;

use crate::template::DEFAULT_MAX_TEMPLATE_PACKETS;

pub const DEFAULT_CASES: usize = 64;
pub const DEFAULT_MAX_CASES: usize = DEFAULT_MAX_TEMPLATE_PACKETS;
pub const MAX_CASES: usize = 100_000;
pub const DEFAULT_MAX_FIELD_BYTES: usize = 4 * 1024;
pub const MAX_FIELD_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_LIST_ITEMS: usize = 256;
pub const MAX_LIST_ITEMS: usize = 4_096;
pub const DEFAULT_MAX_SHRINK_STEPS: usize = 8;
pub const MAX_SHRINK_STEPS: usize = 64;
pub const MAX_DURATION: Duration = Duration::from_secs(3_600);
pub const MAX_STRATEGIES: usize = 4;
pub const MAX_TARGET_FIELDS: usize = 4_096;

/// Largest retained and wire byte total one campaign may charge (256 MiB).
pub const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_BYTES: usize = MAX_TOTAL_BYTES;
/// Largest packet one case may build or dissect (16 MiB).
///
/// A case is one packet, so this is the same ceiling the packet layout uses;
/// a campaign starts at that size and may only lower it.
pub const MAX_PACKET_BYTES: usize = 16 * 1024 * 1024;
/// Deepest list nesting a reflected fuzz value may carry.
///
/// This must not exceed
/// [`MAX_DOCUMENT_NESTING`](crate::document::MAX_DOCUMENT_NESTING): a value a
/// packet document can carry has to stay measurable here.
pub const MAX_VALUE_NESTING: usize = 64;
const SPLITMIX_INCREMENT: u64 = 0x9e37_79b9_7f4a_7c15;
const CASE_DOMAIN: u64 = 0xd1b5_4a32_d192_ed03;

mod decode;
mod error;
mod mutation;
mod prepare;
mod report;
mod request;
pub(crate) mod rng;
mod run;
#[cfg(test)]
mod tests;

pub use decode::{dissect_built, packet_link_type};
pub use error::Error;
pub use report::{Case, CaseFailure, CaseOutcome, Mutation, Report, Stats, Summary};
pub use request::{Limits, Request, Strategy, Target, TargetParseError};
pub use run::{Campaign, run, run_with_events};
