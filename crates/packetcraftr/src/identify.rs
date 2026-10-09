// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit, bounded service identification over already selected numeric endpoints.
//!
//! Responses and banners are untrusted claims. Candidates describe corpus
//! matches, never authenticated identities or vulnerability findings. This
//! operation does not resolve names, authenticate, or follow redirects.

mod budget;
mod engine;
mod error;
mod io;
mod record;
mod request;

pub use error::Error;
pub use packetcraftr_core::document::port_catalog::Transport;
pub use record::{Evidence, IoOutcome, Outcome, Record, Report, Usage};
pub use request::{Endpoint, Limit, Limits, Request, builtin_corpus, builtin_exclusions};

/// Hard allocation and work bounds, independent of caller-selected limits.
pub const MAX_ENDPOINTS: usize = 1_024;
pub const MAX_ATTEMPTS: u64 = 4_096;
pub const MAX_OPERATION_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: u64 = 65_535;
/// Maximum retained candidate entries across evidence and endpoint records
/// in one operation. This independently bounds match-output amplification.
pub const MAX_RESULT_CANDIDATES: usize = 8_192;
