// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Single-packet and template-set send contracts.

mod execution;
mod model;

pub use model::{MAX_SEND_DURATION, Options, Report, SentFrame, SetOptions, SetReport};
