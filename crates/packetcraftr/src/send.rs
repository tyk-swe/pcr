// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Single-packet and template-set send contracts.

mod engine;
mod request;

pub use request::{Options, Report, SentFrame, SetOptions, SetReport};
