// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Send: transmitting every packet a template expands to, a bounded number of
//! passes, under one operation budget.

mod engine;
mod error;
mod evidence;
pub(crate) mod options;
mod plan;
mod report;
mod request;

pub use error::Error;
pub use evidence::{Event, SentFrame};
pub use options::Options;
pub use report::{Aggregate, Collector, Report};
pub use request::Request;
