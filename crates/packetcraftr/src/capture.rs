// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture: passive live capture from one or more interfaces under one operation budget.

mod engine;
mod error;
mod evidence;
mod executor;
mod plan;
mod report;
mod request;

pub use error::{Cause, Error};
pub use evidence::{Event, Source};
pub use report::{Control, Report, StopReason};
pub use request::Request;
