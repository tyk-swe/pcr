// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured DNS output.

mod record;
mod report;
pub use record::{Edns, EdnsOption, Record, RecordData, RejectedRecord, Section};
pub use report::{Attempt, Event, Outcome, Report, Transport, Undecoded};
