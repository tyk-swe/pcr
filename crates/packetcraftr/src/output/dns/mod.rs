// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured DNS output.

mod record;
mod result;
pub use record::{Edns, EdnsOption, Record, RecordData, RejectedRecord, Section};
pub use result::{Attempt, Event, Outcome, Result, Transport, Undecoded};
