// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod record;
mod report;
pub use record::{Edns, EdnsOption, Record, RecordData};
pub use report::{
    Attempt, BatchResult, Event, QuestionComplete, QuestionResult, Report, Undecoded,
};
