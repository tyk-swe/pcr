// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod record;
mod report;
pub use record::{Edns, EdnsOption, Record, RecordData};
pub use report::{
    Attempt, BatchResult, Event, Outcome, QuestionComplete, QuestionResult, QuestionStatus,
    RejectedRecord, Report, ResponseSummary, Section, Transport, Undecoded,
};
