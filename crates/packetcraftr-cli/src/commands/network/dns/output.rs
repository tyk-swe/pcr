// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod record;
mod report;
pub(crate) use record::Record;
pub(crate) use report::{BatchResult, Event, Outcome, QuestionStatus, Report, Section};
