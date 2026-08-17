// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod execution;
mod request;
mod result;

pub use execution::{Exchange, Execution, Executor, Probe};
pub use request::{Limits, QueryType, Request};
pub use result::{
    AttemptEvidence, Edns, EdnsOption, Name, Outcome, Record, RecordValue, RejectedRecord, Result,
    Section, UndecodedEvidence, ValidatedResponse,
};
