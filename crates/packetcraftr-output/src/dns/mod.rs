// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured DNS output.

mod model;
pub use crate::frame::{Captured as Frame, Timestamp};
pub use model::{
    DnsAttemptOutput as Attempt, DnsCommandResult as Result, DnsEdnsOptionOutput as EdnsOption,
    DnsEdnsOutput as Edns, DnsOutcome as Outcome, DnsOutcome as AttemptStatus,
    DnsRecordData as RecordData, DnsRecordOutput as Record,
    DnsRejectedRecordOutput as RejectedRecord, DnsSection as Section,
    DnsStreamCommandResult as Event, DnsUndecodedOutput as Undecoded,
};
