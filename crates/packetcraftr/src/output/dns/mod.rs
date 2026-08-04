// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured DNS output.

mod record;
mod result;
pub use crate::output::frame::{Captured as Frame, Timestamp};
pub use record::{
    DnsEdnsOptionOutput as EdnsOption, DnsEdnsOutput as Edns, DnsRecordData as RecordData,
    DnsRecordOutput as Record, DnsRejectedRecordOutput as RejectedRecord, DnsSection as Section,
};
pub use result::{
    DnsAttemptOutput as Attempt, DnsCommandResult as Result, DnsOutcome as AttemptStatus,
    DnsOutcome as Outcome, DnsStreamCommandResult as Event, DnsUndecodedOutput as Undecoded,
};
