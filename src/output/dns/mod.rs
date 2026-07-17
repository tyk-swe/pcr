//! Structured DNS output.

mod model;
pub use model::{
    DnsAttemptOutput as Attempt, DnsAttemptStatus as AttemptStatus, DnsCommandResult as Result,
    DnsEdnsOptionOutput as EdnsOption, DnsEdnsOutput as Edns, DnsOutcome as Outcome,
    DnsRecordCommandResult as RecordResult, DnsRecordData as RecordData, DnsRecordOutput as Record,
    DnsRejectedRecordOutput as RejectedRecord, DnsSection as Section,
    DnsStreamCommandResult as Event, DnsUndecodedOutput as Undecoded,
};
