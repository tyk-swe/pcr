// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod execution;
mod request;
mod result;

pub use execution::{DnsExchange, DnsExchangeExecution, DnsExecutor, DnsProbe};
pub use request::{DnsLimits, DnsQueryType, DnsRequest};
pub use result::{
    DnsAttemptEvidence, DnsEdns, DnsEdnsOption, DnsName, DnsOutcome,
    DnsOutcome as DnsAttemptStatus, DnsRecord, DnsRecordValue, DnsRejectedRecord, DnsResult,
    DnsSection, DnsUndecodedEvidence, ValidatedDnsResponse,
};
