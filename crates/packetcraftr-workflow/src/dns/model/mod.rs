// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod execution;
mod request;
mod result;

pub use execution::{DnsExchange, DnsExchangeExecution, DnsExecutor, DnsMatchedResponse, DnsProbe};
pub use request::{DnsLimits, DnsQueryType, DnsRequest};
pub use result::{
    DnsAttemptEvidence, DnsAttemptStatus, DnsEdns, DnsEdnsOption, DnsName, DnsOutcome, DnsRecord,
    DnsRecordValue, DnsRejectedRecord, DnsResult, DnsSection, DnsUndecodedEvidence,
    ValidatedDnsResponse,
};
