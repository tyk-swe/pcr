// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Portable workflow boundary for replay, scan, traceroute, DNS, and fuzz tooling.
//!
//! Tool implementations are added incrementally behind this module so the
//! eventual `packetcraftr-tools` extraction does not change root imports.

mod dns;
mod replay;
mod scan;
mod traceroute;

pub use dns::{
    canonical_query_name, classify_dns_response, decode_dns_response, decode_dns_tcp_frame, dns,
    encode_dns_query, response_code_name, AuthorizedDnsTarget, DnsAddressFamily,
    DnsAttemptEvidence, DnsAttemptStatus, DnsAuthorizationError, DnsError, DnsExchange,
    DnsExchangeExecution, DnsExecutionError, DnsExecutor, DnsLimits, DnsMatchedResponse,
    DnsOutcome, DnsProbe, DnsQueryType, DnsRecord, DnsRecordValue, DnsRejectedRecord, DnsRequest,
    DnsResponseClassification, DnsResult, DnsSection, DnsStats, DnsTarget, DnsTransport,
    DnsUndecodedEvidence, DnsWireError, ValidatedDnsResponse, DEFAULT_DNS_ATTEMPTS,
    DEFAULT_DNS_SERVER_PORT, DEFAULT_MAX_DNS_NAME_POINTERS, DEFAULT_MAX_DNS_RECORDS,
    DEFAULT_MAX_DNS_TXT_BYTES, DEFAULT_MAX_DNS_TXT_STRINGS, DEFAULT_MAX_REJECTED_DNS_RECORDS,
    DEFAULT_MAX_UNDECODED_DNS_FRAMES, DNS_EPHEMERAL_SOURCE_PORT_BASE, DNS_HEADER_BYTES,
    MAX_DNS_ATTEMPTS, MAX_DNS_DURATION, MAX_DNS_MESSAGE_BYTES, MAX_DNS_NAME_POINTERS,
    MAX_DNS_RECORDS,
};

pub use replay::{
    replay_capture, ReplayAuthorizationError, ReplayAuthorizer, ReplayClock, ReplayError,
    ReplayFrameEvidence, ReplayLimits, ReplayOptions, ReplaySummary, ReplayTransmission,
    ReplayTransmitter, SystemReplayClock, MAX_REPLAY_DURATION,
};
pub use scan::{
    classify_scan_response, scan, AuthorizedScanTarget, ScanAddressFamily, ScanAuthorizationError,
    ScanAuthorizer, ScanBatch, ScanBatchExecution, ScanClassification, ScanClock,
    ScanEndpointResult, ScanError, ScanExecutionError, ScanExecutor, ScanLimits,
    ScanMatchedResponse, ScanProbe, ScanProbeEvidence, ScanProbeStatus, ScanRequest,
    ScanResponseClassification, ScanResult, ScanStats, ScanTarget, ScanTransport, SystemScanClock,
    DEFAULT_MAX_SCAN_PORTS, DEFAULT_MAX_UNDECODED_SCAN_FRAMES, DEFAULT_SCAN_BATCH_SIZE,
    MAX_SCAN_ATTEMPTS, MAX_SCAN_DURATION, MAX_SCAN_PROBES, MAX_SCAN_RATE,
};
pub use traceroute::{
    classify_traceroute_response, traceroute, AuthorizedTracerouteTarget, TracerouteAddressFamily,
    TracerouteAuthorizationError, TracerouteBatch, TracerouteBatchExecution, TracerouteCompletion,
    TracerouteError, TracerouteExecutionError, TracerouteExecutor, TracerouteHopResult,
    TracerouteLimits, TracerouteMatchedResponse, TracerouteProbe, TracerouteProbeEvidence,
    TracerouteProbeStatus, TracerouteRequest, TracerouteResponseClassification,
    TracerouteResponseKind, TracerouteResult, TracerouteStats, TracerouteStrategy,
    TracerouteTarget, TracerouteUndecodedEvidence, DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES,
    DEFAULT_TRACEROUTE_FIRST_HOP, DEFAULT_TRACEROUTE_MAX_HOPS, DEFAULT_TRACEROUTE_PROBES_PER_HOP,
    DEFAULT_TRACEROUTE_TCP_PORT, DEFAULT_TRACEROUTE_UDP_PORT, MAX_TRACEROUTE_DURATION,
    MAX_TRACEROUTE_PROBES_PER_HOP,
};

pub use scan::SystemScanClock as SystemTracerouteClock;
pub use scan::SystemScanClock as SystemDnsClock;
pub use scan::{ScanAuthorizer as DnsAuthorizer, ScanClock as DnsClock};
pub use scan::{ScanAuthorizer as TracerouteAuthorizer, ScanClock as TracerouteClock};
