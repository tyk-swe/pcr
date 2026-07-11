// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Portable workflow boundary for replay, scan, traceroute, DNS, and fuzz tooling.
//!
//! Tool implementations are added incrementally behind this module so the
//! eventual `packetcraftr-tools` extraction does not change root imports.

mod dns;
mod fuzz;
mod replay;
mod scan;
mod traceroute;

/// Maps an operation-local sequence to an IPv4 identification that native
/// raw-socket adapters can preserve exactly. Zero is deliberately excluded:
/// Linux and other kernels may replace it even when the rest of the header is
/// supplied by the caller.
const fn nonzero_ipv4_identification(sequence: u64) -> u16 {
    ((sequence % u16::MAX as u64) + 1) as u16
}

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

pub use fuzz::{
    fuzz, fuzz_live, FuzzAuthorizationError, FuzzAuthorizer, FuzzCase, FuzzCaseExecution,
    FuzzCaseFailure, FuzzCaseOutcome, FuzzClock, FuzzError, FuzzExecutionCase, FuzzExecutionError,
    FuzzExecutionStats, FuzzExecutor, FuzzLimits, FuzzLiveOptions, FuzzMode, FuzzMutation,
    FuzzReproduction, FuzzRequest, FuzzResult, FuzzStats, FuzzStrategy, FuzzTarget,
    FuzzTargetParseError, SystemFuzzClock, DEFAULT_FUZZ_CASES, DEFAULT_MAX_FUZZ_CASES,
    DEFAULT_MAX_FUZZ_FIELD_BYTES, DEFAULT_MAX_FUZZ_LIST_ITEMS, DEFAULT_MAX_FUZZ_SHRINK_STEPS,
    MAX_FUZZ_CASES, MAX_FUZZ_DURATION, MAX_FUZZ_FIELD_BYTES, MAX_FUZZ_LIST_ITEMS, MAX_FUZZ_RATE,
    MAX_FUZZ_SHRINK_STEPS, MAX_FUZZ_STRATEGIES, MAX_FUZZ_TARGET_FIELDS,
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use bytes::Bytes;

    use super::{
        DnsProbe, DnsQueryType, ScanProbe, ScanTransport, TracerouteProbe, TracerouteStrategy,
    };

    fn identification(packet: &crate::core::Packet) -> u64 {
        packet
            .iter()
            .next()
            .and_then(|layer| layer.field("identification"))
            .and_then(|value| value.as_u64())
            .expect("generated IPv4 probe must expose an identification")
    }

    #[test]
    fn generated_live_ipv4_workflows_never_request_kernel_identification_rewrites() {
        let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let scan = ScanProbe {
            sequence: 0,
            address: destination,
            transport: ScanTransport::Udp,
            port: Some(9),
            attempt: 0,
        };
        let traceroute = TracerouteProbe {
            sequence: u64::from(u16::MAX),
            address: destination,
            strategy: TracerouteStrategy::Udp,
            destination_port: Some(33_434),
            hop_limit: 1,
            attempt: 0,
        };
        let dns = DnsProbe {
            attempt: 0,
            server_address: destination,
            server_port: 53,
            source_port: 49_152,
            transaction_id: 1,
            query_name: "example.test".to_owned(),
            query_type: DnsQueryType::A,
            query: Bytes::new(),
        };

        assert_eq!(identification(&scan.packet()), 1);
        assert_eq!(identification(&traceroute.packet()), 1);
        assert_eq!(identification(&dns.packet()), 1);
    }
}
