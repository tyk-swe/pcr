// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Bounded, policy-gated network workflows.

mod address_family;
pub mod clock;
mod dns_impl;
mod fuzz_impl;
mod probe;
mod replay_impl;
mod scan_impl;
mod stats;
pub mod target;
mod target_adapter;
mod traceroute_impl;

/// Maps an operation-local sequence to an IPv4 identification that native
/// raw-socket adapters can preserve exactly. Zero is deliberately excluded.
const fn nonzero_ipv4_identification(sequence: u64) -> u16 {
    ((sequence % u16::MAX as u64) + 1) as u16
}

fn push_diagnostic_once(
    diagnostics: &mut Vec<crate::packet::internal::Diagnostic>,
    diagnostic: crate::packet::internal::Diagnostic,
) {
    if !diagnostics
        .iter()
        .any(|existing| existing.code == diagnostic.code)
    {
        diagnostics.push(diagnostic);
    }
}

pub use address_family::AddressFamily;
pub use stats::Stats;

/// Bounded network scanning.
pub mod scan {
    pub use super::scan_impl::{
        classify_scan_response as classify_response, scan as run, ClientExecutor,
        ScanBatch as Batch, ScanBatchExecution as Execution, ScanClassification as Classification,
        ScanEndpointResult as Endpoint, ScanError as Error, ScanExecutionError as ExecutionError,
        ScanExecutor as Executor, ScanLimits as Limits, ScanMatchedResponse as MatchedResponse,
        ScanProbe as Probe, ScanProbeEvidence as ProbeEvidence, ScanProbeStatus as ProbeStatus,
        ScanRequest as Request, ScanResponseClassification as ResponseClassification,
        ScanResult as Result, ScanTransport as Transport, DEFAULT_MAX_SCAN_PORTS,
        DEFAULT_MAX_UNDECODED_SCAN_FRAMES, DEFAULT_SCAN_BATCH_SIZE, MAX_SCAN_ATTEMPTS,
        MAX_SCAN_DURATION, MAX_SCAN_PROBES, MAX_SCAN_RATE,
    };
    pub use super::target_adapter::PolicyAuthorizer;
}

/// Bounded DNS queries.
pub mod dns {
    pub use super::dns_impl::{
        canonical_query_name, classify_dns_response as classify_response,
        decode_dns_response as decode_response, decode_dns_tcp_frame as decode_tcp_frame,
        dns as run, encode_dns_query as encode_query, response_code_name, ClientExecutor,
        DnsAttemptEvidence as AttemptEvidence, DnsAttemptStatus as AttemptStatus, DnsEdns as Edns,
        DnsEdnsOption as EdnsOption, DnsError as Error, DnsExchange as Exchange,
        DnsExchangeExecution as Execution, DnsExecutionError as ExecutionError,
        DnsExecutor as Executor, DnsLimits as Limits, DnsMatchedResponse as MatchedResponse,
        DnsName as Name, DnsOutcome as Outcome, DnsProbe as Probe, DnsQueryType as QueryType,
        DnsRecord as Record, DnsRecordValue as RecordValue, DnsRejectedRecord as RejectedRecord,
        DnsRequest as Request, DnsResponseClassification as ResponseClassification,
        DnsResult as Result, DnsSection as Section, DnsTransport as Transport,
        DnsUndecodedEvidence as UndecodedEvidence, DnsWireError as WireError,
        ValidatedDnsResponse as ValidatedResponse, DEFAULT_DNS_ATTEMPTS, DEFAULT_DNS_SERVER_PORT,
        DEFAULT_MAX_DNS_NAME_POINTERS, DEFAULT_MAX_DNS_RECORDS, DEFAULT_MAX_DNS_TXT_BYTES,
        DEFAULT_MAX_DNS_TXT_STRINGS, DEFAULT_MAX_REJECTED_DNS_RECORDS,
        DEFAULT_MAX_UNDECODED_DNS_FRAMES, DNS_EPHEMERAL_SOURCE_PORT_BASE, DNS_HEADER_BYTES,
        MAX_DNS_ATTEMPTS, MAX_DNS_DURATION, MAX_DNS_MESSAGE_BYTES, MAX_DNS_NAME_POINTERS,
        MAX_DNS_RECORDS,
    };
    pub use super::target_adapter::PolicyAuthorizer;
}

/// Bounded traceroute.
pub mod traceroute {
    pub use super::target_adapter::PolicyAuthorizer;
    pub use super::traceroute_impl::{
        classify_traceroute_response as classify_response, traceroute as run, ClientExecutor,
        TracerouteBatch as Batch, TracerouteBatchExecution as Execution,
        TracerouteCompletion as Completion, TracerouteError as Error,
        TracerouteExecutionError as ExecutionError, TracerouteExecutor as Executor,
        TracerouteHopResult as Hop, TracerouteLimits as Limits,
        TracerouteMatchedResponse as MatchedResponse, TracerouteProbe as Probe,
        TracerouteProbeEvidence as ProbeEvidence, TracerouteProbeStatus as ProbeStatus,
        TracerouteRequest as Request, TracerouteResponseClassification as ResponseClassification,
        TracerouteResponseKind as ResponseKind, TracerouteResult as Result,
        TracerouteStrategy as Strategy, TracerouteUndecodedEvidence as UndecodedEvidence,
        DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES, DEFAULT_TRACEROUTE_FIRST_HOP,
        DEFAULT_TRACEROUTE_MAX_HOPS, DEFAULT_TRACEROUTE_PROBES_PER_HOP,
        DEFAULT_TRACEROUTE_TCP_PORT, DEFAULT_TRACEROUTE_UDP_PORT, MAX_TRACEROUTE_DURATION,
        MAX_TRACEROUTE_PROBES_PER_HOP,
    };
}

/// Deterministic packet fuzzing and optional live execution.
pub mod fuzz {
    pub use super::fuzz_impl::{
        fuzz as run, fuzz_live as run_live, ClientExecutor,
        FuzzAuthorizationError as AuthorizationError, FuzzAuthorizer as Authorizer,
        FuzzCase as Case, FuzzCaseExecution as Execution, FuzzCaseFailure as CaseFailure,
        FuzzCaseOutcome as CaseOutcome, FuzzError as Error, FuzzExecutionCase as ExecutionCase,
        FuzzExecutionError as ExecutionError, FuzzExecutionStats as ExecutionStats,
        FuzzExecutor as Executor, FuzzLimits as Limits, FuzzLiveOptions as LiveOptions,
        FuzzMode as Mode, FuzzMutation as Mutation, FuzzReproduction as Reproduction,
        FuzzRequest as Request, FuzzResult as Result, FuzzStats as Stats, FuzzStrategy as Strategy,
        FuzzTarget as Target, FuzzTargetParseError as TargetParseError, PolicyAuthorizer,
        DEFAULT_FUZZ_CASES, DEFAULT_MAX_FUZZ_CASES, DEFAULT_MAX_FUZZ_FIELD_BYTES,
        DEFAULT_MAX_FUZZ_LIST_ITEMS, DEFAULT_MAX_FUZZ_SHRINK_STEPS, MAX_FUZZ_CASES,
        MAX_FUZZ_DURATION, MAX_FUZZ_FIELD_BYTES, MAX_FUZZ_LIST_ITEMS, MAX_FUZZ_RATE,
        MAX_FUZZ_SHRINK_STEPS, MAX_FUZZ_STRATEGIES, MAX_FUZZ_TARGET_FIELDS,
    };
}

/// Capture replay.
pub mod replay {
    pub use super::replay_impl::{
        replay_capture as run, ReplayAuthorizationError as AuthorizationError,
        ReplayAuthorizer as Authorizer, ReplayError as Error, ReplayFrameEvidence as FrameEvidence,
        ReplayLimits as Limits, ReplayOptions as Options, ReplaySummary as Summary,
        ReplayTiming as Timing, ReplayTransmission as Transmission,
        ReplayTransmitter as Transmitter, SystemAuthorizer, SystemTransmitter, MAX_REPLAY_DURATION,
    };
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use bytes::Bytes;

    use super::traceroute_impl::TracerouteStrategy;
    use super::{dns_impl::DnsProbe, dns_impl::DnsQueryType, scan_impl::ScanProbe};
    use super::{scan_impl::ScanTransport, traceroute_impl::TracerouteProbe};

    fn identification(packet: &crate::packet::internal::Packet) -> u64 {
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
