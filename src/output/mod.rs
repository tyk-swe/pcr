// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned structured-output contracts.
//!
//! The v1 vocabulary is deliberately scoped by responsibility and command. Types
//! in this module describe the serialized CLI contract; they are not aliases for
//! workflow results intended to evolve independently.

#![forbid(unsafe_code)]

mod internal;

/// Output-version, command, and format contracts.
pub mod contract {
    pub use super::internal::{
        COMMAND_OUTPUT_CONTRACTS as CONTRACTS, CommandName as Command,
        CommandOutputContract as CommandContract, OUTPUT_SCHEMA_V1 as SCHEMA_V1,
        OutputContractError as Error, OutputFormat as Format, OutputMode as Mode,
    };
}

/// Aggregate JSON and streaming NDJSON envelopes.
pub mod envelope {
    pub use super::internal::{
        AggregateErrorOutput as AggregateError, AggregateOutput as Aggregate, CaptureStats,
        DiagnosticOutput as Diagnostic, DiagnosticRangeOutput as DiagnosticRange,
        DiagnosticSeverityOutput as DiagnosticSeverity, OperationStats as Stats,
        OutputError as Error, OutputErrorKind as ErrorKind, StreamErrorRecord as StreamError,
        StreamRecord as Stream,
    };
}

/// Shared wire, captured, and decoded frame representations.
pub mod frame {
    pub use super::internal::{
        DecodedFrameOutput as Decoded, FrameDirection as Direction, FrameOutput as Captured,
        OutputTimestamp as Timestamp, WireFrameOutput as Wire,
    };
}

/// Structured `build` output.
pub mod build {
    pub use super::internal::BuildCommandResult as Result;
}

/// Structured `dissect` output.
pub mod dissect {
    pub use super::internal::DissectCommandResult as Result;
}

/// Offline-read and live-capture stream output.
pub mod capture {
    pub use super::internal::{CaptureFrameCommandResult as Event, ReadFrameCommandResult as Read};
}

/// Structured network-operation output.
pub mod network {
    /// Structured `interfaces` output.
    pub mod interfaces {
        pub use super::super::internal::{
            InterfaceCapabilityOutput as Capability, InterfaceFlagsOutput as Flags,
            InterfaceOutput as Interface, InterfacesCommandResult as Result,
        };
    }

    /// Structured passive route-planning output.
    pub mod plan {
        pub use super::super::internal::{
            PlanCommandResult as Result, PlannedRouteOutput as Plan,
            RouteCapabilityOutput as Capability, RouteDecisionOutput as Decision,
            RouteInterfaceOutput as Interface, RouteLinkTypeOutput as LinkType,
            RouteMacAddressOutput as MacAddress, RouteModeOutput as Mode,
            RouteScopeOutput as Scope, RouteSelectionOutput as SelectionReason,
            RouteVlanKindOutput as VlanKind, RouteVlanTagOutput as VlanTag,
        };
    }

    /// Structured route-enumeration output.
    pub mod routes {
        pub use super::super::internal::{
            RouteDecisionOutput as Decision, RoutesCommandResult as Result,
        };
    }

    /// Structured packet-send output.
    pub mod send {
        pub use super::super::internal::{
            MaterializedRouteOutput as MaterializedRoute,
            NeighborEvidenceOutput as NeighborEvidence, SendCommandResult as Result,
        };
    }

    /// Structured request/response exchange output.
    pub mod exchange {
        pub use super::super::internal::{
            ExchangeCommandResult as Result, ExchangeResponseOutput as Response,
            ExchangeStreamCommandResult as Event,
        };
    }
}

/// Structured capture-replay output.
pub mod replay {
    pub use super::internal::{
        ReplayCommandResult as Result, ReplayFrameCommandResult as Frame,
        ReplayInterfaceOutput as Interface, ReplayLinkMode as LinkMode,
        ReplaySourceFormat as SourceFormat, ReplayTimingOutput as Timing,
    };
}

/// Structured scan output.
pub mod scan {
    pub use super::internal::{
        ProbeEvidenceOutput as Evidence, ScanClassification as Classification,
        ScanCommandResult as Result, ScanPortCommandResult as PortResult, ScanPortOutput as Port,
        ScanProbeStatus as ProbeStatus, ScanStreamCommandResult as Event,
    };
}

/// Structured traceroute output.
pub mod traceroute {
    pub use super::internal::{
        TraceCompletionReason as Completion, TraceHopOutput as Hop, TraceProbeOutput as Probe,
        TraceProbeStatus as ProbeStatus, TraceResponseKind as ResponseKind,
        TraceUndecodedOutput as Undecoded, TracerouteCommandResult as Result,
        TracerouteStreamCommandResult as Event,
    };
}

/// Structured DNS output.
pub mod dns {
    pub use super::internal::{
        DnsAttemptOutput as Attempt, DnsAttemptStatus as AttemptStatus, DnsCommandResult as Result,
        DnsEdnsOptionOutput as EdnsOption, DnsEdnsOutput as Edns, DnsOutcome as Outcome,
        DnsRecordCommandResult as RecordResult, DnsRecordData as RecordData,
        DnsRecordOutput as Record, DnsRejectedRecordOutput as RejectedRecord,
        DnsSection as Section, DnsStreamCommandResult as Event, DnsUndecodedOutput as Undecoded,
    };
}

/// Structured packet-fuzzing output.
pub mod fuzz {
    pub use super::internal::{
        FuzzCaseOutcome as Outcome, FuzzCaseOutput as Case, FuzzCommandResult as Result,
        FuzzMode as Mode, FuzzMutation as Mutation, FuzzReproduction as Reproduction,
        FuzzStrategy as Strategy, FuzzStreamCommandResult as Event,
    };
}
