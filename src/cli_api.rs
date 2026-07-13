// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Binary-private vocabulary adapter for command handling.
//!
//! Every item in this module is imported from PacketcraftR's public API, just
//! as it would be by a downstream binary. The established command
//! implementation can therefore retain its local vocabulary without exposing
//! compatibility aliases from the library.

#![forbid(unsafe_code)]

pub(crate) use packetcraftr::{capture, client, error, operation, workflow};

pub(crate) mod packet {
    pub(crate) mod internal {
        pub(crate) use packetcraftr::packet::Packet;
        pub(crate) use packetcraftr::packet::build::{
            Builder, Context as BuildContext, DEFAULT_MAX_LAYERS, Mode as BuildMode,
            Options as BuildOptions,
        };
        pub(crate) use packetcraftr::packet::decode::{
            Decoder as Dissector, Options as DecodeOptions,
        };
        pub(crate) use packetcraftr::packet::diagnostic::Diagnostic;
        pub(crate) use packetcraftr::packet::document::{
            DEFAULT_MAX_DOCUMENT_BYTES, DEFAULT_MAX_DOCUMENT_NESTING, Format as DocumentFormat,
            Packet as PacketDocument,
        };
        pub(crate) use packetcraftr::packet::expression::{
            Options as ExpressionOptions, decode_hex, parse as parse_packet_expression,
        };
        pub(crate) use packetcraftr::packet::registry::Registry as ProtocolRegistry;
        pub(crate) use packetcraftr::packet::template::{
            DEFAULT_MAX_TEMPLATE_PACKETS, Template as PacketTemplate,
        };
    }
}

pub(crate) mod protocol {
    pub(crate) mod internal {
        pub(crate) use packetcraftr::protocol::builtin::registry as default_registry;
    }
}

pub(crate) mod net {
    use std::time::Duration;

    pub(crate) use packetcraftr::net::Error as LiveIoError;
    #[cfg(test)]
    pub(crate) use packetcraftr::net::capture::Statistics as CaptureStatistics;
    pub(crate) use packetcraftr::net::capture::{
        Filter as CaptureFilter, Limits as CaptureQueueLimits, Mode as CaptureMode,
        Options as CaptureOptions, OverflowPolicy as CaptureOverflowPolicy,
        Session as CaptureSession, SystemProvider as SystemCaptureProvider,
    };
    pub(crate) use packetcraftr::net::interface::{
        Id as InterfaceId, Info as InterfaceInfo, Provider as InterfaceProvider,
        SystemProvider as SystemInterfaceProvider,
    };
    pub(crate) use packetcraftr::net::link::{Capability as LinkCapability, Mode as LinkMode};
    pub(crate) use packetcraftr::net::neighbor::SystemResolver as SystemNeighborResolver;
    pub(crate) use packetcraftr::net::route::{
        Decision as RouteDecision, Options as PlanOptions, Plan as PlannedRoute,
        Provider as RouteProvider, SystemProvider as SystemRouteProvider,
    };
    pub(crate) use packetcraftr::net::transmit::{
        Dispatch as DispatchPacketIo, SystemLayer2 as SystemLayer2Io,
        SystemLayer3 as SystemLayer3Io,
    };
    pub(crate) use packetcraftr::net::{capture, exchange};

    // These defaults are binary presentation/configuration details. The live
    // provider validates the resulting public `capture::Limits` values.
    pub(crate) const DEFAULT_CAPTURE_QUEUE_FRAMES: usize = 4_096;
    pub(crate) const DEFAULT_CAPTURE_QUEUE_BYTES: usize = 256 * 1024 * 1024;
    pub(crate) const DEFAULT_EVIDENCE_BYTES: usize =
        packetcraftr::client::exchange::DEFAULT_EVIDENCE_BYTES;
    pub(crate) const MAX_EVIDENCE_BYTES: usize = packetcraftr::client::exchange::MAX_EVIDENCE_BYTES;
    pub(crate) const MAX_CAPTURE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
}

pub(crate) mod output {
    pub(crate) use packetcraftr::output::build::Result as BuildCommandResult;
    pub(crate) use packetcraftr::output::capture::{
        Event as CaptureFrameCommandResult, Read as ReadFrameCommandResult,
        ReadComplete as ReadCompleteCommandResult,
    };
    pub(crate) use packetcraftr::output::contract::{
        Command as CommandName, Error as OutputContractError, Format as OutputFormat,
    };
    pub(crate) use packetcraftr::output::dissect::Result as DissectCommandResult;
    pub(crate) use packetcraftr::output::dns::{
        Attempt as DnsAttemptOutput, AttemptStatus as DnsAttemptStatus,
        Event as DnsStreamCommandResult, Outcome as DnsOutcome, Record as DnsRecordOutput,
        Result as DnsCommandResult, Section as DnsSection, Undecoded as DnsUndecodedOutput,
    };
    pub(crate) use packetcraftr::output::doctor::{
        Capability as DoctorCapabilityOutput, Readiness as DoctorReadiness,
        Result as DoctorCommandResult,
    };
    pub(crate) use packetcraftr::output::envelope::{
        Aggregate as AggregateOutput, AggregateError as AggregateErrorOutput,
        Context as EnvelopeContext, Error as OutputError, Stream as StreamRecord,
        StreamError as StreamErrorRecord, install_process_context,
    };
    #[cfg(test)]
    pub(crate) use packetcraftr::output::frame;
    pub(crate) use packetcraftr::output::frame::{
        Captured as FrameOutput, Timestamp as OutputTimestamp, Wire as WireFrameOutput,
    };
    pub(crate) use packetcraftr::output::fuzz::{
        Case as FuzzCaseOutput, Event as FuzzStreamCommandResult, Mode as FuzzMode,
        Outcome as FuzzCaseOutcome, Result as FuzzCommandResult,
    };
    pub(crate) use packetcraftr::output::network::exchange::{
        Event as ExchangeStreamCommandResult, Result as ExchangeCommandResult,
    };
    pub(crate) use packetcraftr::output::network::interfaces::Result as InterfacesCommandResult;
    pub(crate) use packetcraftr::output::network::plan::Result as PlanCommandResult;
    pub(crate) use packetcraftr::output::network::routes::Result as RoutesCommandResult;
    pub(crate) use packetcraftr::output::network::send::Result as SendCommandResult;
    pub(crate) use packetcraftr::output::replay::{
        Frame as ReplayFrameCommandResult, Result as ReplayCommandResult,
    };
    pub(crate) use packetcraftr::output::scan::{
        Event as ScanStreamCommandResult, Port as ScanPortOutput, Result as ScanCommandResult,
    };
    pub(crate) use packetcraftr::output::traceroute::{
        Completion as TraceCompletionReason, Event as TracerouteStreamCommandResult,
        Hop as TraceHopOutput, ProbeStatus as TraceProbeStatus, ResponseKind as TraceResponseKind,
        Result as TracerouteCommandResult, Undecoded as TraceUndecodedOutput,
    };
    pub(crate) use packetcraftr::output::{envelope, network, scan};
}

pub(crate) mod workflow_api {
    pub(crate) use packetcraftr::workflow::AddressFamily;
    pub(crate) use packetcraftr::workflow::clock::System as SystemClock;

    pub(crate) use packetcraftr::workflow::dns::{
        Error as DnsError, Event as DnsEvent, Exchange as DnsExchange,
        Execution as DnsExchangeExecution, ExecutionError as DnsExecutionError,
        Executor as DnsExecutor, Limits as DnsLimits, QueryType as DnsQueryType,
        Request as DnsRequest, run_streaming as dns_streaming,
    };
    pub(crate) use packetcraftr::workflow::fuzz::{
        Error as FuzzError, Event as FuzzEvent, Execution as FuzzCaseExecution,
        ExecutionCase as FuzzExecutionCase, ExecutionError as FuzzExecutionError,
        Executor as FuzzExecutor, Limits as FuzzLimits, LiveOptions as FuzzLiveOptions,
        Request as FuzzRequest, Strategy as FuzzStrategy, Target as FuzzTarget,
        run_live_streaming as fuzz_live_streaming, run_streaming as fuzz_streaming,
    };
    pub(crate) use packetcraftr::workflow::replay::{
        Error as ReplayError, FrameEvidence as ReplayFrameEvidence, Limits as ReplayLimits,
        Options as ReplayOptions, Summary as ReplaySummary, execute as execute_replay,
        prepare as prepare_replay,
    };
    pub(crate) use packetcraftr::workflow::scan::{
        Batch as ScanBatch, Error as ScanError, Event as ScanEvent,
        Execution as ScanBatchExecution, ExecutionError as ScanExecutionError,
        Executor as ScanExecutor, Limits as ScanLimits, Request as ScanRequest,
        Transport as ScanTransport, run_streaming as scan_streaming,
    };
    pub(crate) use packetcraftr::workflow::target::Target as ScanTarget;
    pub(crate) use packetcraftr::workflow::traceroute::{
        Batch as TracerouteBatch, Error as TracerouteError, Event as TracerouteEvent,
        Execution as TracerouteBatchExecution, ExecutionError as TracerouteExecutionError,
        Executor as TracerouteExecutor, Limits as TracerouteLimits, Request as TracerouteRequest,
        Strategy as TracerouteStrategy, run_streaming as traceroute_streaming,
    };

    pub(crate) use packetcraftr::workflow::dns::{
        DEFAULT_DNS_ATTEMPTS, DEFAULT_DNS_SERVER_PORT, DEFAULT_MAX_DNS_NAME_POINTERS,
        DEFAULT_MAX_DNS_RECORDS, DEFAULT_MAX_DNS_TXT_BYTES, DEFAULT_MAX_DNS_TXT_STRINGS,
        DEFAULT_MAX_REJECTED_DNS_RECORDS, DEFAULT_MAX_UNDECODED_DNS_FRAMES, MAX_DNS_MESSAGE_BYTES,
    };
    pub(crate) use packetcraftr::workflow::fuzz::{
        DEFAULT_FUZZ_CASES, DEFAULT_MAX_FUZZ_CASES, DEFAULT_MAX_FUZZ_FIELD_BYTES,
        DEFAULT_MAX_FUZZ_LIST_ITEMS, DEFAULT_MAX_FUZZ_SHRINK_STEPS,
    };
    pub(crate) use packetcraftr::workflow::scan::{
        DEFAULT_MAX_SCAN_PORTS, DEFAULT_MAX_UNDECODED_SCAN_FRAMES, DEFAULT_SCAN_BATCH_SIZE,
    };
    pub(crate) use packetcraftr::workflow::traceroute::{
        DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES, DEFAULT_TRACEROUTE_FIRST_HOP,
        DEFAULT_TRACEROUTE_MAX_HOPS, DEFAULT_TRACEROUTE_PROBES_PER_HOP,
        DEFAULT_TRACEROUTE_TCP_PORT, DEFAULT_TRACEROUTE_UDP_PORT,
    };
}
