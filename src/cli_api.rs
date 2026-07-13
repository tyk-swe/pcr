// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Binary-private vocabulary adapter for command handling.
//!
//! Every item in this module is imported from PacketcraftR's public API, just
//! as it would be by a downstream binary. The established command
//! implementation can therefore retain its local vocabulary without exposing
//! compatibility aliases from the library.

#![forbid(unsafe_code)]

pub(crate) use packetcraftr::{capture, client, error, workflow};

pub(crate) mod packet {
    pub(crate) mod internal {
        pub(crate) use packetcraftr::packet::build::{
            Builder, Context as BuildContext, Mode as BuildMode, Options as BuildOptions,
            DEFAULT_MAX_LAYERS,
        };
        pub(crate) use packetcraftr::packet::decode::{
            Decoder as Dissector, Options as DecodeOptions,
        };
        pub(crate) use packetcraftr::packet::diagnostic::Diagnostic;
        pub(crate) use packetcraftr::packet::document::{
            Format as DocumentFormat, Packet as PacketDocument, DEFAULT_MAX_DOCUMENT_BYTES,
            DEFAULT_MAX_DOCUMENT_NESTING,
        };
        pub(crate) use packetcraftr::packet::expression::{
            decode_hex, parse as parse_packet_expression, Options as ExpressionOptions,
        };
        pub(crate) use packetcraftr::packet::registry::Registry as ProtocolRegistry;
        pub(crate) use packetcraftr::packet::template::{
            Template as PacketTemplate, DEFAULT_MAX_TEMPLATE_PACKETS,
        };
        pub(crate) use packetcraftr::packet::Packet;
    }
}

pub(crate) mod protocol {
    pub(crate) mod internal {
        pub(crate) use packetcraftr::protocol::builtin::registry as default_registry;
    }
}

pub(crate) mod net {
    use std::time::Duration;

    #[cfg(test)]
    pub(crate) use packetcraftr::net::capture::Statistics as CaptureStatistics;
    pub(crate) use packetcraftr::net::capture::{
        Limits as CaptureQueueLimits, OverflowPolicy as CaptureOverflowPolicy,
        Session as CaptureSession, SystemProvider as SystemCaptureProvider,
    };
    pub(crate) use packetcraftr::net::interface::{
        Id as InterfaceId, Provider as InterfaceProvider, SystemProvider as SystemInterfaceProvider,
    };
    pub(crate) use packetcraftr::net::link::Mode as LinkMode;
    pub(crate) use packetcraftr::net::neighbor::SystemResolver as SystemNeighborResolver;
    pub(crate) use packetcraftr::net::route::{
        Options as PlanOptions, Provider as RouteProvider, SystemProvider as SystemRouteProvider,
    };
    pub(crate) use packetcraftr::net::transmit::{
        Dispatch as DispatchPacketIo, SystemLayer2 as SystemLayer2Io,
        SystemLayer3 as SystemLayer3Io,
    };
    pub(crate) use packetcraftr::net::Error as LiveIoError;
    pub(crate) use packetcraftr::net::{capture, exchange};

    // These defaults are binary presentation/configuration details. The live
    // provider validates the resulting public `capture::Limits` values.
    pub(crate) const DEFAULT_CAPTURE_QUEUE_FRAMES: usize = 4_096;
    pub(crate) const DEFAULT_CAPTURE_QUEUE_BYTES: usize = 256 * 1024 * 1024;
    pub(crate) const MAX_CAPTURE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
}

pub(crate) mod output {
    pub(crate) use packetcraftr::output::build::Result as BuildCommandResult;
    pub(crate) use packetcraftr::output::capture::{
        Event as CaptureFrameCommandResult, Read as ReadFrameCommandResult,
    };
    pub(crate) use packetcraftr::output::contract::{
        Command as CommandName, Error as OutputContractError, Format as OutputFormat,
        CONTRACTS as COMMAND_OUTPUT_CONTRACTS,
    };
    pub(crate) use packetcraftr::output::dissect::Result as DissectCommandResult;
    pub(crate) use packetcraftr::output::dns::{
        AttemptStatus as DnsAttemptStatus, Event as DnsStreamCommandResult, Outcome as DnsOutcome,
        Record as DnsRecordOutput, Result as DnsCommandResult, Section as DnsSection,
    };
    pub(crate) use packetcraftr::output::envelope::{
        Aggregate as AggregateOutput, AggregateError as AggregateErrorOutput, Error as OutputError,
        Stream as StreamRecord, StreamError as StreamErrorRecord,
    };
    #[cfg(test)]
    pub(crate) use packetcraftr::output::frame;
    pub(crate) use packetcraftr::output::frame::{
        Captured as FrameOutput, Timestamp as OutputTimestamp,
    };
    pub(crate) use packetcraftr::output::fuzz::{
        Event as FuzzStreamCommandResult, Mode as FuzzMode, Outcome as FuzzCaseOutcome,
        Result as FuzzCommandResult,
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
        Event as ScanStreamCommandResult, Result as ScanCommandResult,
    };
    pub(crate) use packetcraftr::output::traceroute::{
        Completion as TraceCompletionReason, Event as TracerouteStreamCommandResult,
        ProbeStatus as TraceProbeStatus, ResponseKind as TraceResponseKind,
        Result as TracerouteCommandResult,
    };
    pub(crate) use packetcraftr::output::{envelope, network, scan};
}

pub(crate) mod workflow_api {
    pub(crate) use packetcraftr::workflow::clock::System as SystemDnsClock;
    pub(crate) use packetcraftr::workflow::clock::System as SystemFuzzClock;
    pub(crate) use packetcraftr::workflow::clock::System as SystemReplayClock;
    pub(crate) use packetcraftr::workflow::clock::System as SystemScanClock;
    pub(crate) use packetcraftr::workflow::clock::System as SystemTracerouteClock;

    pub(crate) use packetcraftr::workflow::AddressFamily as DnsAddressFamily;
    pub(crate) use packetcraftr::workflow::AddressFamily as ScanAddressFamily;
    pub(crate) use packetcraftr::workflow::AddressFamily as TracerouteAddressFamily;

    pub(crate) use packetcraftr::workflow::dns::{
        run as dns, Error as DnsError, Exchange as DnsExchange, Execution as DnsExchangeExecution,
        ExecutionError as DnsExecutionError, Executor as DnsExecutor, Limits as DnsLimits,
        QueryType as DnsQueryType, Request as DnsRequest,
    };
    pub(crate) use packetcraftr::workflow::fuzz::{
        run as fuzz, run_live as fuzz_live, Error as FuzzError, Execution as FuzzCaseExecution,
        ExecutionCase as FuzzExecutionCase, ExecutionError as FuzzExecutionError,
        Executor as FuzzExecutor, Limits as FuzzLimits, LiveOptions as FuzzLiveOptions,
        Request as FuzzRequest, Strategy as FuzzStrategy, Target as FuzzTarget,
    };
    pub(crate) use packetcraftr::workflow::replay::{
        run as replay_capture, Error as ReplayError, FrameEvidence as ReplayFrameEvidence,
        Limits as ReplayLimits, Options as ReplayOptions, Summary as ReplaySummary,
    };
    pub(crate) use packetcraftr::workflow::scan::{
        run as scan, Batch as ScanBatch, Error as ScanError, Execution as ScanBatchExecution,
        ExecutionError as ScanExecutionError, Executor as ScanExecutor, Limits as ScanLimits,
        Request as ScanRequest, Transport as ScanTransport,
    };
    pub(crate) use packetcraftr::workflow::target::Target as ScanTarget;
    pub(crate) use packetcraftr::workflow::traceroute::{
        run as traceroute, Batch as TracerouteBatch, Error as TracerouteError,
        Execution as TracerouteBatchExecution, ExecutionError as TracerouteExecutionError,
        Executor as TracerouteExecutor, Limits as TracerouteLimits, Request as TracerouteRequest,
        Strategy as TracerouteStrategy,
    };

    pub(crate) use packetcraftr::workflow::dns::{
        DEFAULT_DNS_ATTEMPTS, DEFAULT_DNS_SERVER_PORT, DEFAULT_MAX_DNS_NAME_POINTERS,
        DEFAULT_MAX_DNS_RECORDS, DEFAULT_MAX_DNS_TXT_BYTES, DEFAULT_MAX_DNS_TXT_STRINGS,
        DEFAULT_MAX_REJECTED_DNS_RECORDS, DEFAULT_MAX_UNDECODED_DNS_FRAMES,
        DNS_EPHEMERAL_SOURCE_PORT_BASE, MAX_DNS_MESSAGE_BYTES,
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
