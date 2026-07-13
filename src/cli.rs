// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, IsTerminal, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

use crate::capture::{Format, Frame, Limits, LinkType, Reader, Writer, transcode};
use crate::client::{
    Client,
    exchange::{Event as ClientExchangeEvent, Options as ExchangeOptions},
    policy::{Error as TrafficPolicyError, Policy as TrafficPolicy},
    send::Options as SendOptions,
    target::{IpVersion, SystemResolver as SystemHostnameResolver, Target as LiveTarget},
};
use crate::error::{Classification, Classified, Kind};
use crate::net::capture::Provider as _;
use crate::net::exchange::Composite;
use crate::net::{
    CaptureFilter, CaptureMode, CaptureOptions, CaptureOverflowPolicy, CaptureQueueLimits,
    CaptureSession, DispatchPacketIo, InterfaceId, InterfaceInfo, InterfaceProvider,
    LinkCapability, LinkMode, LiveIoError, PlannedRoute, RouteDecision, RouteProvider,
    SystemCaptureProvider, SystemInterfaceProvider, SystemLayer2Io, SystemLayer3Io,
    SystemNeighborResolver, SystemRouteProvider,
};
use crate::operation::CompletionReason;
use crate::output::{
    AggregateErrorOutput, AggregateOutput, BuildCommandResult, CaptureFrameCommandResult,
    CommandName, DecodedFrameOutput, DissectCommandResult, DnsAttemptOutput, DnsAttemptStatus,
    DnsCommandResult, DnsOutcome, DnsRecordOutput, DnsSection, DnsStreamCommandResult,
    DnsUndecodedOutput, DoctorCapabilityOutput, DoctorCommandResult, DoctorReadiness,
    EnvelopeContext, ExchangeCommandResult, ExchangeStreamCommandResult, FrameOutput,
    FuzzCaseOutcome, FuzzCaseOutput, FuzzCommandResult, FuzzMode, FuzzStreamCommandResult,
    InterfacesCommandResult, OutputContractError, OutputError, OutputFormat, PlanCommandResult,
    ReadCompleteCommandResult, ReadFrameCommandResult, ReplayCommandResult,
    ReplayFrameCommandResult, RoutesCommandResult, ScanCommandResult, ScanPortOutput,
    ScanStreamCommandResult, SendCommandResult, StreamErrorRecord, StreamRecord,
    TraceCompletionReason, TraceHopOutput, TraceProbeStatus, TraceResponseKind,
    TraceUndecodedOutput, TracerouteCommandResult, TracerouteStreamCommandResult, WireFrameOutput,
    install_process_context,
};
use crate::packet::internal::{
    BuildContext, BuildMode, BuildOptions, Builder, DEFAULT_MAX_DOCUMENT_BYTES,
    DEFAULT_MAX_DOCUMENT_NESTING, DEFAULT_MAX_LAYERS, DecodeOptions, Dissector, DocumentFormat,
    ExpressionOptions, Packet, PacketDocument, PacketTemplate, parse_packet_expression,
};
use crate::workflow::dns::{
    ClientExecutor as ClientDnsExecutor, PolicyAuthorizer as TrafficPolicyDnsAuthorizer,
};
use crate::workflow::fuzz::{
    ClientExecutor as ClientFuzzExecutor, PolicyAuthorizer as TrafficPolicyFuzzAuthorizer,
};
use crate::workflow::replay::{
    SystemAuthorizer as ReplaySystemAuthorizer, SystemTransmitter as ReplaySystemTransmitter,
    Timing as ReplayTiming,
};
use crate::workflow::scan::{
    ClientExecutor as ClientScanExecutor, PolicyAuthorizer as TrafficPolicyScanAuthorizer,
};
use crate::workflow::traceroute::{
    ClientExecutor as ClientTracerouteExecutor,
    PolicyAuthorizer as TrafficPolicyTracerouteAuthorizer,
};
use crate::workflow_api::{
    AddressFamily, DnsError, DnsEvent, DnsExchange, DnsExchangeExecution, DnsExecutionError,
    DnsExecutor, DnsLimits, DnsQueryType, DnsRequest, FuzzCaseExecution, FuzzError, FuzzEvent,
    FuzzExecutionCase, FuzzExecutionError, FuzzExecutor, FuzzLimits, FuzzLiveOptions, FuzzRequest,
    FuzzStrategy, FuzzTarget, ReplayError, ReplayLimits, ReplayOptions, ScanBatch,
    ScanBatchExecution, ScanError, ScanEvent, ScanExecutionError, ScanExecutor, ScanLimits,
    ScanRequest, ScanTarget, ScanTransport, SystemClock, TracerouteBatch, TracerouteBatchExecution,
    TracerouteError, TracerouteEvent, TracerouteExecutionError, TracerouteExecutor,
    TracerouteLimits, TracerouteRequest, TracerouteStrategy, dns_streaming, execute_replay,
    fuzz_live_streaming, fuzz_streaming, prepare_replay, scan_streaming, traceroute_streaming,
};

include!("cli/arguments.rs");
include!("cli/errors.rs");
include!("cli/input.rs");
include!("cli/rendering.rs");
include!("cli/runtime.rs");

include!("cli/commands/network.rs");
include!("cli/commands/capture.rs");
include!("cli/commands/scan.rs");
include!("cli/commands/dns.rs");
include!("cli/commands/fuzz.rs");
include!("cli/commands/traceroute.rs");
include!("cli/commands/offline.rs");
include!("cli/commands/replay.rs");
include!("cli/commands/interfaces.rs");
include!("cli/commands/doctor.rs");

include!("cli/tests.rs");
