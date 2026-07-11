// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! PacketcraftR's runtime-neutral packet model, protocol registry, exact builder,
//! bounded dissector, offline capture I/O, session stages, and high-level client.
//!
//! ```
//! use packetcraftr::{BuildContext, BuildOptions, Builder, Packet, Raw};
//! use std::sync::Arc;
//!
//! let registry = Arc::new(packetcraftr::default_registry()?);
//! let mut packet = Packet::new();
//! packet.push(Raw::new(vec![0xde, 0xad, 0xbe, 0xef]));
//! let built = Builder::new(registry).build(
//!     packet,
//!     BuildContext::default(),
//!     BuildOptions::default(),
//! )?;
//! assert_eq!(built.bytes.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![doc = include_str!("../docs/public-api.md")]
#![warn(unreachable_pub)]
#![forbid(unsafe_code)]

pub mod client;
pub mod output;
pub mod tools;
mod v2_cli;

pub use packetcraftr_core::{core, error};
pub use packetcraftr_io::io;
pub use packetcraftr_protocols::protocols;
pub use packetcraftr_session::session;

pub use client::{
    Client, ClientDnsExecutor, ClientError, ClientFuzzExecutor, ClientScanExecutor,
    ClientTracerouteExecutor, ExchangeOptions, ExchangeResult, Hostname, HostnameResolver,
    LiveTarget, MatchedResponse, OperationStats, ResolvedTarget, SendOptions, SendReport,
    SystemHostnameResolver, TargetResolutionError, TrafficPolicy, TrafficPolicyDnsAuthorizer,
    TrafficPolicyError, TrafficPolicyFuzzAuthorizer, TrafficPolicyScanAuthorizer,
    TrafficPolicyTracerouteAuthorizer, UnsupportedNeighborResolver, UnsupportedPacketIo,
    DEFAULT_MAX_RESOLVED_ADDRESSES, DEFAULT_MAX_UNSOLICITED_FRAMES, MAX_EXCHANGE_TIMEOUT,
    MAX_RESOLVED_ADDRESSES,
};
pub use core::{
    BuildContext, BuildError, BuildMode, BuildOptions, Builder, BuiltPacket, ByteRange, CodecError,
    DecodeError, DecodeOptions, DecodedLayerValue, DecodedPacket, Diagnostic, DiagnosticSeverity,
    Discriminator, Dissector, DocumentError, DocumentFormat, EncodedLayer, ExpressionError,
    ExpressionOptions, FieldError, FieldKind, FieldLayout, FieldSchema, FieldValue, Layer,
    LayerCodec, LayerDecodeContext, LayerDocument, LayerEncodeContext, LayerLayout, LayerSchema,
    MalformedLayer, MatchResult, NetworkEnvelope, Packet, PacketDocument, PacketError,
    PacketLayout, PacketTemplate, PacketTemplateIter, PacketTransform, Padding, ProtocolId,
    ProtocolModule, ProtocolRegistry, Raw, RegistryBuilder, RegistryError, ResponseMatcher,
    TemplateError, TemplateValues, WireValue,
};
pub use error::{
    ClassifiedError, ErrorClassification, FailureCategory, FailureKind, EXIT_CAPABILITY, EXIT_CLI,
    EXIT_INTERNAL, EXIT_IO, EXIT_PACKET, EXIT_POLICY,
};
pub use io::{
    transcode_capture, ActiveNeighborResolver, CaptureDirection, CaptureError,
    CaptureEvidenceCompleteness, CaptureFileFormat, CaptureInterface, CaptureOverflowPolicy,
    CaptureProvider, CaptureQueueLimits, CaptureReader, CaptureRecordError, CaptureSession,
    CaptureStatistics, CaptureStreamLimits, CaptureTimestampResolution, CaptureTranscodeReport,
    CaptureWriter, CapturedFrame, DestinationScope, DispatchPacketIo, ExchangeIo, InterfaceAddress,
    InterfaceFlags, InterfaceId, InterfaceInfo, InterfaceProvider, IoSendReport, Layer2Frame,
    Layer2Io, Layer3Frame, Layer3Io, LinkCapability, LinkMode, LinkType, LiveIoError, MacAddress,
    MaterializedRoute, NativeRouteError, NeighborError, NeighborRequest, NeighborResolution,
    NeighborResolutionOptions, NeighborResolver, NeighborVlanKind, NeighborVlanTag, PacketIo,
    PcapEndianness, PlanError, PlanOptions, PlannedRoute, ReplayTiming, RouteDecision,
    RoutePlanner, RouteProvider, RouteSelectionReason, SystemCaptureProvider, SystemCaptureSession,
    SystemInterfaceProvider, SystemLayer2Io, SystemLayer3Io, SystemNeighborResolver,
    SystemRouteProvider, TransmissionFrame, DEFAULT_CAPTURE_QUEUE_BYTES,
    DEFAULT_CAPTURE_QUEUE_FRAMES, DEFAULT_CAPTURE_SIZE_LIMIT, DEFAULT_CAPTURE_STREAM_BYTES,
    DEFAULT_CAPTURE_STREAM_FRAMES, DEFAULT_PCAPNG_INTERFACE_LIMIT,
    DEFAULT_PCAPNG_METADATA_BLOCK_LIMIT, MAX_CAPTURE_TIMEOUT, MAX_NEIGHBOR_VLAN_TAGS,
};
pub use output::{
    AggregateErrorOutput, AggregateOutput, BuildCommandResult, CaptureFrameCommandResult,
    CommandName, CommandOutputContract, DissectCommandResult, DnsAttemptOutput, DnsAttemptStatus,
    DnsCommandResult, DnsOutcome, DnsRecordCommandResult, DnsRecordData, DnsRecordOutput,
    DnsRejectedRecordOutput, DnsSection, DnsStreamCommandResult, DnsUndecodedOutput,
    ExchangeCommandResult, ExchangeResponseOutput, ExchangeStreamCommandResult, FrameOutput,
    FuzzCaseCommandResult, FuzzCaseOutcome, FuzzCaseOutput, FuzzCommandResult, FuzzMode,
    FuzzStreamCommandResult, InterfaceOutput, InterfacesCommandResult, MaterializedRouteOutput,
    NeighborEvidenceOutput, OutputContractError, OutputError, OutputFormat, OutputMode,
    OutputTimestamp, PlanCommandResult, ProbeEvidenceOutput, ReadFrameCommandResult,
    ReplayCommandResult, ReplayFrameCommandResult, RoutesCommandResult, ScanClassification,
    ScanCommandResult, ScanPortCommandResult, ScanPortOutput, ScanProbeStatus,
    ScanStreamCommandResult, SendCommandResult, StreamErrorRecord, StreamRecord,
    TraceCompletionReason, TraceHopOutput, TraceProbeOutput, TraceProbeStatus, TraceResponseKind,
    TraceUndecodedOutput, TracerouteCommandResult, TracerouteStreamCommandResult, WireFrameOutput,
    COMMAND_OUTPUT_CONTRACTS, OUTPUT_SCHEMA_V1,
};
pub use protocols::{
    default_registry, Arp, BsdLoop, BsdNull, BuiltinProtocols, CaptureByteOrder,
    CaptureRootByteOrder, CaptureRootSupport, DestinationOptions, Ethernet, HopByHop, Icmpv4,
    Icmpv6, Ipv4, Ipv6, Ipv6Fragment, LinuxSll, LinuxSll2, ProtocolFallbackSupport,
    ProtocolSupport, ProtocolSupportManifest, SegmentRoutingHeader, Tcp, Udp, Vlan, Vlan8021ad,
    WorkflowProtocolSupport, BUILTIN_CAPTURE_ROOTS, BUILTIN_PROTOCOLS, BUILTIN_PROTOCOL_SUPPORT,
    PROTOCOL_SUPPORT_SCHEMA_V1, STABLE_WORKFLOW_PROTOCOLS,
};
pub use session::{
    Fragment, FragmentError, FragmentKey, FragmentOverlapPolicy, FragmentReassembler,
    FragmentReassemblyEvent, ReassembledDatagram, ReassemblyLimits, TcpFlowKey, TcpReassembler,
    TcpReassemblyError, TcpReassemblyEvent, TcpSegment,
};
pub use tools::{
    canonical_query_name, classify_dns_response, classify_scan_response,
    classify_traceroute_response, decode_dns_response, decode_dns_tcp_frame, dns, encode_dns_query,
    fuzz, fuzz_live, replay_capture, response_code_name, scan, traceroute, AuthorizedDnsTarget,
    AuthorizedScanTarget, AuthorizedTracerouteTarget, DnsAddressFamily, DnsAttemptEvidence,
    DnsAuthorizationError, DnsAuthorizer, DnsClock, DnsError, DnsExchange, DnsExchangeExecution,
    DnsExecutionError, DnsExecutor, DnsLimits, DnsMatchedResponse, DnsProbe, DnsQueryType,
    DnsRecord, DnsRecordValue, DnsRejectedRecord, DnsRequest, DnsResponseClassification, DnsResult,
    DnsStats, DnsTarget, DnsTransport, DnsUndecodedEvidence, DnsWireError, FuzzAuthorizationError,
    FuzzAuthorizer, FuzzCase, FuzzCaseExecution, FuzzCaseFailure, FuzzClock, FuzzError,
    FuzzExecutionCase, FuzzExecutionError, FuzzExecutionStats, FuzzExecutor, FuzzLimits,
    FuzzLiveOptions, FuzzMutation, FuzzReproduction, FuzzRequest, FuzzResult, FuzzStats,
    FuzzStrategy, FuzzTarget, FuzzTargetParseError, ReplayAuthorizationError, ReplayAuthorizer,
    ReplayClock, ReplayError, ReplayFrameEvidence, ReplayLimits, ReplayOptions, ReplaySummary,
    ReplayTransmission, ReplayTransmitter, ScanAddressFamily, ScanAuthorizationError,
    ScanAuthorizer, ScanBatch, ScanBatchExecution, ScanClock, ScanEndpointResult, ScanError,
    ScanExecutionError, ScanExecutor, ScanLimits, ScanMatchedResponse, ScanProbe,
    ScanProbeEvidence, ScanRequest, ScanResponseClassification, ScanResult, ScanStats, ScanTarget,
    ScanTransport, SystemDnsClock, SystemFuzzClock, SystemReplayClock, SystemScanClock,
    SystemTracerouteClock, TracerouteAddressFamily, TracerouteAuthorizationError,
    TracerouteAuthorizer, TracerouteBatch, TracerouteBatchExecution, TracerouteClock,
    TracerouteCompletion, TracerouteError, TracerouteExecutionError, TracerouteExecutor,
    TracerouteHopResult, TracerouteLimits, TracerouteMatchedResponse, TracerouteProbe,
    TracerouteProbeEvidence, TracerouteProbeStatus, TracerouteRequest,
    TracerouteResponseClassification, TracerouteResponseKind, TracerouteResult, TracerouteStats,
    TracerouteStrategy, TracerouteTarget, TracerouteUndecodedEvidence, ValidatedDnsResponse,
    DEFAULT_DNS_ATTEMPTS, DEFAULT_DNS_SERVER_PORT, DEFAULT_FUZZ_CASES,
    DEFAULT_MAX_DNS_NAME_POINTERS, DEFAULT_MAX_DNS_RECORDS, DEFAULT_MAX_DNS_TXT_BYTES,
    DEFAULT_MAX_DNS_TXT_STRINGS, DEFAULT_MAX_FUZZ_CASES, DEFAULT_MAX_FUZZ_FIELD_BYTES,
    DEFAULT_MAX_FUZZ_LIST_ITEMS, DEFAULT_MAX_FUZZ_SHRINK_STEPS, DEFAULT_MAX_REJECTED_DNS_RECORDS,
    DEFAULT_MAX_SCAN_PORTS, DEFAULT_MAX_UNDECODED_DNS_FRAMES, DEFAULT_MAX_UNDECODED_SCAN_FRAMES,
    DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES, DEFAULT_SCAN_BATCH_SIZE, DEFAULT_TRACEROUTE_FIRST_HOP,
    DEFAULT_TRACEROUTE_MAX_HOPS, DEFAULT_TRACEROUTE_PROBES_PER_HOP, DEFAULT_TRACEROUTE_TCP_PORT,
    DEFAULT_TRACEROUTE_UDP_PORT, DNS_EPHEMERAL_SOURCE_PORT_BASE, DNS_HEADER_BYTES,
    MAX_DNS_ATTEMPTS, MAX_DNS_DURATION, MAX_DNS_MESSAGE_BYTES, MAX_DNS_NAME_POINTERS,
    MAX_DNS_RECORDS, MAX_FUZZ_CASES, MAX_FUZZ_DURATION, MAX_FUZZ_FIELD_BYTES, MAX_FUZZ_LIST_ITEMS,
    MAX_FUZZ_RATE, MAX_FUZZ_SHRINK_STEPS, MAX_FUZZ_STRATEGIES, MAX_FUZZ_TARGET_FIELDS,
    MAX_REPLAY_DURATION, MAX_SCAN_ATTEMPTS, MAX_SCAN_DURATION, MAX_SCAN_PROBES, MAX_SCAN_RATE,
    MAX_TRACEROUTE_DURATION, MAX_TRACEROUTE_PROBES_PER_HOP,
};

/// Run the intentionally breaking v0.2 command-line interface.
pub fn run_cli_entrypoint() -> std::process::ExitCode {
    v2_cli::run_entrypoint()
}
