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

#![warn(unreachable_pub)]
#![deny(unsafe_code)]

pub mod client;
pub mod core;
pub mod error;
pub mod io;
pub mod output;
pub mod protocols;
pub mod session;
pub mod tools;
mod v2_cli;

pub use client::{
    Client, ClientError, ExchangeOptions, ExchangeResult, Hostname, HostnameResolver, LiveTarget,
    MatchedResponse, OperationStats, ResolvedTarget, SendOptions, SendReport,
    SystemHostnameResolver, TargetResolutionError, TrafficPolicy, TrafficPolicyError,
    UnsupportedNeighborResolver, UnsupportedPacketIo, DEFAULT_MAX_RESOLVED_ADDRESSES,
    DEFAULT_MAX_UNSOLICITED_FRAMES, MAX_EXCHANGE_TIMEOUT, MAX_RESOLVED_ADDRESSES,
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
    ClassifiedError, ErrorClassification, FailureKind, EXIT_CAPABILITY, EXIT_CLI, EXIT_INTERNAL,
    EXIT_IO, EXIT_PACKET, EXIT_POLICY,
};
pub use io::{
    ActiveNeighborResolver, CaptureDirection, CaptureError, CaptureFileFormat,
    CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureReader, CaptureRecordError,
    CaptureSession, CaptureStatistics, CaptureWriter, CapturedFrame, DestinationScope,
    DispatchPacketIo, ExchangeIo, InterfaceAddress, InterfaceFlags, InterfaceId, InterfaceInfo,
    InterfaceProvider, IoSendReport, Layer2Frame, Layer2Io, Layer3Frame, Layer3Io, LinkCapability,
    LinkMode, LinkType, LiveIoError, MacAddress, MaterializedRoute, NativeRouteError,
    NeighborError, NeighborRequest, NeighborResolution, NeighborResolutionOptions,
    NeighborResolver, NeighborVlanKind, NeighborVlanTag, PacketIo, PcapEndianness, PlanError,
    PlanOptions, PlannedRoute, ReplayTiming, RouteDecision, RoutePlanner, RouteProvider,
    RouteSelectionReason, SystemCaptureProvider, SystemCaptureSession, SystemInterfaceProvider,
    SystemLayer2Io, SystemLayer3Io, SystemNeighborResolver, SystemRouteProvider, TransmissionFrame,
    DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES, DEFAULT_CAPTURE_SIZE_LIMIT,
    DEFAULT_PCAPNG_INTERFACE_LIMIT, DEFAULT_PCAPNG_METADATA_BLOCK_LIMIT, MAX_CAPTURE_TIMEOUT,
    MAX_NEIGHBOR_VLAN_TAGS,
};
pub use output::{
    AggregateErrorOutput, AggregateOutput, BuildCommandResult, CaptureFrameCommandResult,
    CommandName, CommandOutputContract, DissectCommandResult, DnsCommandResult,
    DnsRecordCommandResult, DnsRecordData, DnsRecordOutput, DnsSection, ExchangeCommandResult,
    ExchangeResponseOutput, ExchangeStreamCommandResult, FrameOutput, FuzzCaseCommandResult,
    FuzzCaseOutcome, FuzzCaseOutput, FuzzCommandResult, InterfaceOutput, InterfacesCommandResult,
    MaterializedRouteOutput, NeighborEvidenceOutput, OutputContractError, OutputError,
    OutputFormat, OutputMode, OutputTimestamp, PlanCommandResult, ProbeEvidenceOutput,
    ReadFrameCommandResult, ReplayCommandResult, ReplayFrameCommandResult, RoutesCommandResult,
    ScanClassification, ScanCommandResult, ScanPortCommandResult, ScanPortOutput,
    SendCommandResult, StreamErrorRecord, StreamRecord, TraceCompletionReason, TraceHopOutput,
    TraceProbeOutput, TraceProbeStatus, TracerouteCommandResult, TracerouteHopCommandResult,
    WireFrameOutput, COMMAND_OUTPUT_CONTRACTS, OUTPUT_SCHEMA_V1,
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

/// Run the intentionally breaking v0.2 command-line interface.
pub fn run_cli_entrypoint() -> std::process::ExitCode {
    v2_cli::run_entrypoint()
}
