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
#![forbid(unsafe_code)]

pub mod client;
pub mod core;
pub mod io;
pub mod protocols;
pub mod session;
mod v2_cli;

pub use client::{
    CaptureOverflowPolicy, CaptureQueueLimits, CaptureSession, CaptureStatistics, Client,
    ClientError, ExchangeIo, ExchangeOptions, ExchangeResult, IoSendReport, LiveIoError,
    MatchedResponse, OperationStats, PacketIo, SendOptions, SendReport, TrafficPolicy,
    TrafficPolicyError, TransmissionFrame, UnsupportedNeighborResolver, UnsupportedPacketIo,
    DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES, DEFAULT_MAX_UNSOLICITED_FRAMES,
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
pub use io::{
    CaptureDirection, CaptureError, CaptureFileFormat, CaptureReader, CaptureRecordError,
    CaptureWriter, CapturedFrame, DestinationScope, InterfaceId, LinkCapability, LinkMode,
    LinkType, MacAddress, MaterializedRoute, NeighborError, NeighborResolver, PcapEndianness,
    PlanError, PlanOptions, PlannedRoute, ReplayTiming, RouteDecision, RoutePlanner, RouteProvider,
    DEFAULT_CAPTURE_SIZE_LIMIT, DEFAULT_PCAPNG_INTERFACE_LIMIT,
    DEFAULT_PCAPNG_METADATA_BLOCK_LIMIT,
};
pub use protocols::{
    default_registry, Arp, BsdLoop, BsdNull, BuiltinProtocols, DestinationOptions, Ethernet,
    HopByHop, Icmpv4, Icmpv6, Ipv4, Ipv6, Ipv6Fragment, LinuxSll, LinuxSll2, SegmentRoutingHeader,
    Tcp, Udp, Vlan, Vlan8021ad,
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
