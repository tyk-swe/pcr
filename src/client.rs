// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::{
    BuildContext, BuildError, BuildOptions, Builder, BuiltPacket, DecodeOptions, DecodedPacket,
    Dissector, FieldValue, Packet, PacketTemplate, Padding, ProtocolRegistry,
    DEFAULT_MAX_TEMPLATE_PACKETS,
};
use crate::io::{
    CapturedFrame, MaterializedRoute, NeighborError, NeighborResolver, PlanError, PlanOptions,
    PlannedRoute, RoutePlanner, RouteProvider,
};
use crate::protocols::Ethernet;

// Compatibility surface: provider implementations historically imported these
// contracts through `packetcraftr::client`. Their ownership is now `io`.
pub use crate::io::{
    CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureSession, CaptureStatistics,
    DispatchPacketIo, ExchangeIo, InterfaceAddress, InterfaceFlags, InterfaceInfo,
    InterfaceProvider, IoSendReport, Layer2Frame, Layer2Io, Layer3Frame, Layer3Io, LiveIoError,
    PacketIo, SystemInterfaceProvider, TransmissionFrame, DEFAULT_CAPTURE_QUEUE_BYTES,
    DEFAULT_CAPTURE_QUEUE_FRAMES,
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationStats {
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: CaptureStatistics,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficPolicy {
    pub allow_public_destinations: bool,
    pub allow_permissive_packets: bool,
    pub max_packets_per_operation: u64,
    pub max_bytes_per_operation: u64,
}

impl Default for TrafficPolicy {
    fn default() -> Self {
        Self {
            allow_public_destinations: false,
            allow_permissive_packets: false,
            max_packets_per_operation: 10_000,
            max_bytes_per_operation: 256 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrafficPolicyError {
    #[error("traffic policy denies public destination {destination}")]
    PublicDestination { destination: IpAddr },
    #[error("traffic policy denies permissively built packets")]
    PermissivePacket,
    #[error("operation packet count {actual} exceeds policy limit {limit}")]
    PacketLimit { actual: u64, limit: u64 },
    #[error("operation byte count {actual} exceeds policy limit {limit}")]
    ByteLimit { actual: u64, limit: u64 },
}

impl TrafficPolicy {
    fn authorize_destination(&self, destination: IpAddr) -> Result<(), TrafficPolicyError> {
        if !self.allow_public_destinations && is_public(destination) {
            return Err(TrafficPolicyError::PublicDestination { destination });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SendOptions {
    pub destination: Option<IpAddr>,
    pub plan: PlanOptions,
    pub build: BuildOptions,
    /// Second explicit opt-in required in addition to policy approval.
    pub allow_permissive_live: bool,
}

#[derive(Clone, Debug)]
pub struct SendReport {
    pub built: BuiltPacket,
    pub route: MaterializedRoute,
    pub wire_bytes: Option<Bytes>,
    pub stats: OperationStats,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error(transparent)]
    Plan(#[from] PlanError),
    #[error(transparent)]
    Neighbor(#[from] NeighborError),
    #[error(transparent)]
    Build(#[from] BuildError),
    #[error(transparent)]
    Decode(#[from] crate::core::DecodeError),
    #[error(transparent)]
    Policy(#[from] TrafficPolicyError),
    #[error("permissively built packets require allow_permissive_live")]
    PermissiveLiveOptInRequired,
    #[error(transparent)]
    Io(#[from] LiveIoError),
    #[error("{operation}; capture shutdown also failed: {shutdown}")]
    OperationAndCaptureShutdown {
        operation: LiveIoError,
        shutdown: LiveIoError,
    },
    #[error("exchange packets selected different interfaces or link modes")]
    HeterogeneousExchangeRoute,
    #[error("packet template expansion failed: {message}")]
    Template { message: String },
    #[error("could not materialize {field} on layer {layer}: {message}")]
    PacketMaterialization {
        layer: usize,
        field: &'static str,
        message: String,
    },
    #[error("network packet length {actual} exceeds route MTU {mtu}; apply an explicit fragmentation transform")]
    PacketExceedsMtu { actual: usize, mtu: u32 },
}

pub const DEFAULT_MAX_UNSOLICITED_FRAMES: usize = DEFAULT_CAPTURE_QUEUE_FRAMES;

struct CaptureGuard<C: CaptureSession> {
    inner: C,
    shutdown_attempted: bool,
}

impl<C: CaptureSession> CaptureGuard<C> {
    fn new(inner: C) -> Self {
        Self {
            inner,
            shutdown_attempted: false,
        }
    }
}

impl<C: CaptureSession> CaptureSession for CaptureGuard<C> {
    fn wait_ready(&mut self) -> Result<(), LiveIoError> {
        self.inner.wait_ready()
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<CapturedFrame>, LiveIoError> {
        self.inner.next_frame(timeout)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.shutdown_attempted = true;
        self.inner.shutdown()
    }

    fn statistics(&self) -> CaptureStatistics {
        self.inner.statistics()
    }
}

impl<C: CaptureSession> Drop for CaptureGuard<C> {
    fn drop(&mut self) {
        if !self.shutdown_attempted {
            self.shutdown_attempted = true;
            let _ = self.inner.shutdown();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangeOptions {
    pub send: SendOptions,
    pub timeout: Duration,
    pub max_template_packets: usize,
    pub max_unsolicited: usize,
    pub max_responses: usize,
    /// One aggregate backend queue bound shared by matched, unsolicited, and
    /// undecodable capture traffic.
    pub max_capture_queue_frames: usize,
    pub max_captured_bytes: usize,
    pub capture_overflow_policy: CaptureOverflowPolicy,
    pub decode: DecodeOptions,
}

impl Default for ExchangeOptions {
    fn default() -> Self {
        Self {
            send: SendOptions::default(),
            timeout: Duration::from_secs(3),
            max_template_packets: DEFAULT_MAX_TEMPLATE_PACKETS,
            max_unsolicited: DEFAULT_MAX_UNSOLICITED_FRAMES,
            max_responses: DEFAULT_MAX_UNSOLICITED_FRAMES,
            max_capture_queue_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_captured_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            capture_overflow_policy: CaptureOverflowPolicy::Fail,
            decode: DecodeOptions::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MatchedResponse {
    pub request_index: usize,
    pub response: DecodedPacket,
    pub latency: Duration,
}

#[derive(Clone, Debug)]
pub struct ExchangeResult {
    pub sent: Vec<BuiltPacket>,
    pub responses: Vec<MatchedResponse>,
    pub unanswered: Vec<usize>,
    pub unsolicited: Vec<DecodedPacket>,
    /// Captured records whose bytes could not be decoded under the configured
    /// limits. The complete raw frame is retained for evidence.
    pub undecoded: Vec<CapturedFrame>,
    pub diagnostics: Vec<crate::core::Diagnostic>,
    pub stats: OperationStats,
}

struct ExchangeAccumulator {
    responses: Vec<MatchedResponse>,
    unsolicited: Vec<DecodedPacket>,
    undecoded: Vec<CapturedFrame>,
    diagnostics: Vec<crate::core::Diagnostic>,
    retained_bytes: usize,
    response_counts: Vec<usize>,
}

struct ExchangeProcessContext<'a> {
    registry: &'a ProtocolRegistry,
    dissector: &'a Dissector,
    prepared: &'a [(BuiltPacket, MaterializedRoute)],
    sent_at: &'a [Instant],
    sent_wall_time: &'a [std::time::SystemTime],
    options: &'a ExchangeOptions,
}

impl ExchangeAccumulator {
    fn new(requests: usize) -> Self {
        Self {
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            retained_bytes: 0,
            response_counts: vec![0; requests],
        }
    }

    fn process(&mut self, frame: CapturedFrame, context: ExchangeProcessContext<'_>) {
        let ExchangeProcessContext {
            registry,
            dissector,
            prepared,
            sent_at,
            sent_wall_time,
            options,
        } = context;
        let frame_timestamp = frame.timestamp;
        let raw_frame = frame.clone();
        let decoded = match dissector.decode(frame, options.decode.clone()) {
            Ok(decoded) => decoded,
            Err(error) => {
                push_diagnostic_once(
                    &mut self.diagnostics,
                    crate::core::Diagnostic::warning(
                        "exchange.decode_error",
                        format!("captured frame could not be decoded: {error}"),
                    ),
                );
                self.retain_undecoded(raw_frame, options);
                return;
            }
        };
        let integrity_failure = decoded.diagnostics.iter().any(|diagnostic| {
            diagnostic.code.contains("checksum")
                && diagnostic.severity != crate::core::DiagnosticSeverity::Info
        });
        if integrity_failure {
            push_diagnostic_once(
                &mut self.diagnostics,
                crate::core::Diagnostic::warning(
                    "exchange.integrity_rejected",
                    "a response with failed checksum validation was not correlated",
                ),
            );
            self.retain_unsolicited(decoded, options);
            return;
        }

        let mut matched: Option<(usize, crate::core::MatchResult)> = None;
        for (request_index, (request, _)) in prepared.iter().take(sent_at.len()).enumerate() {
            if frame_timestamp < sent_wall_time[request_index] {
                continue;
            }
            let result = request
                .packet
                .iter()
                .filter_map(|layer| registry.matcher(&layer.protocol_id()))
                .map(|matcher| matcher.matches(&request.packet, &decoded.packet))
                .filter(|result| result.matched)
                .max_by_key(|result| result.confidence);
            let Some(result) = result else {
                continue;
            };
            let replace = matched.as_ref().is_none_or(|(best_index, best)| {
                result.confidence > best.confidence
                    || (result.confidence == best.confidence
                        && self.response_counts[request_index] < self.response_counts[*best_index])
                    || (result.confidence == best.confidence
                        && self.response_counts[request_index] == self.response_counts[*best_index]
                        && request_index < *best_index)
            });
            if replace {
                matched = Some((request_index, result));
            }
        }

        if let Some((request_index, _)) = matched {
            if self.responses.len() >= options.max_responses {
                push_diagnostic_once(
                    &mut self.diagnostics,
                    crate::core::Diagnostic::warning(
                        "exchange.response_limit",
                        format!(
                            "matched response limit {} reached; later responses were not retained",
                            options.max_responses
                        ),
                    ),
                );
                return;
            }
            if reserve_capture_bytes(
                &mut self.retained_bytes,
                decoded.original.len(),
                options.max_captured_bytes,
                &mut self.diagnostics,
            ) {
                self.response_counts[request_index] += 1;
                self.responses.push(MatchedResponse {
                    request_index,
                    response: decoded,
                    latency: sent_at[request_index].elapsed(),
                });
            }
        } else {
            if sent_at.len() < prepared.len() {
                push_diagnostic_once(
                    &mut self.diagnostics,
                    crate::core::Diagnostic::info(
                        "exchange.pre_send_frame",
                        "a captured frame arrived before one or more requests were sent and was not correlated to those requests",
                    ),
                );
            }
            self.retain_unsolicited(decoded, options);
        }
    }

    fn retain_unsolicited(&mut self, decoded: DecodedPacket, options: &ExchangeOptions) {
        if self.unsolicited.len() + self.undecoded.len() >= options.max_unsolicited {
            push_diagnostic_once(
                &mut self.diagnostics,
                crate::core::Diagnostic::warning(
                    "exchange.unsolicited_limit",
                    format!(
                        "unsolicited frame limit {} reached; later frames were not retained",
                        options.max_unsolicited
                    ),
                ),
            );
            return;
        }
        if reserve_capture_bytes(
            &mut self.retained_bytes,
            decoded.original.len(),
            options.max_captured_bytes,
            &mut self.diagnostics,
        ) {
            self.unsolicited.push(decoded);
        }
    }

    fn retain_undecoded(&mut self, frame: CapturedFrame, options: &ExchangeOptions) {
        if self.unsolicited.len() + self.undecoded.len() >= options.max_unsolicited {
            push_diagnostic_once(
                &mut self.diagnostics,
                crate::core::Diagnostic::warning(
                    "exchange.unsolicited_limit",
                    format!(
                        "unsolicited/undecoded frame limit {} reached; later frames were not retained",
                        options.max_unsolicited
                    ),
                ),
            );
            return;
        }
        if reserve_capture_bytes(
            &mut self.retained_bytes,
            frame.bytes.len(),
            options.max_captured_bytes,
            &mut self.diagnostics,
        ) {
            self.undecoded.push(frame);
        }
    }
}

/// High-level composition of packet construction, passive route planning,
/// explicit neighbor materialization, policy, and packet I/O.
#[derive(Debug)]
pub struct Client<R, N, I> {
    registry: Arc<ProtocolRegistry>,
    routes: R,
    neighbors: N,
    io: I,
    policy: TrafficPolicy,
    planner: RoutePlanner,
}

impl<R, N, I> Client<R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: PacketIo,
{
    pub fn new(
        registry: Arc<ProtocolRegistry>,
        routes: R,
        neighbors: N,
        io: I,
        policy: TrafficPolicy,
    ) -> Self {
        Self {
            registry,
            routes,
            neighbors,
            io,
            policy,
            planner: RoutePlanner,
        }
    }

    pub fn registry(&self) -> &Arc<ProtocolRegistry> {
        &self.registry
    }

    /// Passive dry planning: route/source/interface lookup only.
    pub fn plan(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &PlanOptions,
    ) -> Result<PlannedRoute, ClientError> {
        let plan = self
            .planner
            .plan(packet, destination, options, &self.routes)?;
        for destination in &plan.visited_destinations {
            self.policy.authorize_destination(*destination)?;
        }
        // Preserve policy visibility into explicitly supplied outer addresses
        // even when SRH routing makes another segment the effective lookup or
        // final destination. Permissive wire inconsistencies must not become a
        // destination-policy bypass.
        for layer in packet.iter() {
            let destination = match layer.field("destination") {
                Some(FieldValue::Ipv4(value)) if !value.is_unspecified() => Some(IpAddr::V4(value)),
                Some(FieldValue::Ipv6(value)) if !value.is_unspecified() => Some(IpAddr::V6(value)),
                _ => None,
            };
            if let Some(destination) = destination {
                self.policy.authorize_destination(destination)?;
            }
        }
        Ok(plan)
    }

    pub fn send(&self, packet: Packet, options: SendOptions) -> Result<SendReport, ClientError> {
        let started = Instant::now();
        if self.policy.max_packets_per_operation < 1 {
            return Err(TrafficPolicyError::PacketLimit {
                actual: 1,
                limit: self.policy.max_packets_per_operation,
            }
            .into());
        }
        let plan = self.plan(&packet, options.destination, &options.plan)?;
        let mut packet = packet;
        materialize_network_fields(&mut packet, &plan)?;
        materialize_link_structure(&mut packet, &plan)?;
        let builder = Builder::new(Arc::clone(&self.registry));
        let context = build_context(&plan);
        // Validate all packet fields before neighbor discovery emits traffic.
        let preliminary = builder.build(packet.clone(), context.clone(), options.build.clone())?;
        validate_mtu(&preliminary, plan.route.mtu)?;
        self.authorize_built(&preliminary, options.allow_permissive_live)?;
        self.authorize_byte_count(preliminary.bytes.len() as u64)?;
        let route = self.planner.materialize(plan, &self.neighbors)?;
        let link_changed = materialize_link_fields(&mut packet, &route)?;
        let built = if link_changed {
            let built = builder.build(packet, context, options.build)?;
            self.authorize_built(&built, options.allow_permissive_live)?;
            self.authorize_byte_count(built.bytes.len() as u64)?;
            built
        } else {
            preliminary
        };
        // Link-layer synthesis is already included in the exact build. The
        // typed frame selects the matching native provider boundary.
        let io_report = self
            .io
            .send(TransmissionFrame::try_new(&built.bytes, &route)?)?;
        validate_send_report(built.bytes.len(), &io_report)?;
        let bytes_sent = io_report.bytes_sent;
        let wire_bytes = io_report
            .wire_bytes
            .or_else(|| route.plan.synthesized_ethernet.then(|| built.bytes.clone()));
        Ok(SendReport {
            built,
            route,
            wire_bytes,
            stats: OperationStats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: bytes_sent as u64,
                elapsed: started.elapsed(),
                capture: CaptureStatistics::default(),
            },
        })
    }

    fn authorize_built(
        &self,
        built: &BuiltPacket,
        allow_permissive_live: bool,
    ) -> Result<(), ClientError> {
        if built.requires_live_opt_in {
            if !allow_permissive_live {
                return Err(ClientError::PermissiveLiveOptInRequired);
            }
            if !self.policy.allow_permissive_packets {
                return Err(TrafficPolicyError::PermissivePacket.into());
            }
        }
        Ok(())
    }

    fn authorize_byte_count(&self, bytes: u64) -> Result<(), ClientError> {
        if bytes > self.policy.max_bytes_per_operation {
            return Err(TrafficPolicyError::ByteLimit {
                actual: bytes,
                limit: self.policy.max_bytes_per_operation,
            }
            .into());
        }
        Ok(())
    }
}

impl<R, N, I> Client<R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: ExchangeIo,
{
    pub fn exchange(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
    ) -> Result<ExchangeResult, ClientError> {
        let started = Instant::now();
        let expansion_len = template
            .expansion_len()
            .map_err(|source| ClientError::Template {
                message: source.to_string(),
            })?;
        let policy_packet_limit =
            usize::try_from(self.policy.max_packets_per_operation).unwrap_or(usize::MAX);
        if expansion_len > policy_packet_limit {
            return Err(TrafficPolicyError::PacketLimit {
                actual: expansion_len as u64,
                limit: self.policy.max_packets_per_operation,
            }
            .into());
        }
        if expansion_len == 0 {
            return Err(ClientError::Template {
                message: "template expanded to no packets".to_owned(),
            });
        }
        let packets = template
            .expand(options.max_template_packets)
            .map_err(|source| ClientError::Template {
                message: source.to_string(),
            })?;
        let packet_count = expansion_len as u64;
        let builder = Builder::new(Arc::clone(&self.registry));
        let mut planned: Vec<(Packet, PlannedRoute, BuildContext, BuiltPacket)> =
            Vec::with_capacity(expansion_len);
        let mut total_bytes = 0u64;
        for packet in packets {
            let mut packet = packet.map_err(|source| ClientError::Template {
                message: source.to_string(),
            })?;
            let plan = self.plan(&packet, options.send.destination, &options.send.plan)?;
            materialize_network_fields(&mut packet, &plan)?;
            materialize_link_structure(&mut packet, &plan)?;
            let context = build_context(&plan);
            let preliminary =
                builder.build(packet.clone(), context.clone(), options.send.build.clone())?;
            validate_mtu(&preliminary, plan.route.mtu)?;
            self.authorize_built(&preliminary, options.send.allow_permissive_live)?;
            total_bytes = total_bytes
                .checked_add(preliminary.bytes.len() as u64)
                .ok_or(TrafficPolicyError::ByteLimit {
                    actual: u64::MAX,
                    limit: self.policy.max_bytes_per_operation,
                })?;
            if total_bytes > self.policy.max_bytes_per_operation {
                return Err(TrafficPolicyError::ByteLimit {
                    actual: total_bytes,
                    limit: self.policy.max_bytes_per_operation,
                }
                .into());
            }
            if let Some((_, first_plan, _, _)) = planned.first() {
                if first_plan.route.interface != plan.route.interface
                    || first_plan.mode != plan.mode
                {
                    return Err(ClientError::HeterogeneousExchangeRoute);
                }
            }
            planned.push((packet, plan, context, preliminary));
        }

        // Neighbor discovery is delayed until every packet has passed packet,
        // route, permissive-build, and aggregate byte-policy checks.
        let mut prepared: Vec<(BuiltPacket, MaterializedRoute)> = Vec::with_capacity(planned.len());
        for (mut packet, plan, context, preliminary) in planned {
            let preliminary_len = preliminary.bytes.len();
            let route = self.planner.materialize(plan, &self.neighbors)?;
            let link_changed = materialize_link_fields(&mut packet, &route)?;
            let built = if link_changed {
                builder.build(packet, context, options.send.build.clone())?
            } else {
                preliminary
            };
            self.authorize_built(&built, options.send.allow_permissive_live)?;
            if built.bytes.len() != preliminary_len {
                // Only fixed-width MAC fields may change after the preliminary
                // build. Treat a custom codec violating that contract as a
                // build/materialization error rather than mis-accounting it.
                return Err(ClientError::PacketMaterialization {
                    layer: 0,
                    field: "ethernet",
                    message: format!(
                        "link materialization changed frame length from {} to {} bytes",
                        preliminary_len,
                        built.bytes.len()
                    ),
                });
            }
            prepared.push((built, route));
        }

        let first_route = &prepared
            .first()
            .expect("non-empty prepared exchange")
            .1
            .plan;
        let capture_limits = CaptureQueueLimits {
            max_frames: options.max_capture_queue_frames,
            max_bytes: options.max_captured_bytes,
            snap_length: options.decode.max_packet_size,
            overflow_policy: options.capture_overflow_policy,
        }
        .validate()?;
        let mut capture = CaptureGuard::new(self.io.arm_capture(first_route, capture_limits)?);
        if let Err(error) = capture.wait_ready() {
            return Err(error_after_shutdown(&mut capture, error));
        }

        let mut sent_at = Vec::with_capacity(prepared.len());
        let mut sent_wall_time = Vec::with_capacity(prepared.len());
        let mut completed_sends = 0u64;
        let dissector = Dissector::new(Arc::clone(&self.registry));
        let mut captured = ExchangeAccumulator::new(prepared.len());
        for (built, route) in &prepared {
            loop {
                let frame = match capture.next_frame(Duration::ZERO) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(error) => return Err(error_after_shutdown(&mut capture, error)),
                };
                captured.process(
                    frame,
                    ExchangeProcessContext {
                        registry: &self.registry,
                        dissector: &dissector,
                        prepared: &prepared,
                        sent_at: &sent_at,
                        sent_wall_time: &sent_wall_time,
                        options: &options,
                    },
                );
            }
            let send_started = Instant::now();
            let send_wall_time = std::time::SystemTime::now();
            let frame = match TransmissionFrame::try_new(&built.bytes, route) {
                Ok(frame) => frame,
                Err(error) => return Err(error_after_shutdown(&mut capture, error)),
            };
            let sent = match self.io.send(frame) {
                Ok(report) => report,
                Err(error) => return Err(error_after_shutdown(&mut capture, error)),
            };
            if let Err(error) = validate_send_report(built.bytes.len(), &sent) {
                return Err(error_after_shutdown(&mut capture, error));
            }
            sent_at.push(send_started);
            sent_wall_time.push(send_wall_time);
            completed_sends += 1;
            loop {
                let frame = match capture.next_frame(Duration::ZERO) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(error) => return Err(error_after_shutdown(&mut capture, error)),
                };
                captured.process(
                    frame,
                    ExchangeProcessContext {
                        registry: &self.registry,
                        dissector: &dissector,
                        prepared: &prepared,
                        sent_at: &sent_at,
                        sent_wall_time: &sent_wall_time,
                        options: &options,
                    },
                );
            }
        }

        let deadline = Instant::now()
            .checked_add(options.timeout)
            .unwrap_or_else(Instant::now);
        loop {
            let now = Instant::now();
            let Some(remaining) = deadline.checked_duration_since(now) else {
                break;
            };
            let frame = match capture.next_frame(remaining) {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(error) => {
                    return Err(error_after_shutdown(&mut capture, error));
                }
            };
            captured.process(
                frame,
                ExchangeProcessContext {
                    registry: &self.registry,
                    dissector: &dissector,
                    prepared: &prepared,
                    sent_at: &sent_at,
                    sent_wall_time: &sent_wall_time,
                    options: &options,
                },
            );
        }
        capture.shutdown()?;
        let capture_statistics = capture.statistics().validate()?;
        if capture_statistics.has_loss() {
            if capture_limits.overflow_policy == CaptureOverflowPolicy::Fail {
                return Err(LiveIoError::CaptureQueueOverflow {
                    dropped_frames: capture_statistics.dropped_frames,
                    dropped_bytes: capture_statistics.dropped_bytes,
                    overflow_events: capture_statistics.overflow_events,
                }
                .into());
            }
            push_diagnostic_once(
                &mut captured.diagnostics,
                crate::core::Diagnostic::warning(
                    "capture.queue_overflow",
                    format!(
                        "capture backend reported {} overflow event(s), {} dropped frame(s), and {} dropped byte(s) under {:?}",
                        capture_statistics.overflow_events,
                        capture_statistics.dropped_frames,
                        capture_statistics.dropped_bytes,
                        capture_limits.overflow_policy,
                    ),
                ),
            );
        }

        let mut answered = vec![false; prepared.len()];
        for response in &captured.responses {
            answered[response.request_index] = true;
        }
        let unanswered = answered
            .iter()
            .enumerate()
            .filter_map(|(index, answered)| (!answered).then_some(index))
            .collect();
        let sent = prepared.into_iter().map(|(built, _)| built).collect();
        Ok(ExchangeResult {
            sent,
            responses: captured.responses,
            unanswered,
            unsolicited: captured.unsolicited,
            undecoded: captured.undecoded,
            diagnostics: captured.diagnostics,
            stats: OperationStats {
                packets_attempted: packet_count,
                packets_completed: completed_sends,
                bytes: total_bytes,
                elapsed: started.elapsed(),
                capture: capture_statistics,
            },
        })
    }
}

fn validate_send_report(expected: usize, report: &IoSendReport) -> Result<(), LiveIoError> {
    if report.bytes_sent != expected {
        return Err(LiveIoError::PartialSend {
            expected,
            actual: report.bytes_sent,
        });
    }
    if let Some(wire_bytes) = &report.wire_bytes {
        if wire_bytes.len() != report.bytes_sent {
            return Err(LiveIoError::InvalidSendReport {
                bytes_sent: report.bytes_sent,
                wire_bytes: wire_bytes.len(),
            });
        }
    }
    Ok(())
}

fn validate_mtu(built: &BuiltPacket, mtu: u32) -> Result<(), ClientError> {
    let network_layer = built.packet.iter().enumerate().find_map(|(index, layer)| {
        matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6").then_some(index)
    });
    let network_length = network_layer.and_then(|index| {
        let start = built.layout.layer(index)?.range.start;
        let outside_network = built
            .packet
            .iter()
            .rev()
            .take_while(|layer| layer.as_any().is::<Padding>())
            .filter_map(|layer| layer.as_any().downcast_ref::<Padding>())
            .filter(|padding| {
                padding
                    .outside_layer
                    .is_none_or(|outside_layer| index >= outside_layer)
            })
            .try_fold(0_usize, |total, padding| {
                total.checked_add(padding.bytes.len())
            })?;
        built
            .bytes
            .len()
            .checked_sub(outside_network)?
            .checked_sub(start)
    });
    if let Some(actual) = network_length {
        if actual > mtu as usize {
            return Err(ClientError::PacketExceedsMtu { actual, mtu });
        }
    }
    Ok(())
}

fn error_after_shutdown<C: CaptureSession>(capture: &mut C, operation: LiveIoError) -> ClientError {
    match capture.shutdown() {
        Ok(()) => ClientError::Io(operation),
        Err(shutdown) => ClientError::OperationAndCaptureShutdown {
            operation,
            shutdown,
        },
    }
}

fn push_diagnostic_once(
    diagnostics: &mut Vec<crate::core::Diagnostic>,
    diagnostic: crate::core::Diagnostic,
) {
    if !diagnostics
        .iter()
        .any(|existing| existing.code == diagnostic.code)
    {
        diagnostics.push(diagnostic);
    }
}

fn reserve_capture_bytes(
    retained: &mut usize,
    additional: usize,
    limit: usize,
    diagnostics: &mut Vec<crate::core::Diagnostic>,
) -> bool {
    let Some(total) = retained.checked_add(additional) else {
        push_diagnostic_once(
            diagnostics,
            crate::core::Diagnostic::warning(
                "exchange.capture_byte_limit",
                "retained capture byte accounting overflowed; frame was not retained",
            ),
        );
        return false;
    };
    if total > limit {
        push_diagnostic_once(
            diagnostics,
            crate::core::Diagnostic::warning(
                "exchange.capture_byte_limit",
                format!(
                    "retained capture byte limit {limit} reached; later frames were not retained"
                ),
            ),
        );
        return false;
    }
    *retained = total;
    true
}

fn build_context(plan: &PlannedRoute) -> BuildContext {
    BuildContext {
        source: plan.packet_source,
        destination: plan.final_destination,
        mtu: Some(plan.route.mtu),
        link_type: Some(plan.route.link_type.0),
        metadata: Default::default(),
    }
}

fn materialize_link_structure(packet: &mut Packet, plan: &PlannedRoute) -> Result<(), ClientError> {
    if !plan.synthesized_ethernet
        || packet
            .iter()
            .any(|layer| layer.protocol_id().as_str() == "ethernet")
    {
        return Ok(());
    }
    packet
        .insert(0, Ethernet::default())
        .map_err(|source| ClientError::PacketMaterialization {
            layer: 0,
            field: "ethernet",
            message: source.to_string(),
        })?;
    Ok(())
}

fn materialize_network_fields(packet: &mut Packet, plan: &PlannedRoute) -> Result<(), ClientError> {
    for index in 0..packet.len() {
        let Some(layer) = packet.layer_mut(index) else {
            continue;
        };
        let protocol = layer.protocol_id();
        let family_v4 = match protocol.as_str() {
            "ipv4" => true,
            "ipv6" => false,
            _ => continue,
        };
        let source_unspecified = match layer.field("source") {
            Some(FieldValue::Ipv4(value)) => value.is_unspecified(),
            Some(FieldValue::Ipv6(value)) => value.is_unspecified(),
            _ => false,
        };
        if source_unspecified {
            let value = match plan.packet_source {
                Some(IpAddr::V4(value)) if family_v4 => FieldValue::Ipv4(value),
                Some(IpAddr::V6(value)) if !family_v4 => FieldValue::Ipv6(value),
                _ => {
                    return Err(ClientError::PacketMaterialization {
                        layer: index,
                        field: "source",
                        message: "route source family does not match the packet layer".to_owned(),
                    })
                }
            };
            layer.set_field("source", value).map_err(|source| {
                ClientError::PacketMaterialization {
                    layer: index,
                    field: "source",
                    message: source.to_string(),
                }
            })?;
        }

        let destination_unspecified = match layer.field("destination") {
            Some(FieldValue::Ipv4(value)) => value.is_unspecified(),
            Some(FieldValue::Ipv6(value)) => value.is_unspecified(),
            _ => false,
        };
        if destination_unspecified {
            let value = match plan.lookup_destination {
                Some(IpAddr::V4(value)) if family_v4 => FieldValue::Ipv4(value),
                Some(IpAddr::V6(value)) if !family_v4 => FieldValue::Ipv6(value),
                _ => {
                    return Err(ClientError::PacketMaterialization {
                        layer: index,
                        field: "destination",
                        message: "route destination family does not match the packet layer"
                            .to_owned(),
                    })
                }
            };
            layer.set_field("destination", value).map_err(|source| {
                ClientError::PacketMaterialization {
                    layer: index,
                    field: "destination",
                    message: source.to_string(),
                }
            })?;
        }
    }
    Ok(())
}

fn materialize_link_fields(
    packet: &mut Packet,
    route: &MaterializedRoute,
) -> Result<bool, ClientError> {
    if route.plan.mode != crate::io::LinkMode::Layer2 {
        return Ok(false);
    }
    let Some(index) = packet
        .iter()
        .position(|layer| layer.protocol_id().as_str() == "ethernet")
    else {
        return Ok(false);
    };
    let layer = packet
        .layer_mut(index)
        .expect("position returned an existing layer");
    let mut changed = false;
    if matches!(
        layer.field("source"),
        Some(FieldValue::Mac(value)) if value == [0; 6]
    ) {
        let source_mac =
            route
                .plan
                .source_mac
                .ok_or_else(|| ClientError::PacketMaterialization {
                    layer: index,
                    field: "source",
                    message: "route has no interface-owned source MAC".to_owned(),
                })?;
        layer
            .set_field("source", FieldValue::Mac(source_mac.0))
            .map_err(|source| ClientError::PacketMaterialization {
                layer: index,
                field: "source",
                message: source.to_string(),
            })?;
        changed = true;
    }
    if matches!(
        layer.field("destination"),
        Some(FieldValue::Mac(value)) if value == [0; 6]
    ) {
        let destination_mac =
            route
                .plan
                .destination_mac
                .ok_or_else(|| ClientError::PacketMaterialization {
                    layer: index,
                    field: "destination",
                    message: "route has no resolved destination MAC".to_owned(),
                })?;
        layer
            .set_field("destination", FieldValue::Mac(destination_mac.0))
            .map_err(|source| ClientError::PacketMaterialization {
                layer: index,
                field: "destination",
                message: source.to_string(),
            })?;
        changed = true;
    }
    Ok(changed)
}

fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_unspecified()
                || address.is_documentation())
        }
        IpAddr::V6(address) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || is_ipv6_documentation(address))
        }
    }
}

fn is_ipv6_documentation(address: std::net::Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

/// A portable backend that makes live I/O capability failures explicit.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsupportedPacketIo;

impl PacketIo for UnsupportedPacketIo {
    fn send(&self, _frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        Err(LiveIoError::Unsupported {
            message: "build with and configure a native live-I/O backend".to_owned(),
        })
    }
}

/// Resolver used for Layer 3-only clients; any accidental Layer 2 request fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsupportedNeighborResolver;

impl NeighborResolver for UnsupportedNeighborResolver {
    fn resolve(
        &self,
        interface: &crate::io::InterfaceId,
        _interface_source: IpAddr,
        target: IpAddr,
    ) -> Result<crate::io::MacAddress, NeighborError> {
        Err(NeighborError::Resolution {
            interface: interface.name.clone(),
            target,
            message: "no neighbor resolver is configured".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::core::{PacketTemplate, Raw, TemplateValues, WireValue};
    use crate::io::{
        DestinationScope, InterfaceId, LinkCapability, LinkMode, LinkType, MacAddress,
        RouteDecision,
    };
    use crate::protocols::{
        default_registry, Ethernet, Ipv4, Ipv6, SegmentRoutingHeader, Udp, Vlan, Vlan8021ad,
    };

    #[derive(Clone)]
    struct FixedRoutes(RouteDecision);

    impl RouteProvider for FixedRoutes {
        type Error = Infallible;

        fn lookup(
            &self,
            _destination: IpAddr,
            _interface_hint: Option<&InterfaceId>,
        ) -> Result<RouteDecision, Self::Error> {
            Ok(self.0.clone())
        }
    }

    #[derive(Clone)]
    struct InterfaceRoutes {
        decision: RouteDecision,
        ip_lookups: Arc<AtomicUsize>,
        interface_lookups: Arc<AtomicUsize>,
    }

    impl RouteProvider for InterfaceRoutes {
        type Error = Infallible;

        fn lookup(
            &self,
            _destination: IpAddr,
            _interface_hint: Option<&InterfaceId>,
        ) -> Result<RouteDecision, Self::Error> {
            self.ip_lookups.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }

        fn lookup_interface(
            &self,
            _interface: &InterfaceId,
        ) -> Result<Option<RouteDecision>, Self::Error> {
            self.interface_lookups.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.decision.clone()))
        }
    }

    #[derive(Clone, Default)]
    struct CountingNeighbors(Arc<AtomicUsize>);

    impl NeighborResolver for CountingNeighbors {
        fn resolve(
            &self,
            _interface: &InterfaceId,
            _interface_source: IpAddr,
            _target: IpAddr,
        ) -> Result<MacAddress, NeighborError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(MacAddress([0, 1, 2, 3, 4, 5]))
        }
    }

    #[derive(Clone, Copy)]
    struct FailingNeighbors;

    impl NeighborResolver for FailingNeighbors {
        fn resolve(
            &self,
            interface: &InterfaceId,
            _interface_source: IpAddr,
            target: IpAddr,
        ) -> Result<MacAddress, NeighborError> {
            Err(NeighborError::Resolution {
                interface: interface.name.clone(),
                target,
                message: "deterministic test failure".to_owned(),
            })
        }
    }

    #[derive(Clone)]
    struct FakeIo {
        events: Arc<Mutex<Vec<&'static str>>>,
        response: Arc<Mutex<Option<CapturedFrame>>>,
        deliver_before_send: bool,
        limits: Arc<Mutex<Vec<CaptureQueueLimits>>>,
        capture_statistics: CaptureStatistics,
    }

    impl PacketIo for FakeIo {
        fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
            self.events.lock().unwrap().push("send");
            Ok(IoSendReport {
                bytes_sent: frame.bytes().len(),
                wire_bytes: Some(frame.bytes().clone()),
            })
        }
    }

    #[derive(Clone, Default)]
    struct RecordingIo(Arc<Mutex<Vec<Bytes>>>);

    impl PacketIo for RecordingIo {
        fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
            self.0.lock().unwrap().push(frame.bytes().clone());
            Ok(IoSendReport {
                bytes_sent: frame.bytes().len(),
                wire_bytes: Some(frame.bytes().clone()),
            })
        }
    }

    #[derive(Clone, Copy)]
    struct PartialIo;

    impl PacketIo for PartialIo {
        fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
            Ok(IoSendReport {
                bytes_sent: frame.bytes().len().saturating_sub(1),
                wire_bytes: None,
            })
        }
    }

    struct FakeCapture {
        events: Arc<Mutex<Vec<&'static str>>>,
        response: Arc<Mutex<Option<CapturedFrame>>>,
        deliver_before_send: bool,
        statistics: CaptureStatistics,
    }

    impl CaptureSession for FakeCapture {
        fn wait_ready(&mut self) -> Result<(), LiveIoError> {
            self.events.lock().unwrap().push("ready");
            Ok(())
        }

        fn next_frame(&mut self, _timeout: Duration) -> Result<Option<CapturedFrame>, LiveIoError> {
            let sent = self.events.lock().unwrap().contains(&"send");
            if sent || self.deliver_before_send {
                let mut response = self.response.lock().unwrap().take();
                if let Some(frame) = &mut response {
                    frame.timestamp = std::time::SystemTime::now();
                    self.statistics.received_frames = self
                        .statistics
                        .received_frames
                        .checked_add(1)
                        .expect("test capture frame counter");
                    self.statistics.received_bytes = self
                        .statistics
                        .received_bytes
                        .checked_add(frame.bytes.len() as u64)
                        .expect("test capture byte counter");
                }
                Ok(response)
            } else {
                Ok(None)
            }
        }

        fn shutdown(&mut self) -> Result<(), LiveIoError> {
            self.events.lock().unwrap().push("shutdown");
            Ok(())
        }

        fn statistics(&self) -> CaptureStatistics {
            self.statistics
        }
    }

    impl CaptureProvider for FakeIo {
        type Capture = FakeCapture;

        fn arm_capture(
            &self,
            _route: &PlannedRoute,
            limits: CaptureQueueLimits,
        ) -> Result<Self::Capture, LiveIoError> {
            self.events.lock().unwrap().push("arm");
            self.limits.lock().unwrap().push(limits);
            Ok(FakeCapture {
                events: Arc::clone(&self.events),
                response: Arc::clone(&self.response),
                deliver_before_send: self.deliver_before_send,
                statistics: self.capture_statistics,
            })
        }
    }

    #[derive(Clone)]
    struct ReadinessAndShutdownFailIo(Arc<Mutex<Vec<&'static str>>>);

    impl PacketIo for ReadinessAndShutdownFailIo {
        fn send(&self, _frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
            panic!("readiness failure must prevent transmission")
        }
    }

    struct ReadinessAndShutdownFailCapture(Arc<Mutex<Vec<&'static str>>>);

    impl CaptureSession for ReadinessAndShutdownFailCapture {
        fn wait_ready(&mut self) -> Result<(), LiveIoError> {
            self.0.lock().unwrap().push("ready");
            Err(LiveIoError::CaptureReadiness {
                message: "not ready".to_owned(),
            })
        }

        fn next_frame(&mut self, _timeout: Duration) -> Result<Option<CapturedFrame>, LiveIoError> {
            unreachable!("readiness failure prevents receive")
        }

        fn shutdown(&mut self) -> Result<(), LiveIoError> {
            self.0.lock().unwrap().push("shutdown");
            Err(LiveIoError::Capture {
                message: "join failed".to_owned(),
            })
        }

        fn statistics(&self) -> CaptureStatistics {
            CaptureStatistics::default()
        }
    }

    impl CaptureProvider for ReadinessAndShutdownFailIo {
        type Capture = ReadinessAndShutdownFailCapture;

        fn arm_capture(
            &self,
            _route: &PlannedRoute,
            _limits: CaptureQueueLimits,
        ) -> Result<Self::Capture, LiveIoError> {
            self.0.lock().unwrap().push("arm");
            Ok(ReadinessAndShutdownFailCapture(Arc::clone(&self.0)))
        }
    }

    struct DropObservedCapture(Arc<AtomicUsize>);

    impl CaptureSession for DropObservedCapture {
        fn wait_ready(&mut self) -> Result<(), LiveIoError> {
            Ok(())
        }

        fn next_frame(&mut self, _timeout: Duration) -> Result<Option<CapturedFrame>, LiveIoError> {
            Ok(None)
        }

        fn shutdown(&mut self) -> Result<(), LiveIoError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn statistics(&self) -> CaptureStatistics {
            CaptureStatistics::default()
        }
    }

    fn route(mode: LinkCapability) -> RouteDecision {
        RouteDecision {
            interface: InterfaceId {
                name: "test0".to_owned(),
                index: 7,
            },
            source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
            selected_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            preferred_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            next_hop: None,
            selection_reason: crate::io::RouteSelectionReason::OnLink,
            destination_scope: DestinationScope::Private,
            mtu: 1500,
            capability: mode,
            link_type: LinkType::IPV4,
        }
    }

    fn packet(source: Ipv4Addr, destination: Ipv4Addr, sport: u16, dport: u16) -> Packet {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source,
                destination,
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: sport,
                destination_port: dport,
                ..Udp::default()
            });
        packet
    }

    fn canonical_link_intent_packets() -> Vec<(&'static str, Packet)> {
        let base = || {
            packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12345,
                9,
            )
        };

        let mut ethernet = base();
        ethernet.insert(0, Ethernet::default()).unwrap();

        let mut customer_vlan_root = base();
        customer_vlan_root.insert(0, Vlan::default()).unwrap();

        let mut service_vlan_root = base();
        service_vlan_root.insert(0, Vlan8021ad::default()).unwrap();

        let mut ethernet_stacked = base();
        ethernet_stacked
            .insert(
                0,
                Vlan {
                    vlan_id: 200,
                    ..Vlan::default()
                },
            )
            .unwrap();
        ethernet_stacked
            .insert(
                0,
                Vlan8021ad {
                    vlan_id: 100,
                    ..Vlan8021ad::default()
                },
            )
            .unwrap();
        ethernet_stacked.insert(0, Ethernet::default()).unwrap();

        let mut vlan_rooted_stacked = base();
        vlan_rooted_stacked
            .insert(
                0,
                Vlan {
                    vlan_id: 200,
                    ..Vlan::default()
                },
            )
            .unwrap();
        vlan_rooted_stacked
            .insert(
                0,
                Vlan8021ad {
                    vlan_id: 100,
                    ..Vlan8021ad::default()
                },
            )
            .unwrap();

        vec![
            ("ethernet", ethernet),
            ("vlan", customer_vlan_root),
            ("vlan8021ad", service_vlan_root),
            ("ethernet-stacked-vlan", ethernet_stacked),
            ("vlan-rooted-stacked-vlan", vlan_rooted_stacked),
        ]
    }

    fn exchange_with_capture_statistics(
        statistics: CaptureStatistics,
        overflow_policy: CaptureOverflowPolicy,
    ) -> Result<ExchangeResult, ClientError> {
        let io = FakeIo {
            events: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(None)),
            deliver_before_send: false,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: statistics,
        };
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            FixedRoutes(route(LinkCapability::Layer3)),
            CountingNeighbors::default(),
            io,
            TrafficPolicy::default(),
        );
        client.exchange(
            &PacketTemplate::new(packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12345,
                9,
            )),
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
                capture_overflow_policy: overflow_policy,
                ..ExchangeOptions::default()
            },
        )
    }

    #[test]
    fn capture_queue_limits_fail_closed_at_zero_and_arithmetic_overflow() {
        assert_eq!(
            CaptureQueueLimits::default().validate().unwrap(),
            CaptureQueueLimits::default()
        );

        for (field, limits) in [
            (
                "max_frames",
                CaptureQueueLimits {
                    max_frames: 0,
                    ..CaptureQueueLimits::default()
                },
            ),
            (
                "max_bytes",
                CaptureQueueLimits {
                    max_bytes: 0,
                    ..CaptureQueueLimits::default()
                },
            ),
            (
                "snap_length",
                CaptureQueueLimits {
                    snap_length: 0,
                    ..CaptureQueueLimits::default()
                },
            ),
        ] {
            assert!(matches!(
                limits.validate(),
                Err(LiveIoError::InvalidCaptureQueueLimit {
                    field: actual,
                    ..
                }) if actual == field
            ));
        }

        assert!(matches!(
            CaptureQueueLimits {
                max_frames: usize::MAX,
                max_bytes: usize::MAX,
                snap_length: 2,
                overflow_policy: CaptureOverflowPolicy::Fail,
            }
            .validate(),
            Err(LiveIoError::InvalidCaptureQueueLimit {
                field: "max_frames * snap_length",
                ..
            })
        ));
        assert!(matches!(
            CaptureQueueLimits {
                max_bytes: 1,
                snap_length: 2,
                ..CaptureQueueLimits::default()
            }
            .validate(),
            Err(LiveIoError::InvalidCaptureQueueLimit {
                field: "snap_length",
                ..
            })
        ));
    }

    #[test]
    fn capture_loss_is_a_typed_failure_or_visible_diagnostic_by_policy() {
        let statistics = CaptureStatistics {
            received_frames: 3,
            received_bytes: 192,
            dropped_frames: 2,
            dropped_bytes: 128,
            overflow_events: 1,
        };

        let error =
            exchange_with_capture_statistics(statistics, CaptureOverflowPolicy::Fail).unwrap_err();
        assert!(matches!(
            error,
            ClientError::Io(LiveIoError::CaptureQueueOverflow {
                dropped_frames: 2,
                dropped_bytes: 128,
                overflow_events: 1,
            })
        ));

        for policy in [
            CaptureOverflowPolicy::DropNewest,
            CaptureOverflowPolicy::DropOldest,
        ] {
            let result = exchange_with_capture_statistics(statistics, policy).unwrap();
            assert_eq!(result.stats.capture, statistics, "{policy:?}");
            assert!(result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "capture.queue_overflow"));
        }
    }

    #[test]
    fn invalid_capture_statistics_fail_closed() {
        let statistics = CaptureStatistics {
            dropped_bytes: 1,
            ..CaptureStatistics::default()
        };
        let error = exchange_with_capture_statistics(statistics, CaptureOverflowPolicy::DropNewest)
            .unwrap_err();
        assert!(matches!(
            error,
            ClientError::Io(LiveIoError::InvalidCaptureStatistics { .. })
        ));
    }

    #[test]
    fn raw_layer3_backend_never_receives_canonical_link_layer_bytes() {
        let io = RecordingIo::default();
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            FixedRoutes(route(LinkCapability::Layer3)),
            CountingNeighbors::default(),
            io.clone(),
            TrafficPolicy::default(),
        );

        for (case, request) in canonical_link_intent_packets() {
            let error = client
                .send(
                    request,
                    SendOptions {
                        plan: PlanOptions {
                            link_mode: LinkMode::Layer3,
                            interface: None,
                            preferred_source: None,
                        },
                        ..SendOptions::default()
                    },
                )
                .unwrap_err();

            assert!(
                matches!(error, ClientError::Plan(PlanError::EthernetInLayer3)),
                "{case}: {error}"
            );
            assert!(io.0.lock().unwrap().is_empty(), "{case}");
        }
    }

    #[test]
    fn neighbor_failure_cannot_fall_back_from_explicit_layer2() {
        let io = RecordingIo::default();
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            FixedRoutes(RouteDecision {
                capability: LinkCapability::Layer2And3,
                link_type: LinkType::ETHERNET,
                ..route(LinkCapability::Layer2And3)
            }),
            FailingNeighbors,
            io.clone(),
            TrafficPolicy::default(),
        );
        let request = canonical_link_intent_packets()
            .into_iter()
            .find_map(|(case, packet)| (case == "vlan8021ad").then_some(packet))
            .unwrap();

        let error = client
            .send(
                request,
                SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer2,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
            )
            .unwrap_err();

        assert!(matches!(
            error,
            ClientError::Neighbor(NeighborError::Resolution { .. })
        ));
        assert!(io.0.lock().unwrap().is_empty());
    }

    #[test]
    fn dry_plan_keeps_spoofed_packet_and_neighbor_sources_distinct() {
        let neighbors = CountingNeighbors::default();
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            FixedRoutes(RouteDecision {
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254))),
                capability: LinkCapability::Layer2And3,
                link_type: LinkType::ETHERNET,
                ..route(LinkCapability::Layer2And3)
            }),
            neighbors.clone(),
            UnsupportedPacketIo,
            TrafficPolicy::default(),
        );
        let spoofed = Ipv4Addr::new(10, 9, 9, 9);
        let plan = client
            .plan(
                &packet(spoofed, Ipv4Addr::new(10, 0, 1, 5), 1000, 9),
                None,
                &PlanOptions {
                    link_mode: LinkMode::Layer2,
                    interface: None,
                    preferred_source: None,
                },
            )
            .unwrap();

        assert_eq!(plan.packet_source, Some(IpAddr::V4(spoofed)));
        assert_eq!(
            plan.neighbor_source,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            plan.neighbor_target,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)))
        );
        assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn send_complete_custom_ethernet_without_ip_destination() {
        let decision = RouteDecision {
            selected_address: None,
            preferred_source: None,
            next_hop: None,
            capability: LinkCapability::Layer2,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2)
        };
        let interface = decision.interface.clone();
        let ip_lookups = Arc::new(AtomicUsize::new(0));
        let interface_lookups = Arc::new(AtomicUsize::new(0));
        let routes = InterfaceRoutes {
            decision,
            ip_lookups: Arc::clone(&ip_lookups),
            interface_lookups: Arc::clone(&interface_lookups),
        };
        let neighbors = CountingNeighbors::default();
        let io = RecordingIo::default();
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            routes,
            neighbors.clone(),
            io.clone(),
            TrafficPolicy::default(),
        );
        let mut packet = Packet::new();
        packet
            .push(Ethernet {
                destination: [2, 0, 0, 0, 0, 2],
                source: [2, 0, 0, 0, 0, 1],
                ether_type: WireValue::Exact(0x88b5),
            })
            .push(Raw::new(Bytes::from_static(b"custom")));

        let report = client
            .send(
                packet,
                SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Auto,
                        interface: Some(interface),
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
            )
            .unwrap();

        assert_eq!(ip_lookups.load(Ordering::SeqCst), 0);
        assert_eq!(interface_lookups.load(Ordering::SeqCst), 1);
        assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
        assert_eq!(report.route.plan.lookup_destination, None);
        assert_eq!(report.route.plan.final_destination, None);
        assert_eq!(
            report.built.bytes.as_ref(),
            &[2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x88, 0xb5, b'c', b'u', b's', b't', b'o', b'm',]
        );
        assert_eq!(io.0.lock().unwrap().as_slice(), &[report.built.bytes]);
    }

    #[test]
    fn exchange_arms_and_awaits_capture_before_send_and_matches_response() {
        let registry = Arc::new(default_registry().unwrap());
        let response_packet = packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            9,
            12345,
        );
        let response_bytes = Builder::new(Arc::clone(&registry))
            .build(
                response_packet,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap()
            .bytes;
        let events = Arc::new(Mutex::new(Vec::new()));
        let limits = Arc::new(Mutex::new(Vec::new()));
        let io = FakeIo {
            events: Arc::clone(&events),
            response: Arc::new(Mutex::new(Some(
                CapturedFrame::new(std::time::SystemTime::now(), LinkType::IPV4, response_bytes)
                    .unwrap(),
            ))),
            deliver_before_send: false,
            limits: Arc::clone(&limits),
            capture_statistics: CaptureStatistics::default(),
        };
        let client = Client::new(
            registry,
            FixedRoutes(route(LinkCapability::Layer3)),
            CountingNeighbors::default(),
            io,
            TrafficPolicy::default(),
        );
        let request = packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            9,
        );
        let result = client
            .exchange(
                &PacketTemplate::new(request),
                ExchangeOptions {
                    send: SendOptions {
                        plan: PlanOptions {
                            link_mode: LinkMode::Layer3,
                            interface: None,
                            preferred_source: None,
                        },
                        ..SendOptions::default()
                    },
                    ..ExchangeOptions::default()
                },
            )
            .unwrap();

        assert_eq!(
            *events.lock().unwrap(),
            ["arm", "ready", "send", "shutdown"]
        );
        assert_eq!(
            limits.lock().unwrap().as_slice(),
            &[CaptureQueueLimits::default()]
        );
        assert_eq!(result.responses.len(), 1);
        assert!(result.unanswered.is_empty());
        assert!(result.unsolicited.is_empty());
    }

    #[test]
    fn frame_captured_before_request_send_cannot_satisfy_it() {
        let registry = Arc::new(default_registry().unwrap());
        let response_bytes = Builder::new(Arc::clone(&registry))
            .build(
                packet(
                    Ipv4Addr::new(10, 0, 0, 2),
                    Ipv4Addr::new(10, 0, 0, 1),
                    9,
                    12345,
                ),
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap()
            .bytes;
        let client = Client::new(
            registry,
            FixedRoutes(route(LinkCapability::Layer3)),
            CountingNeighbors::default(),
            FakeIo {
                events: Arc::new(Mutex::new(Vec::new())),
                response: Arc::new(Mutex::new(Some(
                    CapturedFrame::new(
                        std::time::SystemTime::now(),
                        LinkType::IPV4,
                        response_bytes,
                    )
                    .unwrap(),
                ))),
                deliver_before_send: true,
                limits: Arc::new(Mutex::new(Vec::new())),
                capture_statistics: CaptureStatistics::default(),
            },
            TrafficPolicy::default(),
        );
        let result = client
            .exchange(
                &PacketTemplate::new(packet(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                    12345,
                    9,
                )),
                ExchangeOptions {
                    send: SendOptions {
                        plan: PlanOptions {
                            link_mode: LinkMode::Layer3,
                            interface: None,
                            preferred_source: None,
                        },
                        ..SendOptions::default()
                    },
                    ..ExchangeOptions::default()
                },
            )
            .unwrap();
        assert!(result.responses.is_empty());
        assert_eq!(result.unsolicited.len(), 1);
        assert_eq!(result.unanswered, [0]);
        assert!(result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.pre_send_frame"));
    }

    #[test]
    fn exchange_retains_complete_frame_when_decode_fails() {
        let registry = Arc::new(default_registry().unwrap());
        let mut invalid = CapturedFrame::new(
            std::time::SystemTime::now(),
            LinkType::IPV4,
            vec![0xde, 0xad, 0xbe, 0xef],
        )
        .unwrap();
        invalid.captured_length = 3;
        let client = Client::new(
            registry,
            FixedRoutes(route(LinkCapability::Layer3)),
            CountingNeighbors::default(),
            FakeIo {
                events: Arc::new(Mutex::new(Vec::new())),
                response: Arc::new(Mutex::new(Some(invalid))),
                deliver_before_send: false,
                limits: Arc::new(Mutex::new(Vec::new())),
                capture_statistics: CaptureStatistics::default(),
            },
            TrafficPolicy::default(),
        );
        let result = client
            .exchange(
                &PacketTemplate::new(packet(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                    12345,
                    9,
                )),
                ExchangeOptions {
                    send: SendOptions {
                        plan: PlanOptions {
                            link_mode: LinkMode::Layer3,
                            interface: None,
                            preferred_source: None,
                        },
                        ..SendOptions::default()
                    },
                    ..ExchangeOptions::default()
                },
            )
            .unwrap();
        assert_eq!(result.undecoded.len(), 1);
        assert_eq!(result.undecoded[0].bytes.as_ref(), [0xde, 0xad, 0xbe, 0xef]);
        assert!(result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.decode_error"));
    }

    #[test]
    fn exchange_surfaces_operation_and_cleanup_failures() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            FixedRoutes(route(LinkCapability::Layer3)),
            CountingNeighbors::default(),
            ReadinessAndShutdownFailIo(Arc::clone(&events)),
            TrafficPolicy::default(),
        );
        let error = client
            .exchange(
                &PacketTemplate::new(packet(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                    12345,
                    9,
                )),
                ExchangeOptions {
                    send: SendOptions {
                        plan: PlanOptions {
                            link_mode: LinkMode::Layer3,
                            interface: None,
                            preferred_source: None,
                        },
                        ..SendOptions::default()
                    },
                    ..ExchangeOptions::default()
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ClientError::OperationAndCaptureShutdown {
                operation: LiveIoError::CaptureReadiness { .. },
                shutdown: LiveIoError::Capture { .. }
            }
        ));
        assert_eq!(*events.lock().unwrap(), ["arm", "ready", "shutdown"]);
    }

    #[test]
    fn capture_guard_attempts_shutdown_during_unwind() {
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&shutdowns);
        let _ = std::panic::catch_unwind(move || {
            let _capture = CaptureGuard::new(DropObservedCapture(observed));
            panic!("simulate external codec panic");
        });
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn permissive_send_requires_option_and_policy_approval() {
        let registry = Arc::new(default_registry().unwrap());
        let client = Client::new(
            registry,
            FixedRoutes(route(LinkCapability::Layer3)),
            CountingNeighbors::default(),
            UnsupportedPacketIo,
            TrafficPolicy {
                allow_permissive_packets: true,
                ..TrafficPolicy::default()
            },
        );
        let mut request = packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            9,
        );
        request.get_mut::<Ipv4>().unwrap().total_length = WireValue::Exact(1);
        let error = client
            .send(
                request,
                SendOptions {
                    build: BuildOptions {
                        mode: crate::core::BuildMode::Permissive,
                        ..BuildOptions::default()
                    },
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
            )
            .unwrap_err();
        assert!(matches!(error, ClientError::PermissiveLiveOptInRequired));
    }

    #[test]
    fn send_materializes_route_selected_ip_source() {
        let io = RecordingIo::default();
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            FixedRoutes(route(LinkCapability::Layer3)),
            CountingNeighbors::default(),
            io.clone(),
            TrafficPolicy::default(),
        );
        let request = packet(Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(10, 0, 0, 2), 12345, 9);

        let report = client
            .send(
                request,
                SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
            )
            .unwrap();

        assert_eq!(&report.built.bytes[12..16], &[10, 0, 0, 1]);
        assert_eq!(io.0.lock().unwrap()[0], report.built.bytes);
    }

    #[test]
    fn send_materializes_resolved_and_interface_owned_macs() {
        let io = RecordingIo::default();
        let neighbors = CountingNeighbors::default();
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            FixedRoutes(RouteDecision {
                capability: LinkCapability::Layer2And3,
                link_type: LinkType::ETHERNET,
                ..route(LinkCapability::Layer2And3)
            }),
            neighbors.clone(),
            io,
            TrafficPolicy::default(),
        );
        let mut request = packet(Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(10, 0, 0, 2), 12345, 9);
        request.insert(0, Ethernet::default()).unwrap();

        let report = client
            .send(
                request,
                SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer2,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
            )
            .unwrap();

        assert_eq!(&report.built.bytes[..6], &[0, 1, 2, 3, 4, 5]);
        assert_eq!(&report.built.bytes[6..12], &[2, 0, 0, 0, 0, 1]);
        assert_eq!(neighbors.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn partial_backend_send_is_a_typed_failure() {
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            FixedRoutes(route(LinkCapability::Layer3)),
            CountingNeighbors::default(),
            PartialIo,
            TrafficPolicy::default(),
        );
        let error = client
            .send(
                packet(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                    12345,
                    9,
                ),
                SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ClientError::Io(LiveIoError::PartialSend { .. })
        ));
    }

    #[test]
    fn synthesized_ethernet_is_authorized_before_neighbor_traffic() {
        let neighbors = CountingNeighbors::default();
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            FixedRoutes(RouteDecision {
                capability: LinkCapability::Layer2And3,
                link_type: LinkType::ETHERNET,
                ..route(LinkCapability::Layer2And3)
            }),
            neighbors.clone(),
            UnsupportedPacketIo,
            TrafficPolicy {
                max_bytes_per_operation: 28,
                ..TrafficPolicy::default()
            },
        );
        let error = client
            .send(
                packet(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                    12345,
                    9,
                ),
                SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer2,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ClientError::Policy(TrafficPolicyError::ByteLimit {
                actual: 42,
                limit: 28
            })
        ));
        assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn mtu_uses_actual_network_span_even_for_permissive_lengths() {
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            FixedRoutes(route(LinkCapability::Layer3)),
            CountingNeighbors::default(),
            RecordingIo::default(),
            TrafficPolicy {
                allow_permissive_packets: true,
                ..TrafficPolicy::default()
            },
        );
        let mut request = packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            9,
        );
        request.push(crate::core::Raw::new(vec![0_u8; 2_000]));
        request.get_mut::<Ipv4>().unwrap().total_length = WireValue::Exact(20);
        let error = client
            .send(
                request,
                SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    build: BuildOptions {
                        mode: crate::core::BuildMode::Permissive,
                        ..BuildOptions::default()
                    },
                    allow_permissive_live: true,
                    ..SendOptions::default()
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ClientError::PacketExceedsMtu { actual, mtu: 1500 } if actual > 2_000
        ));
    }

    #[test]
    fn srh_policy_checks_final_segment_not_only_first_hop() {
        let source: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
        let first: std::net::Ipv6Addr = "fd00::10".parse().unwrap();
        let final_destination: std::net::Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let mut request = Packet::new();
        request
            .push(Ipv6 {
                source,
                destination: first,
                ..Ipv6::default()
            })
            .push(SegmentRoutingHeader {
                segments: vec![first, final_destination],
                ..SegmentRoutingHeader::default()
            })
            .push(Udp::default());
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            FixedRoutes(RouteDecision {
                selected_address: Some(IpAddr::V6(source)),
                preferred_source: Some(IpAddr::V6(source)),
                next_hop: None,
                capability: LinkCapability::Layer3,
                link_type: LinkType::IPV6,
                ..route(LinkCapability::Layer3)
            }),
            CountingNeighbors::default(),
            UnsupportedPacketIo,
            TrafficPolicy::default(),
        );

        let error = client
            .plan(
                &request,
                None,
                &PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
            )
            .unwrap_err();

        assert!(matches!(
            error,
            ClientError::Policy(TrafficPolicyError::PublicDestination { destination })
                if destination == IpAddr::V6(final_destination)
        ));
    }

    #[test]
    fn exchange_accounts_generated_template_packets_lazily() {
        let generated = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&generated);
        let mut base = packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            9,
        );
        base.push(crate::core::Raw::default());
        let template = PacketTemplate::new(base).axis(
            2,
            "bytes",
            TemplateValues::Generated {
                count: 100,
                generator: Arc::new(move |_| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    FieldValue::Bytes(Bytes::from(vec![0_u8; 1024]))
                }),
            },
        );
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            FixedRoutes(route(LinkCapability::Layer3)),
            CountingNeighbors::default(),
            FakeIo {
                events: Arc::new(Mutex::new(Vec::new())),
                response: Arc::new(Mutex::new(None)),
                deliver_before_send: false,
                limits: Arc::new(Mutex::new(Vec::new())),
                capture_statistics: CaptureStatistics::default(),
            },
            TrafficPolicy {
                max_bytes_per_operation: 2_200,
                ..TrafficPolicy::default()
            },
        );

        assert!(matches!(
            client.exchange(
                &template,
                ExchangeOptions {
                    send: SendOptions {
                        plan: PlanOptions {
                            link_mode: LinkMode::Layer3,
                            interface: None,
                            preferred_source: None,
                        },
                        ..SendOptions::default()
                    },
                    ..ExchangeOptions::default()
                },
            ),
            Err(ClientError::Policy(TrafficPolicyError::ByteLimit { .. }))
        ));
        assert!(generated.load(Ordering::SeqCst) <= 3);
    }
}
