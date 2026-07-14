use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::capture::{Frame, LinkType};
use crate::net::{
    CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureSession, CaptureStatistics,
    CapturedFrame, DestinationScope, InterfaceId, InterfaceInfo, InterfaceProvider, IoSendReport,
    Layer2Frame, Layer2Io, LinkCapability, LinkMode, LiveIoError, MAX_NEIGHBOR_VLAN_TAGS,
    MacAddress, MaterializedRoute, NeighborError, NeighborRequest, NeighborResolution,
    NeighborResolver, PlannedRoute, RouteDecision, RouteSelectionReason, SystemCaptureProvider,
    SystemInterfaceProvider, SystemLayer2Io,
};

use super::cache::{NeighborCacheEntry, NeighborCacheKey, NeighborExchangeOutcome};
use super::options::NeighborResolutionOptions;
use super::wire::{build_request_frame, is_unicast_mac, match_neighbor_response};

/// Injectable active resolver. Production composition uses the `System*`
/// providers; tests and applications can supply deterministic providers.
#[derive(Debug)]
pub struct ActiveNeighborResolver<I, L, C> {
    interfaces: I,
    layer2: L,
    capture: C,
    options: NeighborResolutionOptions,
    cache: Arc<Mutex<HashMap<NeighborCacheKey, NeighborCacheEntry>>>,
}

impl<I, L, C> Clone for ActiveNeighborResolver<I, L, C>
where
    I: Clone,
    L: Clone,
    C: Clone,
{
    fn clone(&self) -> Self {
        Self {
            interfaces: self.interfaces.clone(),
            layer2: self.layer2.clone(),
            capture: self.capture.clone(),
            options: self.options.clone(),
            cache: Arc::clone(&self.cache),
        }
    }
}

impl<I, L, C> ActiveNeighborResolver<I, L, C> {
    pub fn try_new(
        interfaces: I,
        layer2: L,
        capture: C,
        options: NeighborResolutionOptions,
    ) -> Result<Self, NeighborError> {
        Ok(Self {
            interfaces,
            layer2,
            capture,
            options: options.validate()?,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn options(&self) -> &NeighborResolutionOptions {
        &self.options
    }

    pub fn clear_cache(&self) -> Result<(), NeighborError> {
        self.cache
            .lock()
            .map_err(|_| NeighborError::State {
                message: "neighbor cache mutex was poisoned".to_owned(),
            })?
            .clear();
        Ok(())
    }
}

impl<I, L, C> Default for ActiveNeighborResolver<I, L, C>
where
    I: Default,
    L: Default,
    C: Default,
{
    fn default() -> Self {
        Self::try_new(
            I::default(),
            L::default(),
            C::default(),
            NeighborResolutionOptions::default(),
        )
        .expect("default neighbor resolution options are valid")
    }
}

/// Native resolver composed from the current target's interface, Layer 2,
/// and capture providers.
pub type SystemNeighborResolver =
    ActiveNeighborResolver<SystemInterfaceProvider, SystemLayer2Io, SystemCaptureProvider>;

impl<I, L, C> NeighborResolver for ActiveNeighborResolver<I, L, C>
where
    I: InterfaceProvider,
    L: Layer2Io,
    C: CaptureProvider,
{
    fn resolve(
        &self,
        interface: &InterfaceId,
        interface_source: IpAddr,
        target: IpAddr,
    ) -> Result<MacAddress, NeighborError> {
        let request = self.request_from_interface(interface, interface_source, target)?;
        self.resolve_active(&request)
            .map(|resolution| resolution.mac_address)
    }

    fn resolve_request(
        &self,
        request: &NeighborRequest,
    ) -> Result<NeighborResolution, NeighborError> {
        self.resolve_active(request)
    }
}

impl<I, L, C> ActiveNeighborResolver<I, L, C>
where
    I: InterfaceProvider,
    L: Layer2Io,
    C: CaptureProvider,
{
    fn request_from_interface(
        &self,
        interface: &InterfaceId,
        interface_source: IpAddr,
        target: IpAddr,
    ) -> Result<NeighborRequest, NeighborError> {
        let interfaces = self
            .interfaces
            .interfaces()
            .map_err(|source| NeighborError::Io {
                interface: interface.name.clone(),
                target,
                operation: "discovering the selected interface",
                source,
            })?;
        let selected = interfaces
            .into_iter()
            .find(|candidate| candidate.id == *interface)
            .ok_or_else(|| {
                resolution_error(interface, target, "interface was not found".to_owned())
            })?;
        request_from_interface_info(selected, interface_source, target)
    }

    fn resolve_active(
        &self,
        request: &NeighborRequest,
    ) -> Result<NeighborResolution, NeighborError> {
        validate_request(request)?;
        let cache_key = NeighborCacheKey::from(request);
        if let Some(mac_address) = self.cached(&cache_key)? {
            return Ok(NeighborResolution {
                mac_address,
                attempts: 0,
                cache_hit: true,
                captured: Vec::new(),
                evidence_truncated: false,
                capture_statistics: CaptureStatistics::default(),
            });
        }

        let (request_bytes, destination_mac) = build_request_frame(request)?;
        let planned_route = discovery_route(request, destination_mac);
        let materialized_route = MaterializedRoute {
            plan: planned_route.clone(),
            neighbor_resolution: None,
        };
        let limits = CaptureQueueLimits {
            max_frames: self.options.max_capture_queue_frames,
            max_bytes: self.options.max_captured_bytes,
            snap_length: self.options.snap_length,
            overflow_policy: CaptureOverflowPolicy::Fail,
        };
        let mut capture = self
            .capture
            .arm_capture(&planned_route, limits)
            .map_err(|error| map_io_error(request, "arming capture", error))?;
        let primary = self.exchange(request, &request_bytes, &materialized_route, &mut capture);
        let cleanup = capture.shutdown();
        // Shutdown joins the owned worker, so counters read afterward are the
        // final statistics for this discovery session.
        let statistics = capture.statistics();
        let outcome = match (primary, cleanup) {
            (Ok(outcome), Ok(())) => outcome,
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(cleanup)) => {
                return Err(NeighborError::Cleanup {
                    interface: request.interface.name.clone(),
                    target: request.target,
                    source: cleanup,
                });
            }
            (Err(operation), Err(cleanup)) => {
                return Err(NeighborError::OperationAndCleanup {
                    interface: request.interface.name.clone(),
                    target: request.target,
                    operation: Box::new(operation),
                    cleanup,
                });
            }
        };
        let validated_statistics = statistics
            .validate()
            .map_err(|error| map_io_error(request, "validating capture statistics", error))?;
        if let Some(error) = validated_statistics.evidence_loss_error() {
            return Err(map_io_error(
                request,
                "checking capture completeness",
                error,
            ));
        }

        let Some(mac_address) = outcome.mac_address else {
            return Err(NeighborError::NotFound {
                interface: request.interface.name.clone(),
                target: request.target,
                attempts: outcome.attempts,
                captured: outcome.captured,
                evidence_truncated: outcome.evidence_truncated,
                capture_statistics: validated_statistics,
            });
        };
        self.cache(mac_address, cache_key)?;
        Ok(NeighborResolution {
            mac_address,
            attempts: outcome.attempts,
            cache_hit: false,
            captured: outcome.captured,
            evidence_truncated: outcome.evidence_truncated,
            capture_statistics: validated_statistics,
        })
    }

    fn exchange<S: CaptureSession>(
        &self,
        request: &NeighborRequest,
        request_bytes: &Bytes,
        route: &MaterializedRoute,
        capture: &mut S,
    ) -> Result<NeighborExchangeOutcome, NeighborError> {
        capture
            .wait_ready(self.options.attempt_timeout)
            .map_err(|error| map_io_error(request, "waiting for capture readiness", error))?;
        let mut captured = Vec::new();
        let mut captured_bytes = 0usize;
        let mut evidence_truncated = false;

        // Frames captured before the first request are evidence but cannot
        // satisfy this lookup.
        for _ in 0..self.options.max_capture_queue_frames {
            let Some(captured_frame) = capture
                .next_captured_frame(Duration::ZERO)
                .map_err(|error| map_io_error(request, "draining pre-request capture", error))?
            else {
                break;
            };
            validate_captured_frame(request, &captured_frame.frame, self.options.snap_length)?;
            retain_evidence(
                captured_frame.frame,
                &self.options,
                &mut captured,
                &mut captured_bytes,
                &mut evidence_truncated,
            );
        }

        for attempt in 1..=self.options.max_attempts {
            let send_started = Instant::now();
            let frame = Layer2Frame::try_new(request_bytes, route)
                .map_err(|error| map_io_error(request, "constructing discovery frame", error))?;
            let report = self
                .layer2
                .send_layer2(frame)
                .map_err(|error| map_io_error(request, "sending discovery request", error))?;
            validate_send_report(request, request_bytes, report)?;

            let deadline = send_started
                .checked_add(self.options.attempt_timeout)
                .ok_or_else(|| invalid_configuration("attempt deadline overflowed".to_owned()))?;
            while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                let Some(captured_frame) =
                    capture.next_captured_frame(remaining).map_err(|error| {
                        map_io_error(request, "receiving discovery response", error)
                    })?
                else {
                    break;
                };
                let CapturedFrame { frame, received_at } = captured_frame;
                validate_captured_frame(request, &frame, self.options.snap_length)?;
                let Some(received_at) = received_at else {
                    retain_evidence(
                        frame,
                        &self.options,
                        &mut captured,
                        &mut captured_bytes,
                        &mut evidence_truncated,
                    );
                    continue;
                };
                if received_at < send_started || received_at > deadline {
                    retain_evidence(
                        frame,
                        &self.options,
                        &mut captured,
                        &mut captured_bytes,
                        &mut evidence_truncated,
                    );
                    continue;
                }
                let response = match_neighbor_response(request, &frame);
                if let Some(mac_address) = response {
                    retain_matching_evidence(
                        frame,
                        &self.options,
                        &mut captured,
                        &mut captured_bytes,
                        &mut evidence_truncated,
                    )?;
                    return Ok(NeighborExchangeOutcome {
                        mac_address: Some(mac_address),
                        attempts: attempt,
                        captured,
                        evidence_truncated,
                    });
                }
                retain_evidence(
                    frame,
                    &self.options,
                    &mut captured,
                    &mut captured_bytes,
                    &mut evidence_truncated,
                );
            }
        }
        Ok(NeighborExchangeOutcome {
            mac_address: None,
            attempts: self.options.max_attempts,
            captured,
            evidence_truncated,
        })
    }

    fn cached(&self, key: &NeighborCacheKey) -> Result<Option<MacAddress>, NeighborError> {
        let now = Instant::now();
        let mut cache = self.cache.lock().map_err(|_| NeighborError::State {
            message: "neighbor cache mutex was poisoned".to_owned(),
        })?;
        cache.retain(|_, entry| entry.expires_at > now);
        Ok(cache.get(key).map(|entry| entry.mac_address))
    }

    fn cache(&self, mac_address: MacAddress, key: NeighborCacheKey) -> Result<(), NeighborError> {
        let now = Instant::now();
        let expires_at = now
            .checked_add(self.options.cache_ttl)
            .ok_or_else(|| invalid_configuration("cache deadline overflowed".to_owned()))?;
        let mut cache = self.cache.lock().map_err(|_| NeighborError::State {
            message: "neighbor cache mutex was poisoned".to_owned(),
        })?;
        cache.retain(|_, entry| entry.expires_at > now);
        if !cache.contains_key(&key)
            && cache.len() >= self.options.max_cache_entries
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
        cache.insert(
            key,
            NeighborCacheEntry {
                mac_address,
                inserted_at: now,
                expires_at,
            },
        );
        Ok(())
    }
}

fn request_from_interface_info(
    interface: InterfaceInfo,
    interface_source: IpAddr,
    target: IpAddr,
) -> Result<NeighborRequest, NeighborError> {
    if !interface.flags.up {
        return Err(resolution_error(
            &interface.id,
            target,
            "interface is down".to_owned(),
        ));
    }
    if !matches!(
        interface.capability,
        LinkCapability::Layer2 | LinkCapability::Layer2And3
    ) {
        return Err(resolution_error(
            &interface.id,
            target,
            "interface does not support Layer 2 discovery".to_owned(),
        ));
    }
    if !interface
        .addresses
        .iter()
        .any(|assigned| assigned.address == interface_source)
    {
        return Err(NeighborError::InvalidRequest {
            message: format!(
                "source {interface_source} is not assigned to {}",
                interface.id.name
            ),
        });
    }
    let interface_mac = interface
        .mac_address
        .ok_or_else(|| NeighborError::MissingSourceMac {
            interface: interface.id.name.clone(),
        })?;
    Ok(NeighborRequest {
        interface: interface.id,
        interface_source,
        interface_mac,
        target,
        vlan_tags: Vec::new(),
        mtu: interface.mtu.ok_or_else(|| NeighborError::InvalidRequest {
            message: "interface has no native MTU".to_owned(),
        })?,
        link_type: interface.link_type,
    })
}

fn validate_request(request: &NeighborRequest) -> Result<(), NeighborError> {
    if request.interface_source.is_ipv4() != request.target.is_ipv4() {
        return Err(NeighborError::InvalidRequest {
            message: format!(
                "source {} and target {} use different address families",
                request.interface_source, request.target
            ),
        });
    }
    if request.interface_source.is_unspecified() || request.interface_source.is_multicast() {
        return Err(NeighborError::InvalidRequest {
            message: format!(
                "interface source {} is not a usable unicast address",
                request.interface_source
            ),
        });
    }
    if request.target.is_unspecified() || request.target.is_multicast() {
        return Err(NeighborError::InvalidRequest {
            message: format!("target {} is not a unicast neighbor", request.target),
        });
    }
    if request.link_type != LinkType::ETHERNET {
        return Err(NeighborError::InvalidRequest {
            message: format!(
                "link type {} does not support Ethernet ARP/NDP",
                request.link_type.0
            ),
        });
    }
    if !is_unicast_mac(request.interface_mac) {
        return Err(NeighborError::InvalidRequest {
            message: format!(
                "interface MAC {} is not an individual unicast address",
                request.interface_mac
            ),
        });
    }
    if request.mtu == 0 {
        return Err(NeighborError::InvalidRequest {
            message: "interface MTU is zero".to_owned(),
        });
    }
    if request.vlan_tags.len() > MAX_NEIGHBOR_VLAN_TAGS {
        return Err(NeighborError::InvalidRequest {
            message: format!("VLAN stack exceeds {MAX_NEIGHBOR_VLAN_TAGS} discovery tags"),
        });
    }
    for tag in &request.vlan_tags {
        if tag.priority > 7 || tag.vlan_id > 4095 {
            return Err(NeighborError::InvalidRequest {
                message: "VLAN priority or identifier is outside its wire range".to_owned(),
            });
        }
    }
    Ok(())
}

fn discovery_route(request: &NeighborRequest, destination_mac: MacAddress) -> PlannedRoute {
    PlannedRoute {
        route: RouteDecision {
            interface: request.interface.clone(),
            source_mac: Some(request.interface_mac),
            selected_address: Some(request.interface_source),
            preferred_source: None,
            next_hop: None,
            selection_reason: RouteSelectionReason::OnLink,
            destination_scope: DestinationScope::Link,
            mtu: request.mtu,
            capability: LinkCapability::Layer2,
            link_type: request.link_type,
        },
        mode: LinkMode::Layer2,
        lookup_destination: Some(request.target),
        final_destination: Some(request.target),
        visited_destinations: vec![request.target],
        packet_source: Some(request.interface_source),
        neighbor_source: Some(request.interface_source),
        neighbor_target: Some(request.target),
        destination_mac: Some(destination_mac),
        source_mac: Some(request.interface_mac),
        neighbor_vlan_tags: request.vlan_tags.clone(),
        synthesized_ethernet: false,
    }
}

fn retain_evidence(
    frame: Frame,
    options: &NeighborResolutionOptions,
    captured: &mut Vec<Frame>,
    captured_bytes: &mut usize,
    truncated: &mut bool,
) {
    let next_bytes = captured_bytes.checked_add(frame.bytes().len());
    if captured.len() >= options.max_capture_queue_frames
        || next_bytes.is_none_or(|bytes| bytes > options.max_captured_bytes)
    {
        *truncated = true;
        return;
    }
    *captured_bytes = next_bytes.expect("checked evidence bytes");
    captured.push(frame);
}

fn retain_matching_evidence(
    frame: Frame,
    options: &NeighborResolutionOptions,
    captured: &mut Vec<Frame>,
    captured_bytes: &mut usize,
    truncated: &mut bool,
) -> Result<(), NeighborError> {
    let frame_length = frame.bytes().len();
    while captured.len() >= options.max_capture_queue_frames
        || captured_bytes
            .checked_add(frame_length)
            .is_none_or(|bytes| bytes > options.max_captured_bytes)
    {
        let Some(discarded) = captured.first() else {
            return Err(NeighborError::State {
                message: "matching capture frame exceeded its validated evidence bound".to_owned(),
            });
        };
        *captured_bytes = captured_bytes
            .checked_sub(discarded.bytes().len())
            .ok_or_else(|| NeighborError::State {
                message: "neighbor evidence byte accounting underflowed".to_owned(),
            })?;
        captured.remove(0);
        *truncated = true;
    }
    *captured_bytes =
        captured_bytes
            .checked_add(frame_length)
            .ok_or_else(|| NeighborError::State {
                message: "neighbor evidence byte accounting overflowed".to_owned(),
            })?;
    captured.push(frame);
    Ok(())
}

fn validate_captured_frame(
    request: &NeighborRequest,
    frame: &Frame,
    snap_length: usize,
) -> Result<(), NeighborError> {
    frame.validate().map_err(|error| {
        resolution_error(
            &request.interface,
            request.target,
            format!("capture returned an invalid frame: {error}"),
        )
    })?;
    if frame.bytes().len() > snap_length {
        return Err(resolution_error(
            &request.interface,
            request.target,
            format!(
                "capture returned {} bytes beyond the configured {snap_length}-byte snap length",
                frame.bytes().len()
            ),
        ));
    }
    Ok(())
}

fn validate_send_report(
    request: &NeighborRequest,
    expected: &Bytes,
    report: IoSendReport,
) -> Result<(), NeighborError> {
    if report.bytes_sent != expected.len() {
        return Err(map_io_error(
            request,
            "sending discovery request",
            LiveIoError::PartialSend {
                expected: expected.len(),
                actual: report.bytes_sent,
            },
        ));
    }
    if let Some(wire_bytes) = report.wire_bytes
        && wire_bytes != *expected
    {
        return Err(map_io_error(
            request,
            "validating discovery send evidence",
            LiveIoError::InvalidSendEvidence {
                message: "discovery wire bytes differ from the exact submitted frame".to_owned(),
            },
        ));
    }
    Ok(())
}

fn invalid_configuration(message: String) -> NeighborError {
    NeighborError::InvalidConfiguration { message }
}

fn resolution_error(interface: &InterfaceId, target: IpAddr, message: String) -> NeighborError {
    NeighborError::Resolution {
        interface: interface.name.clone(),
        target,
        message,
    }
}

fn map_io_error(
    request: &NeighborRequest,
    operation: &'static str,
    error: LiveIoError,
) -> NeighborError {
    NeighborError::Io {
        interface: request.interface.name.clone(),
        target: request.target,
        operation,
        source: error,
    }
}
