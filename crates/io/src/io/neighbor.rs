// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, capture-before-send ARP and IPv6 Neighbor Discovery.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::{
    CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureSession, CaptureStatistics,
    CapturedFrame, DestinationScope, InterfaceId, InterfaceInfo, InterfaceProvider, IoSendReport,
    Layer2Frame, Layer2Io, LinkCapability, LinkMode, LinkType, LiveIoError, MacAddress,
    MaterializedRoute, NeighborError, NeighborRequest, NeighborResolution, NeighborResolver,
    NeighborVlanKind, NeighborVlanTag, PlannedRoute, RouteDecision, RouteSelectionReason,
    SystemCaptureProvider, SystemInterfaceProvider, SystemLayer2Io, MAX_NEIGHBOR_VLAN_TAGS,
};

const ETHERNET_HEADER_LENGTH: usize = 14;
const ETHERNET_MINIMUM_WITHOUT_FCS: usize = 60;
const VLAN_HEADER_LENGTH: usize = 4;
const ARP_PAYLOAD_LENGTH: usize = 28;
const IPV6_HEADER_LENGTH: usize = 40;
const NEIGHBOR_SOLICITATION_LENGTH: usize = 32;

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_SERVICE_VLAN: u16 = 0x88a8;
const IPV6_NEXT_HEADER_ICMP: u8 = 58;
const NEIGHBOR_SOLICITATION_TYPE: u8 = 135;
const NEIGHBOR_ADVERTISEMENT_TYPE: u8 = 136;
const SOURCE_LINK_LAYER_OPTION: u8 = 1;
const TARGET_LINK_LAYER_OPTION: u8 = 2;
const SOLICITED_ADVERTISEMENT_FLAG: u32 = 1 << 30;

const MAX_CONFIGURED_ATTEMPTS: u32 = 10;
const MAX_CONFIGURED_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONFIGURED_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_CONFIGURED_CACHE_ENTRIES: usize = 65_536;
const MAX_CONFIGURED_CAPTURE_FRAMES: usize = 4_096;
const MAX_CONFIGURED_CAPTURE_BYTES: usize = 256 * 1024 * 1024;
const MIN_NEIGHBOR_SNAPSHOT_LENGTH: usize = 128;

/// Finite work, retention, and cache bounds for active neighbor resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborResolutionOptions {
    pub max_attempts: u32,
    pub attempt_timeout: Duration,
    pub cache_ttl: Duration,
    pub max_cache_entries: usize,
    pub max_capture_queue_frames: usize,
    pub max_captured_bytes: usize,
    pub snap_length: usize,
}

impl Default for NeighborResolutionOptions {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            attempt_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(30),
            max_cache_entries: 4_096,
            max_capture_queue_frames: 256,
            max_captured_bytes: 1024 * 1024,
            snap_length: 2_048,
        }
    }
}

impl NeighborResolutionOptions {
    pub fn validate(self) -> Result<Self, NeighborError> {
        if !(1..=MAX_CONFIGURED_ATTEMPTS).contains(&self.max_attempts) {
            return Err(invalid_configuration(format!(
                "max_attempts must be within 1..={MAX_CONFIGURED_ATTEMPTS}"
            )));
        }
        if self.attempt_timeout.is_zero() || self.attempt_timeout > MAX_CONFIGURED_ATTEMPT_TIMEOUT {
            return Err(invalid_configuration(format!(
                "attempt_timeout must be within 1ns..={MAX_CONFIGURED_ATTEMPT_TIMEOUT:?}"
            )));
        }
        if self.cache_ttl.is_zero() || self.cache_ttl > MAX_CONFIGURED_CACHE_TTL {
            return Err(invalid_configuration(format!(
                "cache_ttl must be within 1ns..={MAX_CONFIGURED_CACHE_TTL:?}"
            )));
        }
        if !(1..=MAX_CONFIGURED_CACHE_ENTRIES).contains(&self.max_cache_entries) {
            return Err(invalid_configuration(format!(
                "max_cache_entries must be within 1..={MAX_CONFIGURED_CACHE_ENTRIES}"
            )));
        }
        if !(1..=MAX_CONFIGURED_CAPTURE_FRAMES).contains(&self.max_capture_queue_frames) {
            return Err(invalid_configuration(format!(
                "max_capture_queue_frames must be within 1..={MAX_CONFIGURED_CAPTURE_FRAMES}"
            )));
        }
        if self.max_captured_bytes == 0 || self.max_captured_bytes > MAX_CONFIGURED_CAPTURE_BYTES {
            return Err(invalid_configuration(format!(
                "max_captured_bytes must be within 1..={MAX_CONFIGURED_CAPTURE_BYTES}"
            )));
        }
        if self.snap_length < MIN_NEIGHBOR_SNAPSHOT_LENGTH {
            return Err(invalid_configuration(format!(
                "snap_length must be at least {MIN_NEIGHBOR_SNAPSHOT_LENGTH} bytes"
            )));
        }
        CaptureQueueLimits {
            max_frames: self.max_capture_queue_frames,
            max_bytes: self.max_captured_bytes,
            snap_length: self.snap_length,
            overflow_policy: CaptureOverflowPolicy::Fail,
        }
        .validate()
        .map_err(|error| invalid_configuration(error.to_string()))?;
        Ok(self)
    }
}

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
                })
            }
            (Err(operation), Err(cleanup)) => {
                return Err(NeighborError::OperationAndCleanup {
                    interface: request.interface.name.clone(),
                    target: request.target,
                    operation: Box::new(operation),
                    cleanup,
                })
            }
        };
        statistics
            .validate()
            .map_err(|error| map_io_error(request, "validating capture statistics", error))?;

        let Some(mac_address) = outcome.mac_address else {
            return Err(NeighborError::NotFound {
                interface: request.interface.name.clone(),
                target: request.target,
                attempts: outcome.attempts,
                captured: outcome.captured,
                evidence_truncated: outcome.evidence_truncated,
                capture_statistics: statistics,
            });
        };
        self.cache(mac_address, cache_key)?;
        Ok(NeighborResolution {
            mac_address,
            attempts: outcome.attempts,
            cache_hit: false,
            captured: outcome.captured,
            evidence_truncated: outcome.evidence_truncated,
            capture_statistics: statistics,
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
            .wait_ready()
            .map_err(|error| map_io_error(request, "waiting for capture readiness", error))?;
        let mut captured = Vec::new();
        let mut captured_bytes = 0usize;
        let mut evidence_truncated = false;

        // Frames captured before the first request are evidence but cannot
        // satisfy this lookup.
        while let Some(frame) = capture
            .next_frame(Duration::ZERO)
            .map_err(|error| map_io_error(request, "draining pre-request capture", error))?
        {
            validate_captured_frame(request, &frame, self.options.snap_length)?;
            retain_evidence(
                frame,
                &self.options,
                &mut captured,
                &mut captured_bytes,
                &mut evidence_truncated,
            )?;
        }

        for attempt in 1..=self.options.max_attempts {
            let frame = Layer2Frame::try_new(request_bytes, route)
                .map_err(|error| map_io_error(request, "constructing discovery frame", error))?;
            let report = self
                .layer2
                .send_layer2(frame)
                .map_err(|error| map_io_error(request, "sending discovery request", error))?;
            validate_send_report(request, request_bytes, report)?;

            let deadline = Instant::now()
                .checked_add(self.options.attempt_timeout)
                .ok_or_else(|| invalid_configuration("attempt deadline overflowed".to_owned()))?;
            while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                let Some(frame) = capture.next_frame(remaining).map_err(|error| {
                    map_io_error(request, "receiving discovery response", error)
                })?
                else {
                    break;
                };
                validate_captured_frame(request, &frame, self.options.snap_length)?;
                let response = match_neighbor_response(request, &frame)?;
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
                )?;
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
        if !cache.contains_key(&key) && cache.len() >= self.options.max_cache_entries {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest);
            }
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct NeighborCacheKey {
    interface: InterfaceId,
    interface_source: IpAddr,
    interface_mac: MacAddress,
    target: IpAddr,
    vlan_tags: Vec<NeighborVlanTag>,
    link_type: LinkType,
}

impl From<&NeighborRequest> for NeighborCacheKey {
    fn from(request: &NeighborRequest) -> Self {
        Self {
            interface: request.interface.clone(),
            interface_source: request.interface_source,
            interface_mac: request.interface_mac,
            target: request.target,
            vlan_tags: request.vlan_tags.clone(),
            link_type: request.link_type,
        }
    }
}

#[derive(Debug)]
struct NeighborCacheEntry {
    mac_address: MacAddress,
    inserted_at: Instant,
    expires_at: Instant,
}

struct NeighborExchangeOutcome {
    mac_address: Option<MacAddress>,
    attempts: u32,
    captured: Vec<CapturedFrame>,
    evidence_truncated: bool,
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

fn build_request_frame(request: &NeighborRequest) -> Result<(Bytes, MacAddress), NeighborError> {
    match (request.interface_source, request.target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            if ARP_PAYLOAD_LENGTH > request.mtu as usize {
                return Err(NeighborError::InvalidRequest {
                    message: format!(
                        "ARP request is {ARP_PAYLOAD_LENGTH} bytes but route MTU is {}",
                        request.mtu
                    ),
                });
            }
            let destination = MacAddress([0xff; 6]);
            Ok((build_arp_request(request, source, target), destination))
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            let ipv6_destination = solicited_node_multicast(target);
            let destination = ipv6_multicast_mac(ipv6_destination);
            let packet_length = IPV6_HEADER_LENGTH + NEIGHBOR_SOLICITATION_LENGTH;
            if packet_length > request.mtu as usize {
                return Err(NeighborError::InvalidRequest {
                    message: format!(
                        "IPv6 neighbor solicitation is {packet_length} bytes but route MTU is {}",
                        request.mtu
                    ),
                });
            }
            Ok((
                build_neighbor_solicitation(request, source, target, ipv6_destination, destination),
                destination,
            ))
        }
        _ => Err(NeighborError::InvalidRequest {
            message: "source and target address families differ".to_owned(),
        }),
    }
}

fn build_arp_request(request: &NeighborRequest, source: Ipv4Addr, target: Ipv4Addr) -> Bytes {
    let destination = MacAddress([0xff; 6]);
    let mut frame = ethernet_prefix(
        destination,
        request.interface_mac,
        &request.vlan_tags,
        ETHERTYPE_ARP,
    );
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame.extend_from_slice(&[6, 4]);
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&request.interface_mac.0);
    frame.extend_from_slice(&source.octets());
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&target.octets());
    frame.resize(
        ETHERNET_MINIMUM_WITHOUT_FCS + request.vlan_tags.len() * VLAN_HEADER_LENGTH,
        0,
    );
    Bytes::from(frame)
}

fn build_neighbor_solicitation(
    request: &NeighborRequest,
    source: Ipv6Addr,
    target: Ipv6Addr,
    destination: Ipv6Addr,
    destination_mac: MacAddress,
) -> Bytes {
    let mut frame = ethernet_prefix(
        destination_mac,
        request.interface_mac,
        &request.vlan_tags,
        ETHERTYPE_IPV6,
    );
    let mut icmp = Vec::with_capacity(NEIGHBOR_SOLICITATION_LENGTH);
    icmp.extend_from_slice(&[NEIGHBOR_SOLICITATION_TYPE, 0, 0, 0]);
    icmp.extend_from_slice(&[0; 4]);
    icmp.extend_from_slice(&target.octets());
    icmp.extend_from_slice(&[SOURCE_LINK_LAYER_OPTION, 1]);
    icmp.extend_from_slice(&request.interface_mac.0);
    let checksum = icmpv6_checksum(source, destination, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&(NEIGHBOR_SOLICITATION_LENGTH as u16).to_be_bytes());
    frame.extend_from_slice(&[IPV6_NEXT_HEADER_ICMP, 255]);
    frame.extend_from_slice(&source.octets());
    frame.extend_from_slice(&destination.octets());
    frame.extend_from_slice(&icmp);
    Bytes::from(frame)
}

fn ethernet_prefix(
    destination: MacAddress,
    source: MacAddress,
    tags: &[NeighborVlanTag],
    payload_type: u16,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(
        ETHERNET_HEADER_LENGTH + tags.len() * VLAN_HEADER_LENGTH + ARP_PAYLOAD_LENGTH,
    );
    frame.extend_from_slice(&destination.0);
    frame.extend_from_slice(&source.0);
    frame.extend_from_slice(
        &tags
            .first()
            .map_or(payload_type, |tag| tag.kind.ether_type())
            .to_be_bytes(),
    );
    for (index, tag) in tags.iter().enumerate() {
        let tci = (u16::from(tag.priority) << 13)
            | (if tag.drop_eligible { 1 << 12 } else { 0 })
            | tag.vlan_id;
        frame.extend_from_slice(&tci.to_be_bytes());
        let next = tags
            .get(index + 1)
            .map_or(payload_type, |next| next.kind.ether_type());
        frame.extend_from_slice(&next.to_be_bytes());
    }
    frame
}

fn match_neighbor_response(
    request: &NeighborRequest,
    frame: &CapturedFrame,
) -> Result<Option<MacAddress>, NeighborError> {
    if frame.link_type != LinkType::ETHERNET
        || frame
            .interface
            .is_some_and(|index| index != request.interface.index)
    {
        return Ok(None);
    }
    let Some(ethernet) = parse_ethernet(&frame.bytes)? else {
        return Ok(None);
    };
    if ethernet.destination != request.interface_mac || ethernet.vlan_tags != request.vlan_tags {
        return Ok(None);
    }
    match (
        request.interface_source,
        request.target,
        ethernet.ether_type,
    ) {
        (IpAddr::V4(source), IpAddr::V4(target), ETHERTYPE_ARP) => {
            match_arp_response(request, source, target, ethernet)
        }
        (IpAddr::V6(source), IpAddr::V6(target), ETHERTYPE_IPV6) => {
            match_neighbor_advertisement(source, target, ethernet)
        }
        _ => Ok(None),
    }
}

struct EthernetView<'a> {
    destination: MacAddress,
    source: MacAddress,
    vlan_tags: Vec<NeighborVlanTag>,
    ether_type: u16,
    payload: &'a [u8],
}

fn parse_ethernet(bytes: &[u8]) -> Result<Option<EthernetView<'_>>, NeighborError> {
    if bytes.len() < ETHERNET_HEADER_LENGTH {
        return Ok(None);
    }
    let mut destination = [0; 6];
    destination.copy_from_slice(&bytes[..6]);
    let mut source = [0; 6];
    source.copy_from_slice(&bytes[6..12]);
    let mut ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
    let mut offset = ETHERNET_HEADER_LENGTH;
    let mut vlan_tags = Vec::new();
    while matches!(ether_type, ETHERTYPE_VLAN | ETHERTYPE_SERVICE_VLAN) {
        if vlan_tags.len() >= MAX_NEIGHBOR_VLAN_TAGS {
            return Ok(None);
        }
        let Some(header) = bytes.get(offset..offset + VLAN_HEADER_LENGTH) else {
            return Ok(None);
        };
        let tci = u16::from_be_bytes([header[0], header[1]]);
        vlan_tags.push(NeighborVlanTag {
            kind: if ether_type == ETHERTYPE_SERVICE_VLAN {
                NeighborVlanKind::Ieee8021Ad
            } else {
                NeighborVlanKind::Ieee8021Q
            },
            priority: ((tci >> 13) & 7) as u8,
            drop_eligible: (tci & 0x1000) != 0,
            vlan_id: tci & 0x0fff,
        });
        ether_type = u16::from_be_bytes([header[2], header[3]]);
        offset += VLAN_HEADER_LENGTH;
    }
    Ok(Some(EthernetView {
        destination: MacAddress(destination),
        source: MacAddress(source),
        vlan_tags,
        ether_type,
        payload: &bytes[offset..],
    }))
}

fn match_arp_response(
    request: &NeighborRequest,
    source: Ipv4Addr,
    target: Ipv4Addr,
    ethernet: EthernetView<'_>,
) -> Result<Option<MacAddress>, NeighborError> {
    let Some(arp) = ethernet.payload.get(..ARP_PAYLOAD_LENGTH) else {
        return Ok(None);
    };
    if arp[..8] != [0, 1, 0x08, 0, 6, 4, 0, 2] {
        return Ok(None);
    }
    let mut sender_mac = [0; 6];
    sender_mac.copy_from_slice(&arp[8..14]);
    let sender_ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    let mut target_mac = [0; 6];
    target_mac.copy_from_slice(&arp[18..24]);
    let target_ip = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);
    let sender_mac = MacAddress(sender_mac);
    if sender_ip != target
        || target_ip != source
        || target_mac != request.interface_mac.0
        || ethernet.source != sender_mac
        || !is_unicast_mac(sender_mac)
    {
        return Ok(None);
    }
    Ok(Some(sender_mac))
}

fn match_neighbor_advertisement(
    interface_source: Ipv6Addr,
    target: Ipv6Addr,
    ethernet: EthernetView<'_>,
) -> Result<Option<MacAddress>, NeighborError> {
    if ethernet.payload.len() < IPV6_HEADER_LENGTH {
        return Ok(None);
    }
    let ipv6 = ethernet.payload;
    if ipv6[0] >> 4 != 6 || ipv6[6] != IPV6_NEXT_HEADER_ICMP || ipv6[7] != 255 {
        return Ok(None);
    }
    let payload_length = usize::from(u16::from_be_bytes([ipv6[4], ipv6[5]]));
    let Some(icmp) = ipv6.get(IPV6_HEADER_LENGTH..IPV6_HEADER_LENGTH + payload_length) else {
        return Ok(None);
    };
    if icmp.len() < 24
        || icmp[0] != NEIGHBOR_ADVERTISEMENT_TYPE
        || icmp[1] != 0
        || u32::from_be_bytes([icmp[4], icmp[5], icmp[6], icmp[7]]) & SOLICITED_ADVERTISEMENT_FLAG
            == 0
    {
        return Ok(None);
    }
    let source = ipv6_address(&ipv6[8..24]);
    let destination = ipv6_address(&ipv6[24..40]);
    let advertised_target = ipv6_address(&icmp[8..24]);
    if source.is_unspecified()
        || source.is_multicast()
        || destination != interface_source
        || advertised_target != target
        || advertised_target.is_multicast()
        || icmpv6_checksum(source, destination, icmp) != 0
    {
        return Ok(None);
    }

    let mut option_offset = 24;
    let mut target_mac = None;
    while option_offset < icmp.len() {
        let Some(header) = icmp.get(option_offset..option_offset + 2) else {
            return Ok(None);
        };
        let option_length = usize::from(header[1]) * 8;
        if option_length == 0 {
            return Ok(None);
        }
        let Some(option) = icmp.get(option_offset..option_offset + option_length) else {
            return Ok(None);
        };
        if header[0] == TARGET_LINK_LAYER_OPTION {
            if option_length != 8 {
                return Ok(None);
            }
            let mut mac = [0; 6];
            mac.copy_from_slice(&option[2..8]);
            let mac = MacAddress(mac);
            if target_mac.is_some_and(|existing| existing != mac) {
                return Ok(None);
            }
            target_mac = Some(mac);
        }
        option_offset += option_length;
    }
    let Some(target_mac) = target_mac else {
        return Ok(None);
    };
    if target_mac != ethernet.source || !is_unicast_mac(target_mac) {
        return Ok(None);
    }
    Ok(Some(target_mac))
}

fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let target = target.octets();
    let mut multicast = [0_u8; 16];
    multicast[0] = 0xff;
    multicast[1] = 0x02;
    multicast[11] = 0x01;
    multicast[12] = 0xff;
    multicast[13..].copy_from_slice(&target[13..]);
    Ipv6Addr::from(multicast)
}

fn ipv6_multicast_mac(address: Ipv6Addr) -> MacAddress {
    let address = address.octets();
    MacAddress([
        0x33,
        0x33,
        address[12],
        address[13],
        address[14],
        address[15],
    ])
}

fn ipv6_address(bytes: &[u8]) -> Ipv6Addr {
    let mut address = [0; 16];
    address.copy_from_slice(bytes);
    Ipv6Addr::from(address)
}

fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, message: &[u8]) -> u16 {
    let length = u32::try_from(message.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes();
    checksum(&[
        &source.octets(),
        &destination.octets(),
        &length,
        &[0, 0, 0, IPV6_NEXT_HEADER_ICMP],
        message,
    ])
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u64;
    let mut pending = None;
    for part in parts {
        let mut bytes = *part;
        if let Some(high) = pending.take() {
            if let Some((&low, rest)) = bytes.split_first() {
                sum += u64::from(u16::from_be_bytes([high, low]));
                bytes = rest;
            } else {
                pending = Some(high);
                continue;
            }
        }
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u64::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        pending = chunks.remainder().first().copied();
    }
    if let Some(high) = pending {
        sum += u64::from(u16::from_be_bytes([high, 0]));
    }
    while sum > u64::from(u16::MAX) {
        sum = (sum & u64::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
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
    frame: CapturedFrame,
    options: &NeighborResolutionOptions,
    captured: &mut Vec<CapturedFrame>,
    captured_bytes: &mut usize,
    truncated: &mut bool,
) -> Result<(), NeighborError> {
    let next_bytes = captured_bytes.checked_add(frame.bytes.len());
    if captured.len() >= options.max_capture_queue_frames
        || next_bytes.is_none_or(|bytes| bytes > options.max_captured_bytes)
    {
        *truncated = true;
        return Ok(());
    }
    *captured_bytes = next_bytes.expect("checked evidence bytes");
    captured.push(frame);
    Ok(())
}

fn retain_matching_evidence(
    frame: CapturedFrame,
    options: &NeighborResolutionOptions,
    captured: &mut Vec<CapturedFrame>,
    captured_bytes: &mut usize,
    truncated: &mut bool,
) -> Result<(), NeighborError> {
    let frame_length = frame.bytes.len();
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
            .checked_sub(discarded.bytes.len())
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
    frame: &CapturedFrame,
    snap_length: usize,
) -> Result<(), NeighborError> {
    frame.validate().map_err(|error| {
        resolution_error(
            &request.interface,
            request.target,
            format!("capture returned an invalid frame: {error}"),
        )
    })?;
    if frame.bytes.len() > snap_length {
        return Err(resolution_error(
            &request.interface,
            request.target,
            format!(
                "capture returned {} bytes beyond the configured {snap_length}-byte snap length",
                frame.bytes.len()
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
    if let Some(wire_bytes) = report.wire_bytes {
        if wire_bytes != *expected {
            return Err(map_io_error(
                request,
                "validating discovery send evidence",
                LiveIoError::InvalidSendEvidence {
                    message: "discovery wire bytes differ from the exact submitted frame"
                        .to_owned(),
                },
            ));
        }
    }
    Ok(())
}

fn is_unicast_mac(address: MacAddress) -> bool {
    address.0 != [0; 6] && address.0 != [0xff; 6] && address.0[0] & 1 == 0
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Condvar, MutexGuard};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::error::ClassifiedError;
    use crate::io::{
        CaptureDirection, InterfaceAddress, InterfaceFlags, IoSendReport, LiveIoError,
    };

    type ResponseFactory = dyn Fn(&Bytes) -> Vec<CapturedFrame> + Send + Sync;

    #[derive(Default)]
    struct MockState {
        ready: bool,
        sent: Vec<Bytes>,
        planned: Vec<PlannedRoute>,
        frames: VecDeque<CapturedFrame>,
        shutdowns: usize,
    }

    #[derive(Default)]
    struct MockShared {
        state: Mutex<MockState>,
        changed: Condvar,
    }

    impl MockShared {
        fn lock(&self) -> MutexGuard<'_, MockState> {
            self.state.lock().unwrap()
        }
    }

    #[derive(Clone)]
    struct MockInterfaces(InterfaceInfo);

    impl InterfaceProvider for MockInterfaces {
        fn interfaces(&self) -> Result<Vec<InterfaceInfo>, LiveIoError> {
            Ok(vec![self.0.clone()])
        }
    }

    #[derive(Clone)]
    struct MockLayer2 {
        shared: Arc<MockShared>,
        responses: Arc<ResponseFactory>,
    }

    impl Layer2Io for MockLayer2 {
        fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
            let bytes = frame.bytes().clone();
            let responses = (self.responses)(&bytes);
            let mut state = self.shared.lock();
            assert!(state.ready, "capture must be ready before neighbor send");
            assert_eq!(frame.route().plan.mode, LinkMode::Layer2);
            state.sent.push(bytes.clone());
            state.frames.extend(responses);
            self.shared.changed.notify_all();
            Ok(IoSendReport {
                bytes_sent: bytes.len(),
                wire_bytes: Some(bytes),
            })
        }
    }

    #[derive(Clone)]
    struct MockCaptureProvider(Arc<MockShared>);

    impl CaptureProvider for MockCaptureProvider {
        type Capture = MockCaptureSession;

        fn arm_capture(
            &self,
            route: &PlannedRoute,
            limits: CaptureQueueLimits,
        ) -> Result<Self::Capture, LiveIoError> {
            limits.validate()?;
            self.0.lock().planned.push(route.clone());
            Ok(MockCaptureSession(Arc::clone(&self.0)))
        }
    }

    struct MockCaptureSession(Arc<MockShared>);

    impl CaptureSession for MockCaptureSession {
        fn wait_ready(&mut self) -> Result<(), LiveIoError> {
            self.0.lock().ready = true;
            self.0.changed.notify_all();
            Ok(())
        }

        fn next_frame(&mut self, timeout: Duration) -> Result<Option<CapturedFrame>, LiveIoError> {
            let mut state = self.0.lock();
            if let Some(frame) = state.frames.pop_front() {
                return Ok(Some(frame));
            }
            if timeout.is_zero() {
                return Ok(None);
            }
            let (mut state, _) = self.0.changed.wait_timeout(state, timeout).unwrap();
            Ok(state.frames.pop_front())
        }

        fn shutdown(&mut self) -> Result<(), LiveIoError> {
            let mut state = self.0.lock();
            state.ready = false;
            state.shutdowns += 1;
            Ok(())
        }

        fn statistics(&self) -> CaptureStatistics {
            CaptureStatistics::default()
        }
    }

    fn interface() -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId {
                name: "mock0".to_owned(),
                index: 7,
            },
            description: Some("mock interface".to_owned()),
            mac_address: Some(MacAddress([0x02, 0, 0, 0, 0, 7])),
            addresses: vec![
                InterfaceAddress {
                    address: "192.0.2.7".parse().unwrap(),
                    prefix_length: 24,
                },
                InterfaceAddress {
                    address: "2001:db8::7".parse().unwrap(),
                    prefix_length: 64,
                },
            ],
            flags: InterfaceFlags {
                up: true,
                broadcast: true,
                multicast: true,
                ..InterfaceFlags::default()
            },
            mtu: Some(1_500),
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
        }
    }

    fn request(source: &str, target: &str) -> NeighborRequest {
        let interface = interface();
        NeighborRequest {
            interface: interface.id,
            interface_source: source.parse().unwrap(),
            interface_mac: interface.mac_address.unwrap(),
            target: target.parse().unwrap(),
            vlan_tags: Vec::new(),
            mtu: interface.mtu.unwrap(),
            link_type: interface.link_type,
        }
    }

    fn options() -> NeighborResolutionOptions {
        NeighborResolutionOptions {
            max_attempts: 2,
            attempt_timeout: Duration::from_millis(20),
            cache_ttl: Duration::from_secs(30),
            max_cache_entries: 8,
            max_capture_queue_frames: 8,
            max_captured_bytes: 8 * 2_048,
            snap_length: 2_048,
        }
    }

    fn resolver(
        shared: Arc<MockShared>,
        responses: Arc<ResponseFactory>,
        options: NeighborResolutionOptions,
    ) -> ActiveNeighborResolver<MockInterfaces, MockLayer2, MockCaptureProvider> {
        ActiveNeighborResolver::try_new(
            MockInterfaces(interface()),
            MockLayer2 {
                shared: Arc::clone(&shared),
                responses,
            },
            MockCaptureProvider(shared),
            options,
        )
        .unwrap()
    }

    fn captured(bytes: Bytes, interface: u32) -> CapturedFrame {
        let mut frame = CapturedFrame::new(UNIX_EPOCH, LinkType::ETHERNET, bytes).unwrap();
        frame.interface = Some(interface);
        frame.direction = Some(CaptureDirection::Inbound);
        frame
    }

    fn arp_reply(request: &NeighborRequest, target_mac: MacAddress) -> CapturedFrame {
        let (IpAddr::V4(source), IpAddr::V4(target)) = (request.interface_source, request.target)
        else {
            panic!("IPv4 request required");
        };
        let mut frame = ethernet_prefix(
            request.interface_mac,
            target_mac,
            &request.vlan_tags,
            ETHERTYPE_ARP,
        );
        frame.extend_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 2]);
        frame.extend_from_slice(&target_mac.0);
        frame.extend_from_slice(&target.octets());
        frame.extend_from_slice(&request.interface_mac.0);
        frame.extend_from_slice(&source.octets());
        frame.resize(
            ETHERNET_MINIMUM_WITHOUT_FCS + request.vlan_tags.len() * VLAN_HEADER_LENGTH,
            0,
        );
        captured(Bytes::from(frame), request.interface.index)
    }

    fn neighbor_advertisement(request: &NeighborRequest, target_mac: MacAddress) -> CapturedFrame {
        let (IpAddr::V6(interface_source), IpAddr::V6(target)) =
            (request.interface_source, request.target)
        else {
            panic!("IPv6 request required");
        };
        let mut icmp = Vec::with_capacity(NEIGHBOR_SOLICITATION_LENGTH);
        icmp.extend_from_slice(&[NEIGHBOR_ADVERTISEMENT_TYPE, 0, 0, 0]);
        icmp.extend_from_slice(&(SOLICITED_ADVERTISEMENT_FLAG | (1 << 29)).to_be_bytes());
        icmp.extend_from_slice(&target.octets());
        icmp.extend_from_slice(&[TARGET_LINK_LAYER_OPTION, 1]);
        icmp.extend_from_slice(&target_mac.0);
        let checksum = icmpv6_checksum(target, interface_source, &icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

        let mut frame = ethernet_prefix(
            request.interface_mac,
            target_mac,
            &request.vlan_tags,
            ETHERTYPE_IPV6,
        );
        frame.extend_from_slice(&[0x60, 0, 0, 0]);
        frame.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
        frame.extend_from_slice(&[IPV6_NEXT_HEADER_ICMP, 255]);
        frame.extend_from_slice(&target.octets());
        frame.extend_from_slice(&interface_source.octets());
        frame.extend_from_slice(&icmp);
        captured(Bytes::from(frame), request.interface.index)
    }

    #[test]
    fn arp_resolution_preserves_vlan_route_and_uses_cache() {
        let mut request = request("192.0.2.7", "192.0.2.1");
        request.vlan_tags = vec![
            NeighborVlanTag {
                kind: NeighborVlanKind::Ieee8021Ad,
                priority: 5,
                drop_eligible: false,
                vlan_id: 100,
            },
            NeighborVlanTag {
                kind: NeighborVlanKind::Ieee8021Q,
                priority: 1,
                drop_eligible: true,
                vlan_id: 200,
            },
        ];
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let response_request = request.clone();
        let shared = Arc::new(MockShared::default());
        let resolver = resolver(
            Arc::clone(&shared),
            Arc::new(move |_| vec![arp_reply(&response_request, target_mac)]),
            options(),
        );

        let resolution = resolver.resolve_request(&request).unwrap();
        assert_eq!(resolution.mac_address, target_mac);
        assert_eq!(resolution.attempts, 1);
        assert_eq!(resolution.captured.len(), 1);
        assert!(!resolution.cache_hit);
        let state = shared.lock();
        assert_eq!(state.shutdowns, 1);
        assert_eq!(state.sent.len(), 1);
        assert_eq!(
            state.sent[0].len(),
            ETHERNET_MINIMUM_WITHOUT_FCS + 2 * VLAN_HEADER_LENGTH
        );
        assert_eq!(&state.sent[0][..6], &[0xff; 6]);
        assert_eq!(&state.sent[0][6..12], &request.interface_mac.0);
        assert_eq!(
            &state.sent[0][12..14],
            &ETHERTYPE_SERVICE_VLAN.to_be_bytes()
        );
        assert_eq!(state.planned[0].route.mtu, request.mtu);
        assert_eq!(state.planned[0].neighbor_vlan_tags, request.vlan_tags);
        drop(state);

        let cached = resolver.resolve_request(&request).unwrap();
        assert!(cached.cache_hit);
        assert_eq!(cached.attempts, 0);
        assert_eq!(shared.lock().sent.len(), 1);
    }

    #[test]
    fn ndp_solicitation_and_advertisement_follow_wire_contract() {
        let request = request("2001:db8::7", "2001:db8::1");
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let response_request = request.clone();
        let shared = Arc::new(MockShared::default());
        let resolver = resolver(
            Arc::clone(&shared),
            Arc::new(move |_| vec![neighbor_advertisement(&response_request, target_mac)]),
            options(),
        );

        let resolution = resolver.resolve_request(&request).unwrap();
        assert_eq!(resolution.mac_address, target_mac);
        let sent = shared.lock().sent[0].clone();
        assert_eq!(&sent[..6], &[0x33, 0x33, 0xff, 0, 0, 1]);
        assert_eq!(sent[20], IPV6_NEXT_HEADER_ICMP);
        assert_eq!(sent[21], 255);
        let destination = ipv6_address(&sent[38..54]);
        assert_eq!(destination, "ff02::1:ff00:1".parse::<Ipv6Addr>().unwrap());
        let icmp = &sent[ETHERNET_HEADER_LENGTH + IPV6_HEADER_LENGTH..];
        assert_eq!(icmp[0], NEIGHBOR_SOLICITATION_TYPE);
        assert_eq!(
            &icmp[8..24],
            &request
                .target
                .to_string()
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(&icmp[24..26], &[SOURCE_LINK_LAYER_OPTION, 1]);
        assert_eq!(
            icmpv6_checksum(
                request.interface_source.to_string().parse().unwrap(),
                destination,
                icmp
            ),
            0
        );
    }

    #[test]
    fn ndp_rejects_bad_checksum_before_accepting_correlated_evidence() {
        let request = request("2001:db8::7", "2001:db8::1");
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let response_request = request.clone();
        let shared = Arc::new(MockShared::default());
        let resolver = resolver(
            Arc::clone(&shared),
            Arc::new(move |_| {
                let valid = neighbor_advertisement(&response_request, target_mac);
                let mut bad = valid.clone();
                let mut bytes = bad.bytes.to_vec();
                bytes[ETHERNET_HEADER_LENGTH + IPV6_HEADER_LENGTH + 2] ^= 0xff;
                bad.bytes = Bytes::from(bytes);
                vec![bad, valid]
            }),
            options(),
        );

        let resolution = resolver.resolve_request(&request).unwrap();
        assert_eq!(resolution.mac_address, target_mac);
        assert_eq!(resolution.attempts, 1);
        assert_eq!(resolution.captured.len(), 2);
        assert_eq!(shared.lock().sent.len(), 1);
    }

    #[test]
    fn arp_rejects_responses_from_another_vlan_or_interface() {
        let mut request = request("192.0.2.7", "192.0.2.1");
        request.vlan_tags.push(NeighborVlanTag {
            kind: NeighborVlanKind::Ieee8021Q,
            priority: 0,
            drop_eligible: false,
            vlan_id: 100,
        });
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let correct_request = request.clone();
        let mut other_vlan_request = request.clone();
        other_vlan_request.vlan_tags[0].vlan_id = 101;
        let shared = Arc::new(MockShared::default());
        let mut bounded = options();
        bounded.max_attempts = 1;
        bounded.attempt_timeout = Duration::from_millis(5);
        let resolver = resolver(
            Arc::clone(&shared),
            Arc::new(move |_| {
                let wrong_vlan = arp_reply(&other_vlan_request, target_mac);
                let mut wrong_interface = arp_reply(&correct_request, target_mac);
                wrong_interface.interface = Some(correct_request.interface.index + 1);
                vec![wrong_vlan, wrong_interface]
            }),
            bounded,
        );

        let error = resolver.resolve_request(&request).unwrap_err();
        assert!(matches!(
            error,
            NeighborError::NotFound {
                attempts: 1,
                captured,
                ..
            } if captured.len() == 2
        ));
        assert_eq!(shared.lock().sent.len(), 1);
    }

    #[test]
    fn timeout_is_bounded_attempted_and_joined() {
        let request = request("192.0.2.7", "192.0.2.99");
        let shared = Arc::new(MockShared::default());
        let mut bounded = options();
        bounded.max_capture_queue_frames = 1;
        let resolver = resolver(
            Arc::clone(&shared),
            Arc::new(|_| {
                vec![captured(
                    Bytes::from_static(&[0; ETHERNET_HEADER_LENGTH]),
                    7,
                )]
            }),
            bounded,
        );
        let error = resolver.resolve_request(&request).unwrap_err();
        assert_eq!(
            error.classification().category,
            crate::error::FailureCategory::Timeout
        );
        let NeighborError::NotFound {
            attempts,
            captured,
            evidence_truncated,
            ..
        } = error
        else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(attempts, 2);
        assert_eq!(captured.len(), 1);
        assert!(evidence_truncated);
        let state = shared.lock();
        assert_eq!(state.sent.len(), 2);
        assert_eq!(state.shutdowns, 1);
    }

    #[test]
    fn pre_request_frames_cannot_satisfy_lookup_and_evidence_is_bounded() {
        let request = request("192.0.2.7", "192.0.2.1");
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let shared = Arc::new(MockShared::default());
        shared
            .lock()
            .frames
            .push_back(arp_reply(&request, target_mac));
        let response_request = request.clone();
        let mut bounded = options();
        bounded.max_capture_queue_frames = 1;
        let resolver = resolver(
            Arc::clone(&shared),
            Arc::new(move |_| {
                let mut response = arp_reply(&response_request, target_mac);
                response.timestamp = UNIX_EPOCH + Duration::from_secs(1);
                vec![response]
            }),
            bounded,
        );
        let resolution = resolver.resolve_request(&request).unwrap();
        assert_eq!(resolution.mac_address, target_mac);
        assert_eq!(resolution.captured.len(), 1);
        assert_eq!(
            resolution.captured[0].timestamp,
            UNIX_EPOCH + Duration::from_secs(1)
        );
        assert!(resolution.evidence_truncated);
        assert_eq!(shared.lock().sent.len(), 1);
    }

    #[test]
    fn low_mtu_rejects_ndp_before_native_side_effects() {
        let mut request = request("2001:db8::7", "2001:db8::1");
        request.mtu = 64;
        let shared = Arc::new(MockShared::default());
        let resolver = resolver(Arc::clone(&shared), Arc::new(|_| Vec::new()), options());
        assert!(matches!(
            resolver.resolve_request(&request),
            Err(NeighborError::InvalidRequest { .. })
        ));
        let state = shared.lock();
        assert!(state.sent.is_empty());
        assert!(state.planned.is_empty());
    }

    #[test]
    fn low_mtu_rejects_arp_before_native_side_effects() {
        let mut request = request("192.0.2.7", "192.0.2.1");
        request.mtu = (ARP_PAYLOAD_LENGTH - 1) as u32;
        let shared = Arc::new(MockShared::default());
        let resolver = resolver(Arc::clone(&shared), Arc::new(|_| Vec::new()), options());
        assert!(matches!(
            resolver.resolve_request(&request),
            Err(NeighborError::InvalidRequest { .. })
        ));
        let state = shared.lock();
        assert!(state.sent.is_empty());
        assert!(state.planned.is_empty());
    }

    #[test]
    fn invalid_options_fail_before_provider_construction() {
        let mut invalid = options();
        invalid.max_attempts = 0;
        assert!(matches!(
            invalid.validate(),
            Err(NeighborError::InvalidConfiguration { .. })
        ));
        let mut invalid = options();
        invalid.snap_length = 64;
        assert!(matches!(
            invalid.validate(),
            Err(NeighborError::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn direct_resolve_uses_interface_owned_metadata() {
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let request = request("192.0.2.7", "192.0.2.1");
        let response_request = request.clone();
        let shared = Arc::new(MockShared::default());
        let resolver = resolver(
            shared,
            Arc::new(move |_| vec![arp_reply(&response_request, target_mac)]),
            options(),
        );
        assert_eq!(
            resolver
                .resolve(&request.interface, request.interface_source, request.target)
                .unwrap(),
            target_mac
        );
    }

    #[test]
    fn checksum_carries_across_odd_part_boundaries() {
        assert_eq!(checksum(&[&[0x12], &[0x34, 0x56], &[0x78]]), 0x9753);
    }

    #[test]
    fn captured_helper_uses_stable_timestamp() {
        let frame = captured(Bytes::from_static(&[0; 14]), 7);
        assert_eq!(frame.timestamp, SystemTime::UNIX_EPOCH);
    }
}
