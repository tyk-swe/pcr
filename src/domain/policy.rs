// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::domain::request::{PacketRequest, TransmissionRequest};
use crate::domain::spec::{Ipv6ExtHeader, PacketSpec, TargetAddress, TransportSpec};

pub const DEFAULT_MAX_TARGETS: usize = 256;
pub const DEFAULT_MAX_PORTS: usize = 1024;
pub const DEFAULT_MAX_ESTIMATED_PACKETS: u64 = 4096;
pub const DEFAULT_MAX_BATCH_SIZE: usize = 256;
pub const DEFAULT_MAX_RATE_PER_SEC: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficBudget {
    pub max_targets: usize,
    pub max_ports: usize,
    pub max_estimated_packets: u64,
    pub max_batch_size: usize,
    pub max_rate_per_sec: u64,
}

impl Default for TrafficBudget {
    fn default() -> Self {
        Self {
            max_targets: DEFAULT_MAX_TARGETS,
            max_ports: DEFAULT_MAX_PORTS,
            max_estimated_packets: DEFAULT_MAX_ESTIMATED_PACKETS,
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_rate_per_sec: DEFAULT_MAX_RATE_PER_SEC,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TrafficPolicy {
    pub allow_public_targets: bool,
    pub allow_malformed: bool,
    pub allow_high_volume: bool,
    pub allow_unbounded_sends: bool,
    pub dry_run: bool,
    pub budget: TrafficBudget,
}

impl TrafficPolicy {
    pub fn new(allow_unbounded_sends: bool, dry_run: bool) -> Self {
        Self {
            allow_unbounded_sends,
            dry_run,
            ..Default::default()
        }
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn authorize(&self, plan: &TrafficPlan) -> Result<PolicyOutcome, PolicyRejection> {
        if plan.target_count == 0
            || plan.port_count == 0
            || matches!(plan.estimated_packets, Some(0))
        {
            return Err(PolicyRejection::new(
                PolicyRejectionCode::CountMustBePositive,
                "target, port, and packet counts must be greater than zero",
            ));
        }

        if plan.unbounded && !self.allow_unbounded_sends {
            return Err(PolicyRejection::new(
                PolicyRejectionCode::UnboundedSend,
                "unbounded sends require --allow-unbounded-sends",
            ));
        }

        if plan.target_scope == TargetScope::Public && !self.allow_public_targets {
            return Err(PolicyRejection::new(
                PolicyRejectionCode::PublicTarget,
                "public targets require --allow-public-targets",
            ));
        }

        if plan.malformed && !self.allow_malformed {
            return Err(PolicyRejection::new(
                PolicyRejectionCode::MalformedRequiresOptIn,
                "malformed traffic requires --allow-malformed",
            ));
        }

        if plan.exceeds_recommended_defaults() && !self.allow_high_volume {
            return Err(PolicyRejection::new(
                PolicyRejectionCode::HighVolumeRequiresOptIn,
                "high-volume traffic requires --allow-high-volume",
            ));
        }

        if plan.target_count > self.budget.max_targets {
            return Err(PolicyRejection::new(
                PolicyRejectionCode::TargetCapExceeded,
                format!(
                    "target count {} exceeds configured cap {}",
                    plan.target_count, self.budget.max_targets
                ),
            ));
        }

        if plan.port_count > self.budget.max_ports {
            return Err(PolicyRejection::new(
                PolicyRejectionCode::PortCapExceeded,
                format!(
                    "port count {} exceeds configured cap {}",
                    plan.port_count, self.budget.max_ports
                ),
            ));
        }

        if let Some(estimated) = plan.estimated_packets {
            if estimated > self.budget.max_estimated_packets {
                return Err(PolicyRejection::new(
                    PolicyRejectionCode::PacketCapExceeded,
                    format!(
                        "estimated packet count {} exceeds configured cap {}",
                        estimated, self.budget.max_estimated_packets
                    ),
                ));
            }
        }

        if plan.batch_size > self.budget.max_batch_size {
            return Err(PolicyRejection::new(
                PolicyRejectionCode::BatchCapExceeded,
                format!(
                    "batch size {} exceeds configured cap {}",
                    plan.batch_size, self.budget.max_batch_size
                ),
            ));
        }

        if let Some(rate) = plan.rate_per_sec {
            if rate > self.budget.max_rate_per_sec {
                return Err(PolicyRejection::new(
                    PolicyRejectionCode::RateCapExceeded,
                    format!(
                        "traffic rate {} packets/sec exceeds configured cap {}",
                        rate, self.budget.max_rate_per_sec
                    ),
                ));
            }
        }

        Ok(PolicyOutcome::allowed())
    }

    pub fn validate_configuration(&self) -> Result<(), PolicyRejection> {
        let default = TrafficBudget::default();
        let raises_default = self.budget.max_targets > default.max_targets
            || self.budget.max_ports > default.max_ports
            || self.budget.max_estimated_packets > default.max_estimated_packets
            || self.budget.max_batch_size > default.max_batch_size
            || self.budget.max_rate_per_sec > default.max_rate_per_sec;

        if raises_default && !self.allow_high_volume {
            return Err(PolicyRejection::new(
                PolicyRejectionCode::HighVolumeRequiresOptIn,
                "traffic cap, batch, or rate overrides above the recommended defaults require --allow-high-volume",
            ));
        }

        Ok(())
    }

    pub fn rate_delay(&self) -> Option<std::time::Duration> {
        if self.budget.max_rate_per_sec == 0 {
            return None;
        }

        let nanos = (1_000_000_000u64 / self.budget.max_rate_per_sec).max(1);
        Some(std::time::Duration::from_nanos(nanos))
    }
}

pub type TransmissionPolicy = TrafficPolicy;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficPlan {
    pub mode: TrafficMode,
    pub target_scope: TargetScope,
    pub target_count: usize,
    pub port_count: usize,
    pub estimated_packets: Option<u64>,
    pub malformed: bool,
    pub unbounded: bool,
    pub batch_size: usize,
    pub rate_per_sec: Option<u64>,
    pub required_privileges: Vec<TrafficPrivilege>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<TrafficSelection>,
}

impl TrafficPlan {
    pub fn new(mode: TrafficMode, target_scope: TargetScope) -> Self {
        Self {
            mode,
            target_scope,
            target_count: 1,
            port_count: 1,
            estimated_packets: Some(1),
            malformed: false,
            unbounded: false,
            batch_size: 1,
            rate_per_sec: None,
            required_privileges: Vec::new(),
            selection: None,
        }
    }

    pub fn from_packet_request(
        request: &PacketRequest,
        mode: TrafficMode,
        policy: &TrafficPolicy,
    ) -> Self {
        let unbounded = request.transmit.loop_forever.unwrap_or(false)
            || (request.transmit.flood.unwrap_or(false) && request.transmit.count.is_none());
        let estimated_packets = if unbounded {
            None
        } else {
            Some(request.transmit.count.unwrap_or(1))
        };

        Self {
            mode,
            target_scope: classify_request_target(request),
            target_count: 1,
            port_count: 1,
            estimated_packets,
            malformed: request_uses_malformed_options(request),
            unbounded,
            batch_size: 1,
            rate_per_sec: Some(policy.budget.max_rate_per_sec),
            required_privileges: request_privileges(request),
            selection: None,
        }
    }

    pub fn exceeds_recommended_defaults(&self) -> bool {
        self.target_count > DEFAULT_MAX_TARGETS
            || self.port_count > DEFAULT_MAX_PORTS
            || self
                .estimated_packets
                .map(|packets| packets > DEFAULT_MAX_ESTIMATED_PACKETS)
                .unwrap_or(false)
            || self.batch_size > DEFAULT_MAX_BATCH_SIZE
            || self
                .rate_per_sec
                .map(|rate| rate > DEFAULT_MAX_RATE_PER_SEC)
                .unwrap_or(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficSelection {
    pub interface: Option<TrafficSelectionValue>,
    pub source: Option<TrafficSelectionValue>,
    pub destination: Option<TrafficSelectionValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficSelectionValue {
    pub value: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficMode {
    Send,
    RuleSend,
    Scan,
    Traceroute,
    Fuzz,
}

impl fmt::Display for TrafficMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Send => "send",
            Self::RuleSend => "rule_send",
            Self::Scan => "scan",
            Self::Traceroute => "traceroute",
            Self::Fuzz => "fuzz",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetScope {
    Local,
    Private,
    Documentation,
    Public,
    Unspecified,
}

impl fmt::Display for TargetScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Local => "local",
            Self::Private => "private",
            Self::Documentation => "documentation",
            Self::Public => "public",
            Self::Unspecified => "unspecified",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficPrivilege {
    RawSocket,
    Datalink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyOutcome {
    pub status: &'static str,
}

impl PolicyOutcome {
    pub fn allowed() -> Self {
        Self { status: "allowed" }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct PolicyRejection {
    pub code: PolicyRejectionCode,
    pub message: String,
}

impl PolicyRejection {
    pub fn new(message_code: PolicyRejectionCode, message: impl Into<String>) -> Self {
        Self {
            code: message_code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRejectionCode {
    PublicTarget,
    MalformedRequiresOptIn,
    HighVolumeRequiresOptIn,
    TargetCapExceeded,
    PortCapExceeded,
    PacketCapExceeded,
    BatchCapExceeded,
    RateCapExceeded,
    UnboundedSend,
    CountMustBePositive,
}

impl fmt::Display for PolicyRejectionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::PublicTarget => "public_target",
            Self::MalformedRequiresOptIn => "malformed_requires_opt_in",
            Self::HighVolumeRequiresOptIn => "high_volume_requires_opt_in",
            Self::TargetCapExceeded => "target_cap_exceeded",
            Self::PortCapExceeded => "port_cap_exceeded",
            Self::PacketCapExceeded => "packet_cap_exceeded",
            Self::BatchCapExceeded => "batch_cap_exceeded",
            Self::RateCapExceeded => "rate_cap_exceeded",
            Self::UnboundedSend => "unbounded_send",
            Self::CountMustBePositive => "count_must_be_positive",
        };
        f.write_str(value)
    }
}

pub fn validate_unbounded_request_policy(
    request: &TransmissionRequest,
    policy: TransmissionPolicy,
) -> Result<(), PolicyRejection> {
    let packet_request = PacketRequest {
        transmit: request.clone(),
        ..Default::default()
    };
    policy
        .authorize(&TrafficPlan::from_packet_request(
            &packet_request,
            TrafficMode::Send,
            &policy,
        ))
        .map(|_| ())
}

pub fn classify_ip(addr: IpAddr) -> TargetScope {
    match addr {
        IpAddr::V4(addr) => classify_ipv4(addr),
        IpAddr::V6(addr) => classify_ipv6(addr),
    }
}

pub fn combine_target_scopes(scopes: impl IntoIterator<Item = TargetScope>) -> TargetScope {
    let mut combined = TargetScope::Unspecified;
    for scope in scopes {
        combined = match (combined, scope) {
            (TargetScope::Public, _) | (_, TargetScope::Public) => TargetScope::Public,
            (TargetScope::Private, _) | (_, TargetScope::Private) => TargetScope::Private,
            (TargetScope::Documentation, _) | (_, TargetScope::Documentation) => {
                TargetScope::Documentation
            }
            (TargetScope::Local, _) | (_, TargetScope::Local) => TargetScope::Local,
            _ => TargetScope::Unspecified,
        };
    }
    combined
}

pub fn packet_spec_target_scope(spec: &PacketSpec) -> TargetScope {
    let mut scopes = Vec::new();

    if let Some(ip) = spec.ip.as_ref().and_then(|ip| ip.destination) {
        scopes.push(classify_ip(ip));
    } else {
        if let Some(addr) = spec
            .target
            .address
            .as_ref()
            .and_then(TargetAddress::resolved_ip)
        {
            scopes.push(classify_ip(addr));
        }
    }

    for header in &spec.ipv6.exthdrs {
        if let Ipv6ExtHeader::Routing { segments, .. } = header {
            scopes.extend(segments.iter().copied().map(IpAddr::V6).map(classify_ip));
        }
    }

    combine_target_scopes(scopes)
}

pub fn packet_spec_uses_malformed_options(spec: &PacketSpec) -> bool {
    spec.ip
        .as_ref()
        .map(|ip| {
            ip.fragmentation.overlap
                || ip.fragmentation.teardrop
                || ip.fragmentation.profile.is_some()
        })
        .unwrap_or(false)
}

pub fn packet_spec_privileges(spec: &PacketSpec) -> Vec<TrafficPrivilege> {
    let requires_raw = spec.layer2.source.is_some()
        || spec.layer2.destination.is_some()
        || matches!(
            &spec.transport,
            TransportSpec::Tcp(_)
                | TransportSpec::Udp(_)
                | TransportSpec::Icmp(_)
                | TransportSpec::Icmpv6(_)
        )
        || spec.transmit.is_layer3();

    if requires_raw {
        vec![TrafficPrivilege::RawSocket]
    } else {
        Vec::new()
    }
}

fn classify_request_target(request: &PacketRequest) -> TargetScope {
    if let Some(addr) = request.destination.resolved_destination {
        return classify_ip(addr);
    }

    if let Some(raw) = request
        .destination
        .destination_ip
        .as_deref()
        .or(request.ip.destination_ip.as_deref())
    {
        return raw
            .parse::<IpAddr>()
            .map(classify_ip)
            .unwrap_or(TargetScope::Unspecified);
    }

    if let Some(raw) = request.destination.destination.as_deref() {
        return raw
            .parse::<IpAddr>()
            .map(classify_ip)
            .unwrap_or(TargetScope::Unspecified);
    }

    TargetScope::Unspecified
}

fn request_uses_malformed_options(request: &PacketRequest) -> bool {
    request.ip.fragment.overlap.unwrap_or(false)
        || request.ip.fragment.teardrop.unwrap_or(false)
        || request.ip.fragment.profile.is_some()
}

fn request_privileges(request: &PacketRequest) -> Vec<TrafficPrivilege> {
    let requires_raw = request.layer2.source_mac.is_some()
        || request.layer2.destination_mac.is_some()
        || request.layer2.ethertype.is_some()
        || request.transport.command.is_some()
        || request.transmit.force_layer3.unwrap_or(false);

    if requires_raw {
        vec![TrafficPrivilege::RawSocket]
    } else {
        Vec::new()
    }
}

fn classify_ipv4(addr: Ipv4Addr) -> TargetScope {
    let [a, b, c, _d] = addr.octets();

    if a == 127 || a == 0 || addr == Ipv4Addr::BROADCAST {
        return TargetScope::Local;
    }

    if a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) {
        return TargetScope::Private;
    }

    if a == 169 && b == 254 {
        return TargetScope::Local;
    }

    if (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
    {
        return TargetScope::Documentation;
    }

    TargetScope::Public
}

fn classify_ipv6(addr: Ipv6Addr) -> TargetScope {
    let segments = addr.segments();
    let first = segments[0];

    if addr.is_loopback() || addr.is_unspecified() {
        return TargetScope::Local;
    }

    if (first & 0xfe00) == 0xfc00 {
        return TargetScope::Private;
    }

    if (first & 0xffc0) == 0xfe80 {
        return TargetScope::Local;
    }

    if first == 0x2001 && segments[1] == 0x0db8 {
        return TargetScope::Documentation;
    }

    TargetScope::Public
}
