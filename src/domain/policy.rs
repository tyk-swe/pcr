// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::domain::request::{PacketRequest, TransmissionRequest};
use crate::domain::spec::{Ipv6ExtHeader, PacketSpec, TargetAddress, TransportSpec};

pub(crate) const DEFAULT_MAX_TARGETS: usize = 256;
pub(crate) const DEFAULT_MAX_PORTS: usize = 1024;
pub(crate) const DEFAULT_MAX_ESTIMATED_PACKETS: u64 = 4096;
pub(crate) const DEFAULT_MAX_BATCH_SIZE: usize = 256;
pub(crate) const DEFAULT_MAX_RATE_PER_SEC: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TrafficBudget {
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
pub(crate) struct TrafficPolicy {
    pub allow_public_targets: bool,
    pub allow_malformed: bool,
    pub allow_high_volume: bool,
    pub allow_unbounded_sends: bool,
    pub dry_run: bool,
    pub budget: TrafficBudget,
}

impl TrafficPolicy {
    pub(crate) fn new(allow_unbounded_sends: bool, dry_run: bool) -> Self {
        Self {
            allow_unbounded_sends,
            dry_run,
            ..Default::default()
        }
    }

    pub(crate) fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub(crate) fn authorize(&self, plan: &TrafficPlan) -> Result<PolicyOutcome, PolicyRejection> {
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

    pub(crate) fn validate_configuration(&self) -> Result<(), PolicyRejection> {
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

    pub(crate) fn rate_delay(&self) -> Option<std::time::Duration> {
        if self.budget.max_rate_per_sec == 0 {
            return None;
        }

        let nanos = (1_000_000_000u64 / self.budget.max_rate_per_sec).max(1);
        Some(std::time::Duration::from_nanos(nanos))
    }
}

pub(crate) type TransmissionPolicy = TrafficPolicy;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TrafficPlan {
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
    pub(crate) fn new(mode: TrafficMode, target_scope: TargetScope) -> Self {
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

    pub(crate) fn from_packet_request(
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

    pub(crate) fn exceeds_recommended_defaults(&self) -> bool {
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
pub(crate) struct TrafficSelection {
    pub interface: Option<TrafficSelectionValue>,
    pub source: Option<TrafficSelectionValue>,
    pub destination: Option<TrafficSelectionValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TrafficSelectionValue {
    pub value: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TrafficMode {
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
pub(crate) enum TargetScope {
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
pub(crate) enum TrafficPrivilege {
    RawSocket,
    Datalink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PolicyOutcome {
    pub status: &'static str,
}

impl PolicyOutcome {
    pub(crate) fn allowed() -> Self {
        Self { status: "allowed" }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{code}: {message}")]
pub(crate) struct PolicyRejection {
    pub code: PolicyRejectionCode,
    pub message: String,
}

impl PolicyRejection {
    pub(crate) fn new(message_code: PolicyRejectionCode, message: impl Into<String>) -> Self {
        Self {
            code: message_code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyRejectionCode {
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

pub(crate) fn validate_unbounded_request_policy(
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

pub(crate) fn classify_ip(addr: IpAddr) -> TargetScope {
    match addr {
        IpAddr::V4(addr) => classify_ipv4(addr),
        IpAddr::V6(addr) => classify_ipv6(addr),
    }
}

pub(crate) fn combine_target_scopes(scopes: impl IntoIterator<Item = TargetScope>) -> TargetScope {
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

pub(crate) fn packet_spec_target_scope(spec: &PacketSpec) -> TargetScope {
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

pub(crate) fn packet_spec_uses_malformed_options(spec: &PacketSpec) -> bool {
    spec.ip
        .as_ref()
        .map(|ip| {
            ip.fragmentation.overlap
                || ip.fragmentation.teardrop
                || ip.fragmentation.profile.is_some()
        })
        .unwrap_or(false)
}

pub(crate) fn packet_spec_privileges(spec: &PacketSpec) -> Vec<TrafficPrivilege> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::request::TransmissionRequest;
    use crate::domain::request::{
        FragmentProfile, FragmentRequest, IpRequest, Layer2Request, PacketRequest,
    };

    fn plan_with(scope: TargetScope) -> TrafficPlan {
        TrafficPlan::new(TrafficMode::Send, scope)
    }

    fn rejection_code(plan: TrafficPlan) -> PolicyRejectionCode {
        TrafficPolicy::default().authorize(&plan).unwrap_err().code
    }

    #[test]
    fn traffic_policy_allows_default_private_plan() {
        let outcome = TrafficPolicy::default()
            .authorize(&plan_with(TargetScope::Private))
            .unwrap();

        assert_eq!(outcome.status, "allowed");
    }

    #[test]
    fn traffic_policy_rejects_zero_counts_first() {
        let mut plan = plan_with(TargetScope::Private);
        plan.target_count = 0;

        assert_eq!(
            rejection_code(plan),
            PolicyRejectionCode::CountMustBePositive
        );
    }

    #[test]
    fn traffic_policy_rejects_unbounded_without_opt_in() {
        let mut plan = plan_with(TargetScope::Private);
        plan.unbounded = true;
        plan.estimated_packets = None;

        assert_eq!(rejection_code(plan), PolicyRejectionCode::UnboundedSend);
    }

    #[test]
    fn traffic_policy_rejects_public_target_without_opt_in() {
        assert_eq!(
            rejection_code(plan_with(TargetScope::Public)),
            PolicyRejectionCode::PublicTarget
        );
    }

    #[test]
    fn traffic_policy_rejects_malformed_without_opt_in() {
        let mut plan = plan_with(TargetScope::Private);
        plan.malformed = true;

        assert_eq!(
            rejection_code(plan),
            PolicyRejectionCode::MalformedRequiresOptIn
        );
    }

    #[test]
    fn traffic_policy_rejects_high_volume_and_specific_caps() {
        let mut high_volume = plan_with(TargetScope::Private);
        high_volume.port_count = DEFAULT_MAX_PORTS + 1;
        assert_eq!(
            rejection_code(high_volume.clone()),
            PolicyRejectionCode::HighVolumeRequiresOptIn
        );

        let policy = TrafficPolicy {
            allow_high_volume: true,
            budget: TrafficBudget {
                max_ports: DEFAULT_MAX_PORTS,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            policy.authorize(&high_volume).unwrap_err().code,
            PolicyRejectionCode::PortCapExceeded
        );
    }

    #[test]
    fn traffic_policy_rejects_each_configured_cap() {
        let policy = TrafficPolicy {
            allow_high_volume: true,
            budget: TrafficBudget {
                max_targets: 1,
                max_ports: 1,
                max_estimated_packets: 1,
                max_batch_size: 1,
                max_rate_per_sec: 1,
            },
            ..Default::default()
        };

        let mut target_plan = plan_with(TargetScope::Private);
        target_plan.target_count = 2;
        let mut packet_plan = plan_with(TargetScope::Private);
        packet_plan.estimated_packets = Some(2);
        let mut batch_plan = plan_with(TargetScope::Private);
        batch_plan.batch_size = 2;
        let mut rate_plan = plan_with(TargetScope::Private);
        rate_plan.rate_per_sec = Some(2);

        assert_eq!(
            policy.authorize(&target_plan).unwrap_err().code,
            PolicyRejectionCode::TargetCapExceeded
        );
        assert_eq!(
            policy.authorize(&packet_plan).unwrap_err().code,
            PolicyRejectionCode::PacketCapExceeded
        );
        assert_eq!(
            policy.authorize(&batch_plan).unwrap_err().code,
            PolicyRejectionCode::BatchCapExceeded
        );
        assert_eq!(
            policy.authorize(&rate_plan).unwrap_err().code,
            PolicyRejectionCode::RateCapExceeded
        );
    }

    #[test]
    fn traffic_policy_validate_configuration_requires_high_volume_for_raised_caps() {
        let policy = TrafficPolicy {
            budget: TrafficBudget {
                max_targets: DEFAULT_MAX_TARGETS + 1,
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(
            policy.validate_configuration().unwrap_err().code,
            PolicyRejectionCode::HighVolumeRequiresOptIn
        );
        assert!(TrafficPolicy {
            allow_high_volume: true,
            ..policy
        }
        .validate_configuration()
        .is_ok());
    }

    #[test]
    fn traffic_policy_rate_delay_handles_zero_and_nonzero_rates() {
        assert_eq!(
            TrafficPolicy {
                budget: TrafficBudget {
                    max_rate_per_sec: 2,
                    ..Default::default()
                },
                ..Default::default()
            }
            .rate_delay(),
            Some(std::time::Duration::from_millis(500))
        );
        assert_eq!(
            TrafficPolicy {
                budget: TrafficBudget {
                    max_rate_per_sec: 0,
                    ..Default::default()
                },
                ..Default::default()
            }
            .rate_delay(),
            None
        );
    }

    #[test]
    fn classify_ip_covers_ipv4_scopes() {
        assert_eq!(
            classify_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            TargetScope::Local
        );
        assert_eq!(
            classify_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            TargetScope::Private
        );
        assert_eq!(
            classify_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            TargetScope::Documentation
        );
        assert_eq!(
            classify_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            TargetScope::Public
        );
    }

    #[test]
    fn classify_ip_covers_ipv6_scopes() {
        assert_eq!(
            classify_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            TargetScope::Local
        );
        assert_eq!(
            classify_ip(IpAddr::V6("fd00::1".parse().unwrap())),
            TargetScope::Private
        );
        assert_eq!(
            classify_ip(IpAddr::V6("2001:db8::1".parse().unwrap())),
            TargetScope::Documentation
        );
        assert_eq!(
            classify_ip(IpAddr::V6("2606:4700:4700::1111".parse().unwrap())),
            TargetScope::Public
        );
    }

    #[test]
    fn combine_target_scopes_returns_highest_risk_scope() {
        assert_eq!(
            combine_target_scopes([TargetScope::Local, TargetScope::Documentation]),
            TargetScope::Documentation
        );
        assert_eq!(
            combine_target_scopes([TargetScope::Private, TargetScope::Public]),
            TargetScope::Public
        );
    }

    #[test]
    fn traffic_plan_from_packet_request_detects_unbounded_malformed_and_privileges() {
        let request = PacketRequest {
            destination: crate::domain::request::DestinationRequest {
                destination_ip: Some("192.168.1.10".to_string()),
                ..Default::default()
            },
            layer2: Layer2Request {
                source_mac: Some("00:11:22:33:44:55".to_string()),
                ..Default::default()
            },
            ip: IpRequest {
                fragment: FragmentRequest {
                    profile: Some(FragmentProfile::Overlap),
                    ..Default::default()
                },
                ..Default::default()
            },
            transmit: TransmissionRequest {
                flood: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let plan = TrafficPlan::from_packet_request(
            &request,
            TrafficMode::Send,
            &TrafficPolicy::default(),
        );

        assert_eq!(plan.target_scope, TargetScope::Private);
        assert!(plan.malformed);
        assert!(plan.unbounded);
        assert_eq!(plan.estimated_packets, None);
        assert_eq!(plan.required_privileges, vec![TrafficPrivilege::RawSocket]);
    }

    #[test]
    fn packet_spec_helpers_classify_routing_segments_and_malformed_options() {
        let mut spec = PacketSpec::from_request(&PacketRequest {
            ip: IpRequest {
                destination_ip: Some("2001:db8::1".to_string()),
                fragment: FragmentRequest {
                    teardrop: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        spec.ipv6.exthdrs = vec![Ipv6ExtHeader::Routing {
            routing_type: 0,
            segments: vec!["2001:db8::1".parse().unwrap(), "8::1".parse().unwrap()],
            data: None,
        }];

        assert_eq!(packet_spec_target_scope(&spec), TargetScope::Public);
        assert!(packet_spec_uses_malformed_options(&spec));
    }

    #[test]
    fn packet_spec_privileges_detect_raw_socket_requirements() {
        let no_raw = PacketSpec::default();
        let raw = PacketSpec {
            transport: TransportSpec::Icmp(crate::domain::spec::IcmpSpec::default()),
            ..Default::default()
        };

        assert!(packet_spec_privileges(&no_raw).is_empty());
        assert_eq!(
            packet_spec_privileges(&raw),
            vec![TrafficPrivilege::RawSocket]
        );
    }

    #[test]
    fn validate_unbounded_request_policy_reuses_packet_policy() {
        let request = TransmissionRequest {
            loop_forever: Some(true),
            ..Default::default()
        };

        assert_eq!(
            validate_unbounded_request_policy(&request, TrafficPolicy::default())
                .unwrap_err()
                .code,
            PolicyRejectionCode::UnboundedSend
        );
        assert!(
            validate_unbounded_request_policy(&request, TrafficPolicy::new(true, false)).is_ok()
        );
    }
}
