// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use crate::domain::policy::TransmissionPolicy;
use crate::domain::spec::{LoggingSpec, TransmissionSpec};

#[derive(Debug, Clone)]
pub(crate) struct TransmissionPlan {
    pub frames: Vec<Vec<u8>>,
    pub link_type: TransmissionLinkType,
    pub transmit: TransmissionSpec,
    pub destination: TransmissionTarget,
    pub interface_name: String,
    pub selection: TransmissionSelection,
    pub protocol: TransmissionProtocol,
    pub summary: TransmissionSummary,
    pub logging: LoggingSpec,
    pub mode: PlanningMode,
    pub policy: TransmissionPolicy,
}

#[derive(Debug, Clone)]
pub(crate) enum TransmissionLinkType {
    Ethernet,
    Ipv4,
    Ipv6,
}

impl TransmissionLinkType {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            TransmissionLinkType::Ethernet => "ethernet",
            TransmissionLinkType::Ipv4 => "ipv4",
            TransmissionLinkType::Ipv6 => "ipv6",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum TransmissionTarget {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransmissionProtocol(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanningMode {
    Live,
    DryRun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransmissionSelection {
    pub selected_interface: String,
    pub interface_reason: InterfaceSelectionReason,
    pub source_ip: IpAddr,
    pub source_reason: SourceSelectionReason,
    pub destination_ip: IpAddr,
    pub destination_reason: DestinationSelectionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InterfaceSelectionReason {
    ExplicitInterface,
    RouteTable,
    Heuristic,
}

impl InterfaceSelectionReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitInterface => "explicit_interface",
            Self::RouteTable => "route_table",
            Self::Heuristic => "heuristic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceSelectionReason {
    ExplicitSourceIp,
    InterfaceAddress,
    Ipv6ScopeMatch,
}

impl SourceSelectionReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitSourceIp => "explicit_source_ip",
            Self::InterfaceAddress => "interface_address",
            Self::Ipv6ScopeMatch => "ipv6_scope_match",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DestinationSelectionReason {
    HostnameResolution,
    TargetLiteral,
}

impl DestinationSelectionReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::HostnameResolution => "hostname_resolution",
            Self::TargetLiteral => "target_literal",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TransmissionSummary {
    pub payload_len: usize,
    pub largest_frame_len: usize,
    pub frame_count: usize,
    pub transport: &'static str,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendControlError {
    #[error("--flood without --count requires explicit unbounded-send opt-in")]
    FloodRequiresCount,
    #[error("--loop requires explicit unbounded-send opt-in")]
    LoopRequiresAllowUnbounded,
    #[error("--count must be greater than zero")]
    CountMustBePositive,
    #[error(
        "emitted unit count overflows u64: attempts={attempts} units_per_attempt={units_per_attempt}"
    )]
    EmittedUnitsOverflow {
        attempts: u64,
        units_per_attempt: u64,
    },
}

pub(crate) fn validate_transmission_policy(
    spec: &TransmissionSpec,
    policy: TransmissionPolicy,
) -> Result<(), SendControlError> {
    if matches!(spec.count, Some(0)) {
        return Err(SendControlError::CountMustBePositive);
    }

    if spec.loop_send && !policy.allow_unbounded_sends {
        return Err(SendControlError::LoopRequiresAllowUnbounded);
    }

    if spec.flood && spec.count.is_none() && !policy.allow_unbounded_sends {
        return Err(SendControlError::FloodRequiresCount);
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SendMode {
    Finite(u64),
    Infinite,
}

pub(crate) fn determine_send_mode(
    spec: &TransmissionSpec,
    policy: TransmissionPolicy,
) -> Result<SendMode, SendControlError> {
    validate_transmission_policy(spec, policy)?;

    if spec.loop_send {
        Ok(SendMode::Infinite)
    } else if let Some(count) = spec.count {
        Ok(SendMode::Finite(count))
    } else if spec.flood {
        Ok(SendMode::Infinite)
    } else {
        Ok(SendMode::Finite(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EmissionAccounting {
    pub attempts: Option<u64>,
    pub units_per_attempt: u64,
    pub total_emitted_units: Option<u64>,
}

pub(crate) fn emission_accounting(
    spec: &TransmissionSpec,
    policy: TransmissionPolicy,
    units_per_attempt: u64,
) -> Result<EmissionAccounting, SendControlError> {
    let attempts = match determine_send_mode(spec, policy)? {
        SendMode::Finite(count) => Some(count),
        SendMode::Infinite => None,
    };
    let total_emitted_units = attempts
        .map(|count| {
            count
                .checked_mul(units_per_attempt)
                .ok_or(SendControlError::EmittedUnitsOverflow {
                    attempts: count,
                    units_per_attempt,
                })
        })
        .transpose()?;

    Ok(EmissionAccounting {
        attempts,
        units_per_attempt,
        total_emitted_units,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> TransmissionSpec {
        TransmissionSpec::default()
    }

    #[test]
    fn rejects_unbounded_sends_without_policy_opt_in() {
        let mut loop_spec = spec();
        loop_spec.loop_send = true;
        assert_eq!(
            validate_transmission_policy(&loop_spec, TransmissionPolicy::default()),
            Err(SendControlError::LoopRequiresAllowUnbounded)
        );

        let mut flood_spec = spec();
        flood_spec.flood = true;
        assert_eq!(
            validate_transmission_policy(&flood_spec, TransmissionPolicy::default()),
            Err(SendControlError::FloodRequiresCount)
        );
    }

    #[test]
    fn allows_unbounded_sends_with_policy_opt_in() {
        let policy = TransmissionPolicy {
            allow_unbounded_sends: true,
            ..Default::default()
        };

        let mut loop_spec = spec();
        loop_spec.loop_send = true;
        assert!(validate_transmission_policy(&loop_spec, policy).is_ok());

        let accounting = emission_accounting(&loop_spec, policy, 3).unwrap();
        assert_eq!(accounting.attempts, None);
        assert_eq!(accounting.total_emitted_units, None);
    }

    #[test]
    fn accounts_finite_emissions_and_overflow() {
        let mut finite = spec();
        finite.count = Some(4);
        let accounting = emission_accounting(&finite, TransmissionPolicy::default(), 3).unwrap();
        assert_eq!(accounting.attempts, Some(4));
        assert_eq!(accounting.units_per_attempt, 3);
        assert_eq!(accounting.total_emitted_units, Some(12));

        finite.count = Some(u64::MAX);
        assert_eq!(
            emission_accounting(&finite, TransmissionPolicy::default(), 2),
            Err(SendControlError::EmittedUnitsOverflow {
                attempts: u64::MAX,
                units_per_attempt: 2
            })
        );
    }
}
