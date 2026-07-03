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
    fn transmission_link_type_strings_are_stable() {
        assert_eq!(TransmissionLinkType::Ethernet.as_str(), "ethernet");
        assert_eq!(TransmissionLinkType::Ipv4.as_str(), "ipv4");
        assert_eq!(TransmissionLinkType::Ipv6.as_str(), "ipv6");
    }

    #[test]
    fn interface_selection_reason_strings_are_stable() {
        assert_eq!(
            InterfaceSelectionReason::ExplicitInterface.as_str(),
            "explicit_interface"
        );
        assert_eq!(InterfaceSelectionReason::RouteTable.as_str(), "route_table");
        assert_eq!(InterfaceSelectionReason::Heuristic.as_str(), "heuristic");
    }

    #[test]
    fn source_selection_reason_strings_are_stable() {
        assert_eq!(
            SourceSelectionReason::ExplicitSourceIp.as_str(),
            "explicit_source_ip"
        );
        assert_eq!(
            SourceSelectionReason::InterfaceAddress.as_str(),
            "interface_address"
        );
        assert_eq!(
            SourceSelectionReason::Ipv6ScopeMatch.as_str(),
            "ipv6_scope_match"
        );
    }

    #[test]
    fn destination_selection_reason_strings_are_stable() {
        assert_eq!(
            DestinationSelectionReason::HostnameResolution.as_str(),
            "hostname_resolution"
        );
        assert_eq!(
            DestinationSelectionReason::TargetLiteral.as_str(),
            "target_literal"
        );
    }

    #[test]
    fn send_control_errors_display_actionable_cli_context() {
        assert_eq!(
            SendControlError::FloodRequiresCount.to_string(),
            "--flood without --count requires explicit unbounded-send opt-in"
        );
        assert_eq!(
            SendControlError::LoopRequiresAllowUnbounded.to_string(),
            "--loop requires explicit unbounded-send opt-in"
        );
        assert_eq!(
            SendControlError::CountMustBePositive.to_string(),
            "--count must be greater than zero"
        );
    }

    #[test]
    fn validate_transmission_policy_rejects_zero_count() {
        let err = validate_transmission_policy(
            &TransmissionSpec {
                count: Some(0),
                ..spec()
            },
            TransmissionPolicy::default(),
        )
        .unwrap_err();

        assert_eq!(err, SendControlError::CountMustBePositive);
    }

    #[test]
    fn validate_transmission_policy_rejects_unbounded_modes_without_opt_in() {
        let loop_err = validate_transmission_policy(
            &TransmissionSpec {
                loop_send: true,
                ..spec()
            },
            TransmissionPolicy::default(),
        )
        .unwrap_err();
        let flood_err = validate_transmission_policy(
            &TransmissionSpec {
                flood: true,
                ..spec()
            },
            TransmissionPolicy::default(),
        )
        .unwrap_err();

        assert_eq!(loop_err, SendControlError::LoopRequiresAllowUnbounded);
        assert_eq!(flood_err, SendControlError::FloodRequiresCount);
    }

    #[test]
    fn determine_send_mode_defaults_to_single_attempt() {
        let mode = determine_send_mode(&spec(), TransmissionPolicy::default()).unwrap();

        assert!(matches!(mode, SendMode::Finite(1)));
    }

    #[test]
    fn determine_send_mode_uses_count_and_infinite_modes() {
        let finite = determine_send_mode(
            &TransmissionSpec {
                count: Some(7),
                ..spec()
            },
            TransmissionPolicy::default(),
        )
        .unwrap();
        let infinite = determine_send_mode(
            &TransmissionSpec {
                loop_send: true,
                ..spec()
            },
            TransmissionPolicy {
                allow_unbounded_sends: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(matches!(finite, SendMode::Finite(7)));
        assert!(matches!(infinite, SendMode::Infinite));
    }

    #[test]
    fn emission_accounting_calculates_total_units() {
        let accounting = emission_accounting(
            &TransmissionSpec {
                count: Some(3),
                ..spec()
            },
            TransmissionPolicy::default(),
            4,
        )
        .unwrap();

        assert_eq!(
            accounting,
            EmissionAccounting {
                attempts: Some(3),
                units_per_attempt: 4,
                total_emitted_units: Some(12)
            }
        );
    }

    #[test]
    fn emission_accounting_represents_unbounded_total_as_none() {
        let accounting = emission_accounting(
            &TransmissionSpec {
                flood: true,
                ..spec()
            },
            TransmissionPolicy {
                allow_unbounded_sends: true,
                ..Default::default()
            },
            4,
        )
        .unwrap();

        assert_eq!(accounting.attempts, None);
        assert_eq!(accounting.total_emitted_units, None);
    }

    #[test]
    fn emission_accounting_rejects_total_overflow() {
        let err = emission_accounting(
            &TransmissionSpec {
                count: Some(u64::MAX),
                ..spec()
            },
            TransmissionPolicy::default(),
            2,
        )
        .unwrap_err();

        assert_eq!(
            err,
            SendControlError::EmittedUnitsOverflow {
                attempts: u64::MAX,
                units_per_attempt: 2
            }
        );
    }
}
