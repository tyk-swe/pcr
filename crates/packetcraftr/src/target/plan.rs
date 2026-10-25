// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Target planning: a passive preview of the addresses a selection admits.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::budget::Cancelled;
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Coordinate, Kind};

use super::{Family, SelectedAddress, Selection, SelectionError, Specification, Target};
use crate::Client;
use crate::client::admission::{DeclaredTargets, FamilyGate, admit_selection, wire_limits};
use crate::clock::Clock;
use crate::providers::TargetProviders;

#[derive(Clone, Debug, Serialize)]
pub struct SelectedAddressRecord {
    #[serde(flatten)]
    pub selected: SelectedAddress,
    pub declarations: Vec<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub declared: String,
    pub targets: Vec<SelectedAddressRecord>,
    pub resolution_performed: bool,
    pub duplicates: Vec<u32>,
}

impl Report {
    pub fn resolved_addresses(&self) -> Vec<IpAddr> {
        self.targets
            .iter()
            .map(|target| target.selected.address)
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub selection: Selection,
    pub family: Family,
    pub max_targets: usize,
    pub max_duration: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    #[error("target selection failed")]
    TargetSelection(#[from] SelectionError),
    #[error("invalid target-plan limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("target plan authorization failed")]
    Authorization(#[source] BoundaryError),
    #[error("resolved targets have no {family} address selected for this plan")]
    Family { family: &'static str },
    #[error("target plan duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
}

packetcraftr_core::deadline_error_conversions!(Error);

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(source) => source.classification(),
            Self::TargetSelection(source) => source.classification(),
            Self::Authorization(source) => source.classification(),
            Self::InvalidLimit { .. } => Classification::new(
                "cli.scan_limit",
                Kind::Usage,
                Some("use finite non-zero target, duration, and budget limits"),
            ),
            Self::Family { .. } => Classification::new(
                "packet.target_address_family",
                Kind::Packet,
                Some("select an address family returned by the authorized target resolution"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.scan_duration_limit",
                Kind::Policy,
                Some("reduce declarations or deliberately raise the finite duration limit"),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization(source) => source.as_causes(),
            _ => packetcraftr_core::error::source_chain(self),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Authorization(source) => source.context(),
            _ => None,
        }
    }
}

fn selection_error(step: u64, failure: crate::error::Failure) -> Error {
    match failure {
        crate::error::Failure::InvalidLimit {
            field,
            value,
            reason,
        } => Error::InvalidLimit {
            field,
            value,
            reason,
        },
        crate::error::Failure::Authorization(source) => Error::Authorization(source),
        crate::error::Failure::DurationLimit(source) => {
            let _step = step;

            source.into()
        }
        crate::error::Failure::Interrupted(source) => {
            let _step = step;

            source.into()
        }
        crate::error::Failure::Clock(_source) => {
            let _step = step;

            BoundaryError::internal_execution(
                "target planning never waits on a clock",
                "internal.target_plan",
                "report the unexpected selection path",
            )
            .into()
        }
        crate::error::Failure::Execution(source) => {
            let _step = step;

            Error::Authorization(source)
        }
        crate::error::Failure::InvalidEvidence(_source) => {
            let _step = step;

            BoundaryError::internal_execution(
                "target planning produces no evidence",
                "internal.target_plan",
                "report the unexpected selection path",
            )
            .into()
        }
        crate::error::Failure::StatsOverflow(_source) => {
            let _step = step;

            BoundaryError::internal_execution(
                "target planning accumulates no statistics",
                "internal.target_plan",
                "report the unexpected selection path",
            )
            .into()
        }
    }
}

impl From<BoundaryError> for Error {
    fn from(source: BoundaryError) -> Self {
        Self::Authorization(source)
    }
}

impl<P: TargetProviders, K: Clock> Client<P, K> {
    pub fn plan_targets(&self, request: Request) -> Result<Report, Error> {
        request.selection.validate().map_err(Error::from)?;
        if !(1..=super::selection::MAX_CANDIDATES).contains(&request.max_targets) {
            return Err(Error::InvalidLimit {
                field: "max_targets",
                value: request.max_targets as u64,
                reason: format!("must be in 1..={}", super::selection::MAX_CANDIDATES),
            });
        }
        if request.max_duration.is_zero()
            || request.max_duration > packetcraftr_netio::deadline::MAX_WAIT
        {
            return Err(Error::InvalidLimit {
                field: "max_duration",
                value: u64::try_from(request.max_duration.as_millis()).unwrap_or(u64::MAX),
                reason: format!(
                    "must be non-zero and at most {:?} (value in milliseconds)",
                    packetcraftr_netio::deadline::MAX_WAIT
                ),
            });
        }
        let deadline = self.deadline(request.max_duration);
        let mut admission = self.admission();
        let (selected, ()) = admit_selection(
            &mut admission,
            &deadline,
            selection_error,
            DeclaredTargets {
                selection: &request.selection,
                family: FamilyGate::new(request.family, |family| Error::Family {
                    family: family.label(),
                }),
                max_targets: request.max_targets,
                resolved: None,
            },
            Error::TargetSelection,
            |_| Ok(()),
            |_| Ok(wire_limits(0, 0)),
        )?;
        let resolution_performed = declares_hostname(&request.selection);
        Ok(Report {
            declared: selected.declared,
            targets: selected
                .targets
                .into_iter()
                .zip(selected.declarations)
                .map(|(selected, declarations)| SelectedAddressRecord {
                    selected,
                    declarations,
                })
                .collect(),
            resolution_performed,
            duplicates: selected.duplicates,
        })
    }
}

fn declares_hostname(selection: &Selection) -> bool {
    let mut seen = HashSet::new();
    selection
        .include
        .iter()
        .filter(|specification| seen.insert(*specification))
        .any(|specification| matches!(specification, Specification::Target(Target::Hostname(_))))
}
