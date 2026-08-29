// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use super::{Family, Target};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use crate::authorization::{Authorizer, Operation, WireBudget};
use crate::clock::check_deadline;

pub(crate) struct SelectedTargets {
    pub(crate) declared: String,
    pub(crate) addresses: Vec<IpAddr>,
}

/// Resolves, authorizes, filters, and de-duplicates a target while checking
/// the same absolute deadline on both sides of every policy boundary.
pub(crate) fn resolve_selected<A, E>(
    authorizer: &mut A,
    target: &Target,
    family: Family,
    deadline: &Deadline,
    mut duration_error: impl FnMut(Duration, Duration) -> E,
) -> Result<SelectedTargets, E>
where
    A: Authorizer,
    E: From<BoundaryError>,
{
    check_deadline(deadline, &mut duration_error)?;
    let resolved = authorizer.resolve_and_authorize(target);
    check_deadline(deadline, &mut duration_error)?;
    let resolved = resolved.map_err(E::from)?;

    let declared = resolved.declared.to_string();
    let mut addresses = Vec::with_capacity(resolved.addresses.len());
    let mut seen = HashSet::with_capacity(resolved.addresses.len());
    for address in resolved.addresses {
        check_deadline(deadline, &mut duration_error)?;
        if family.accepts(address) && seen.insert(address) {
            addresses.push(address);
        }
    }
    Ok(SelectedTargets {
        declared,
        addresses,
    })
}

/// Obtains complete packet and byte approval before batch construction or
/// execution can produce live side effects.
pub(crate) fn approve_operation<A, E>(
    authorizer: &mut A,
    packets: u64,
    maximum_wire_bytes: u64,
    deadline: &Deadline,
    mut duration_error: impl FnMut(Duration, Duration) -> E,
) -> Result<(), E>
where
    A: Authorizer,
    E: From<BoundaryError>,
{
    check_deadline(deadline, &mut duration_error)?;
    let approval = authorizer.authorize_operation(Operation::Budgeted(WireBudget::new(
        packets,
        maximum_wire_bytes,
    )));
    check_deadline(deadline, &mut duration_error)?;
    approval.map_err(E::from)
}
