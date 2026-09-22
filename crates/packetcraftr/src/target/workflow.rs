// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use super::{Family, Target};
use packetcraftr_core::budget::{Deadline, Interrupted};
use packetcraftr_core::error::BoundaryError;

use crate::clock::check_deadline;
use crate::policy::{Authorizer, Operation, WireBudget};

/// How a workflow names the failures each admission gate can raise.
pub(crate) trait GateErrors {
    type Error;
    /// The elapsed-time budget was spent at a policy boundary.
    fn duration_limit(&self, actual: Duration, limit: Duration) -> Self::Error;
    /// The authorizer refused the declared target or the operation budget.
    fn authorization(&self, source: BoundaryError) -> Self::Error;
    /// A cooperative `Deadline::enforce` boundary refused: the operation was
    /// cancelled or its budget was spent.
    fn interrupted(&self, source: Interrupted) -> Self::Error;
    /// Resolution produced no address the requested family accepts.
    fn family(&self, family: Family) -> Self::Error;
}

/// The admitted address set a resolution produced: the declared target
/// string plus the family-filtered, deduplicated addresses.
#[derive(Debug)]
pub(crate) struct SelectedTargets {
    pub(crate) declared: String,
    pub(crate) addresses: Vec<IpAddr>,
}

/// Resolves, authorizes, filters, and de-duplicates a target while checking
/// the same absolute deadline on both sides of every policy boundary.
pub(crate) fn resolve_selected<A, G>(
    authorizer: &mut A,
    target: &Target,
    family: Family,
    deadline: &Deadline,
    gates: &G,
) -> Result<SelectedTargets, G::Error>
where
    A: Authorizer,
    G: GateErrors,
{
    let duration_error = |actual, limit| gates.duration_limit(actual, limit);
    check_deadline(deadline, duration_error)?;
    let resolved = authorizer.resolve_and_authorize(target);
    check_deadline(deadline, duration_error)?;
    let resolved = resolved.map_err(|source| gates.authorization(source))?;

    let declared = resolved.declared.to_string();
    let mut addresses = Vec::with_capacity(resolved.addresses.len());
    let mut seen = HashSet::with_capacity(resolved.addresses.len());
    for address in resolved.addresses {
        check_deadline(deadline, duration_error)?;
        if family.accepts(address) && seen.insert(address) {
            addresses.push(address);
        }
    }
    Ok(SelectedTargets {
        declared,
        addresses,
    })
}

/// Authorizes the complete operation before live side effects, checking the
/// absolute deadline before and after authorization.
pub(crate) fn approve_operation<A, G>(
    authorizer: &mut A,
    operation: Operation<'_>,
    deadline: &Deadline,
    gates: &G,
) -> Result<(), G::Error>
where
    A: Authorizer,
    G: GateErrors,
{
    let duration_error = |actual, limit| gates.duration_limit(actual, limit);
    check_deadline(deadline, duration_error)?;
    let approval = authorizer.authorize_operation(operation);
    check_deadline(deadline, duration_error)?;
    approval.map_err(|source| gates.authorization(source))
}

pub(crate) const fn budgeted(packets: u64, maximum_wire_bytes: u64) -> Operation<'static> {
    Operation::Budgeted(WireBudget::new(packets, maximum_wire_bytes))
}
