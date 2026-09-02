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

/// How a workflow names the two failures every policy gate can raise.
pub(crate) trait GateErrors {
    type Error;
    fn duration_limit(&self, actual: Duration, limit: Duration) -> Self::Error;
    fn authorization(&self, source: BoundaryError) -> Self::Error;
}

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

/// Obtains complete operation approval before batch construction or execution
/// can produce live side effects, checking the same absolute deadline on both
/// sides of the authorization boundary.
///
/// Every packet-oriented workflow states its own shape here; the bracket is
/// shared so no caller has to open-code it.
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

/// The packet-and-byte budget shape scan and traceroute state.
pub(crate) const fn budgeted(packets: u64, maximum_wire_bytes: u64) -> Operation<'static> {
    Operation::Budgeted(WireBudget::new(packets, maximum_wire_bytes))
}
