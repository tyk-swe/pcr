// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::net::IpAddr;

use super::{Family, Target};
use packetcraftr_core::budget::Deadline;

use crate::execution::Errors;
use crate::policy::{Authorizer, Operation, WireLimits};

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
    G: Errors,
{
    let check = || check_deadline(deadline, gates);
    check()?;
    let resolved = authorizer.resolve_and_authorize(target);
    check()?;
    let resolved = resolved.map_err(|source| gates.authorization(source))?;

    let declared = resolved.declared.to_string();
    let mut addresses = Vec::with_capacity(resolved.addresses.len());
    let mut seen = HashSet::with_capacity(resolved.addresses.len());
    for address in resolved.addresses {
        check()?;
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
    G: Errors,
{
    check_deadline(deadline, gates)?;
    let approval = authorizer.authorize_operation(operation);
    check_deadline(deadline, gates)?;
    approval.map_err(|source| gates.authorization(source))
}

/// The elapsed-time check on each side of a policy boundary, reported for the
/// operation as a whole.
fn check_deadline<G: Errors>(deadline: &Deadline, gates: &G) -> Result<(), G::Error> {
    deadline
        .check()
        .map_err(|source| gates.duration_limit(G::Step::default(), source))
}

pub(crate) const fn wire_limits(packets: u64, maximum_wire_bytes: u64) -> Operation<'static> {
    Operation::Wire(WireLimits::new(packets, maximum_wire_bytes))
}
