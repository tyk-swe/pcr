// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::net::IpAddr;

use super::{Family, ResolveTarget, Target};
use packetcraftr_core::budget::Deadline;

use crate::execution::Errors;
use crate::policy::{Authorizer, Operation, WireLimits};

#[derive(Debug)]
pub(crate) struct SelectedTargets {
    pub(crate) declared: String,
    pub(crate) addresses: Vec<IpAddr>,
}

pub(crate) fn resolve_selected<A, G>(
    authorizer: &mut A,
    target: &Target,
    family: Family,
    deadline: &Deadline,
    gates: &G,
) -> Result<SelectedTargets, G::Error>
where
    A: ResolveTarget,
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

fn check_deadline<G: Errors>(deadline: &Deadline, gates: &G) -> Result<(), G::Error> {
    deadline
        .check()
        .map_err(|source| gates.duration_limit(G::Step::default(), source))
}

pub(crate) const fn wire_limits(packets: u64, maximum_wire_bytes: u64) -> Operation<'static> {
    Operation::Wire(WireLimits::new(packets, maximum_wire_bytes))
}
