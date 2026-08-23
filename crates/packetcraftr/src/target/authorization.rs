// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::net::IpAddr;

use super::{Family, Resolver, Target};
use crate::policy::Policy;
use packetcraftr_core::budget::Deadline;

pub(crate) struct SelectedTargets {
    pub(crate) declared: String,
    pub(crate) addresses: Vec<IpAddr>,
}

/// Resolves, authorizes, filters, and de-duplicates a target while checking
/// the same absolute deadline on both sides of every policy boundary.
pub(crate) fn resolve_selected(
    policy: &Policy,
    resolver: &impl Resolver,
    target: &Target,
    family: Family,
    deadline: &Deadline,
) -> Result<SelectedTargets, crate::Error> {
    deadline.check()?;
    let resolved = policy.resolve_target(target, resolver);
    deadline.check()?;
    let resolved = resolved?;

    let declared = resolved.declared.to_string();
    let mut addresses = Vec::with_capacity(resolved.addresses.len());
    let mut seen = HashSet::with_capacity(resolved.addresses.len());
    for address in resolved.addresses {
        deadline.check()?;
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
pub(crate) fn approve_operation(
    policy: &Policy,
    packets: u64,
    maximum_wire_bytes: u64,
    deadline: &Deadline,
) -> Result<(), crate::Error> {
    deadline.check()?;
    let approval = policy.authorize_operation(packets, maximum_wire_bytes);
    deadline.check()?;
    approval?;
    Ok(())
}
