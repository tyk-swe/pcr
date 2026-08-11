// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use super::{Authorized, Family, Target};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use crate::clock::check_deadline;

/// Policy and resolution seam shared by scan, DNS, and traceroute.
pub trait Authorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError>;

    fn authorize_operation(
        &mut self,
        packets: u64,
        maximum_wire_bytes: u64,
    ) -> Result<(), BoundaryError>;
}

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
    let approval = authorizer.authorize_operation(packets, maximum_wire_bytes);
    check_deadline(deadline, &mut duration_error)?;
    approval.map_err(E::from)
}

/// Applies a client traffic policy and hostname resolver to target
/// authorization without exposing either concern to workflow engines.
pub struct PolicyAuthorizer<'a, R> {
    policy: &'a crate::policy::Policy,
    resolver: &'a R,
}

impl<'a, R> PolicyAuthorizer<'a, R> {
    pub fn new(policy: &'a crate::policy::Policy, resolver: &'a R) -> Self {
        Self { policy, resolver }
    }
}

impl<R: crate::target::Resolver> Authorizer for PolicyAuthorizer<'_, R> {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        self.policy
            .resolve_target(target, self.resolver)
            .map_err(BoundaryError::from_error)
    }

    fn authorize_operation(
        &mut self,
        packets: u64,
        maximum_wire_bytes: u64,
    ) -> Result<(), BoundaryError> {
        self.policy
            .authorize_operation(packets, maximum_wire_bytes)
            .map_err(BoundaryError::from_error)
    }
}
