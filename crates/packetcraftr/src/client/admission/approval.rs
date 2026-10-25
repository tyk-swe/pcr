// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Authorized resolution of one target and approval of an operation's budget.

use std::collections::HashSet;
use std::net::IpAddr;

use packetcraftr_netio::interface::Id as InterfaceId;

use packetcraftr_core::budget::Deadline;

use crate::error::Failure;
use crate::policy::{Authorizer, Operation, WireLimits};
use crate::target::{Family, ResolveTarget, SelectedAddress, Target};

#[derive(Debug)]
pub(crate) struct SelectedTargets {
    pub(crate) declared: String,
    pub(crate) targets: Vec<SelectedAddress>,
    pub(crate) declarations: Vec<Vec<u32>>,
    pub(crate) duplicates: Vec<u32>,
}

impl SelectedTargets {
    pub(crate) fn addresses(&self) -> Vec<IpAddr> {
        self.targets.iter().map(|target| target.address).collect()
    }
}

pub(crate) fn resolve_selected<A, E>(
    authorizer: &mut A,
    target: &Target,
    family: Family,
    deadline: &Deadline,
    gates: fn(u64, Failure) -> E,
) -> Result<SelectedTargets, E>
where
    A: ResolveTarget,
{
    let check = || check_deadline(deadline, gates);
    check()?;
    let resolved = authorizer.resolve_and_authorize(target, deadline);
    check()?;
    let resolved = resolved.map_err(|source| (gates)(0_u64, Failure::Authorization(source)))?;

    let declared = resolved.declared.to_string();
    let mut targets = Vec::with_capacity(resolved.selected.len());
    let mut seen = HashSet::<(IpAddr, Option<InterfaceId>)>::with_capacity(resolved.selected.len());
    for record in resolved.selected {
        check()?;
        if family.accepts(record.address) && seen.insert(record.key()) {
            targets.push(record);
        }
    }
    Ok(SelectedTargets {
        declared,
        targets,
        declarations: Vec::new(),
        duplicates: Vec::new(),
    })
}

pub(crate) fn approve_operation<A, E>(
    authorizer: &mut A,
    operation: Operation<'_>,
    deadline: &Deadline,
    gates: fn(u64, Failure) -> E,
) -> Result<(), E>
where
    A: Authorizer,
{
    check_deadline(deadline, gates)?;
    let approval = authorizer.authorize_operation(operation);
    check_deadline(deadline, gates)?;
    approval.map_err(|source| (gates)(0_u64, Failure::Authorization(source)))
}

fn check_deadline<E>(deadline: &Deadline, gates: fn(u64, Failure) -> E) -> Result<(), E> {
    deadline
        .check()
        .map_err(|source| (gates)(0_u64, Failure::DurationLimit(source)))
}

pub(crate) const fn wire_limits(packets: u64, maximum_wire_bytes: u64) -> Operation<'static> {
    Operation::Wire(WireLimits::new(packets, maximum_wire_bytes))
}
