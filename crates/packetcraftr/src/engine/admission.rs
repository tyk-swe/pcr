// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Admission of one live operation: authorized target resolution and
//! selection, the empty/family gates, and approval of its traffic budget.

mod approval;
mod selection;

pub(crate) use approval::{approve_operation, resolve_selected, wire_limits};
pub(crate) use selection::{DeclaredTargets, FamilyGate, admit_operation, admit_selection};

use packetcraftr_core::error::BoundaryError;

use crate::Client;
use crate::policy::{self, Authorizer, Operation, Policy};
use crate::providers::TargetProviders;
use crate::target::{Authorized, ResolveTarget, Resolver, Target};

pub(crate) struct Admission<'c> {
    policy: &'c Policy,
    resolver: &'c dyn Resolver,
}

impl<'c> Admission<'c> {
    pub(crate) fn new(policy: &'c Policy, resolver: &'c dyn Resolver) -> Self {
        Self { policy, resolver }
    }

    pub(crate) fn authorize(&self, operation: Operation<'_>) -> Result<(), policy::Error> {
        self.policy.authorize(operation)
    }
}

impl Authorizer for Admission<'_> {
    fn authorize_operation(&mut self, request: Operation<'_>) -> Result<(), BoundaryError> {
        self.authorize(request).map_err(BoundaryError::from_error)
    }
}

impl ResolveTarget for Admission<'_> {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<Authorized, BoundaryError> {
        self.policy
            .resolve_target(target, self.resolver, deadline)
            .map_err(BoundaryError::from_error)
    }
}

impl<P: TargetProviders, K> Client<P, K> {
    pub(crate) fn admission(&self) -> Admission<'_> {
        Admission::new(&self.policy, self.providers.resolver())
    }
}
