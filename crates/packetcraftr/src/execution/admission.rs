// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::policy::{self, Authorizer, Operation, Policy};
use crate::target::{Authorized, ResolveTarget, Resolver, Target};
use packetcraftr_core::error::BoundaryError;

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
