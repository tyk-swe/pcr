// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Admission of one live operation: authorized target resolution and
//! selection, the empty/family gates, and approval of its traffic budget.

mod approval;
mod selection;

pub(crate) use approval::{approve_operation, resolve_selected, wire_limits};
pub(crate) use selection::{DeclaredTargets, FamilyGate, admit_operation, admit_selection};

use std::borrow::Cow;
use std::time::SystemTime;

use packetcraftr_core::error::BoundaryError;

use crate::Client;
use crate::policy::{Authorizer, Operation, Policy};
use crate::providers::TargetProviders;
use crate::target::{Authorized, ResolveTarget, Resolver, Target};

pub(crate) struct Admission<'c> {
    policy: Cow<'c, Policy>,
    resolver: &'c dyn Resolver,
    now: SystemTime,
}

impl<'c> Admission<'c> {
    pub(crate) fn new(
        policy: impl Into<Cow<'c, Policy>>,
        resolver: &'c dyn Resolver,
        now: SystemTime,
    ) -> Self {
        Self {
            policy: policy.into(),
            resolver,
            now,
        }
    }
}

impl Authorizer for Admission<'_> {
    fn authorize_operation(&mut self, request: Operation<'_>) -> Result<(), BoundaryError> {
        self.policy
            .authorize_at(request, self.now)
            .map_err(BoundaryError::from_error)
    }
}

impl ResolveTarget for Admission<'_> {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<Authorized, BoundaryError> {
        self.policy
            .authorize_window_at(self.now)
            .map_err(BoundaryError::from_error)?;
        self.policy
            .resolve_target(target, self.resolver, deadline)
            .map_err(BoundaryError::from_error)
    }
}

impl<P: TargetProviders, K: crate::clock::Clock> Client<P, K> {
    pub(crate) fn admission(&self) -> Admission<'_> {
        Admission::new(
            Cow::Borrowed(self.policy.as_ref()),
            self.providers.resolver(),
            self.wall_now(),
        )
    }
}
