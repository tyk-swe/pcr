// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The one path through which a client's workflows are admitted.

use crate::BoundaryError;
use crate::policy::{self, Authorizer, Operation, Policy};
use crate::target::{Authorized, ResolveTarget, Resolver, Target};

/// A client's policy together with the resolver its declared targets resolve
/// through. [`Client::admission`](crate::Client) vends it; staged preparation
/// authorizes packet budgets through [`authorize`](Self::authorize), and
/// target workflows use it as their [`Authorizer`] and [`ResolveTarget`].
pub(crate) struct Admission<'c> {
    policy: &'c Policy,
    resolver: &'c dyn Resolver,
}

impl<'c> Admission<'c> {
    pub(crate) fn new(policy: &'c Policy, resolver: &'c dyn Resolver) -> Self {
        Self { policy, resolver }
    }

    /// The policy every decision applies.
    pub(crate) fn policy(&self) -> &'c Policy {
        self.policy
    }

    /// Authorizes `operation`, keeping the typed policy failure.
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
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        self.policy
            .resolve_target(target, self.resolver)
            .map_err(BoundaryError::from_error)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use packetcraftr_core::error::Classified;

    use super::*;
    use crate::policy::WireLimits;
    use crate::test_support::ScriptedResolver;

    #[test]
    fn admission_resolves_through_its_resolver_and_applies_its_policy() {
        let policy = Policy {
            max_packets_per_operation: 1,
            allow_hostname_resolution: true,
            ..Policy::default()
        };
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let resolver = ScriptedResolver::new([vec![address]]);
        let mut admission = Admission::new(&policy, &resolver);

        let target: Target = "documentation.invalid".parse().expect("hostname target");
        let authorized = admission
            .resolve_and_authorize(&target)
            .expect("the documentation address is authorized");
        assert_eq!(authorized.addresses, [address]);
        assert_eq!(resolver.calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let denied = admission
            .authorize_operation(Operation::Wire(WireLimits::new(2, 0)))
            .expect_err("two packets exceed the policy");
        assert_eq!(denied.classification().code, "policy.packet_limit");
        assert!(matches!(
            admission.authorize(Operation::Wire(WireLimits::new(2, 0))),
            Err(policy::Error::PacketLimit { .. })
        ));
    }
}
