// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::client::target::{Hostname, Target as ClientTarget};

use super::BoundaryError;
use super::target::{Authorized, Authorizer, Target};

/// Applies a client traffic policy and hostname resolver to the shared target
/// authorization contract.
pub struct PolicyAuthorizer<'a, R> {
    policy: &'a crate::client::policy::Policy,
    resolver: &'a R,
}

impl<'a, R> PolicyAuthorizer<'a, R> {
    pub fn new(policy: &'a crate::client::policy::Policy, resolver: &'a R) -> Self {
        Self { policy, resolver }
    }
}

impl<R: crate::client::target::Resolver> Authorizer for PolicyAuthorizer<'_, R> {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        let target = match target {
            Target::Address(address) => ClientTarget::Address(*address),
            Target::Hostname(hostname) => ClientTarget::Hostname(
                hostname
                    .parse::<Hostname>()
                    .map_err(BoundaryError::from_error)?,
            ),
        };
        let resolved = self
            .policy
            .resolve_target(&target, self.resolver)
            .map_err(BoundaryError::from_error)?;
        let declared = match resolved.declared() {
            ClientTarget::Address(address) => address.to_string(),
            ClientTarget::Hostname(hostname) => hostname.to_string(),
        };
        Ok(Authorized {
            declared,
            addresses: resolved.addresses().to_vec(),
        })
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
