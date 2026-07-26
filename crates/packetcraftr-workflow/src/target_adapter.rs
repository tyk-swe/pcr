// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_policy::TrafficPolicy;
use packetcraftr_policy::target::{Hostname, HostnameResolver, LiveTarget as PolicyTarget};

use super::BoundaryError;
use super::target::{Authorized, Authorizer, Target};

/// Applies a traffic policy and hostname resolver to the shared workflow
/// target-authorization contract. It carries no client dependency: policy is
/// the authority, so workflow engines can be exercised against the real
/// authorization path without an active network stack.
pub struct PolicyAuthorizer<'a, R> {
    policy: &'a TrafficPolicy,
    resolver: &'a R,
}

impl<'a, R> PolicyAuthorizer<'a, R> {
    pub fn new(policy: &'a TrafficPolicy, resolver: &'a R) -> Self {
        Self { policy, resolver }
    }
}

impl<R: HostnameResolver> Authorizer for PolicyAuthorizer<'_, R> {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        let target = match target {
            Target::Address(address) => PolicyTarget::Address(*address),
            Target::Hostname(hostname) => PolicyTarget::Hostname(
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
            PolicyTarget::Address(address) => address.to_string(),
            PolicyTarget::Hostname(hostname) => hostname.to_string(),
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
