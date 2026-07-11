// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::client::policy::Error as PolicyError;
use crate::client::target::{Hostname, Target as ClientTarget};

use super::target::{AuthorizationError, Authorized, Authorizer, Target};

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
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, AuthorizationError> {
        let target = match target {
            Target::Address(address) => ClientTarget::Address(*address),
            Target::Hostname(hostname) => ClientTarget::Hostname(
                hostname
                    .parse::<Hostname>()
                    .map_err(|error| AuthorizationError::classified(&error))?,
            ),
        };
        let resolved = self
            .policy
            .resolve_target(&target, self.resolver)
            .map_err(|error| AuthorizationError::classified(&error))?;
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
    ) -> Result<(), AuthorizationError> {
        if packets > self.policy.max_packets_per_operation {
            return Err(AuthorizationError::classified(&PolicyError::PacketLimit {
                actual: packets,
                limit: self.policy.max_packets_per_operation,
            }));
        }
        if maximum_wire_bytes > self.policy.max_bytes_per_operation {
            return Err(AuthorizationError::classified(&PolicyError::ByteLimit {
                actual: maximum_wire_bytes,
                limit: self.policy.max_bytes_per_operation,
            }));
        }
        Ok(())
    }
}
