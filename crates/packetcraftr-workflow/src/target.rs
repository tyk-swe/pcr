// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_client::target::{Hostname, Target as ClientTarget};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use crate::clock::check_deadline;

/// Address-family selection shared by target-oriented workflows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub(crate) fn accepts(self, address: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Ipv4 => address.is_ipv4(),
            Self::Ipv6 => address.is_ipv6(),
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Any => "requested",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        }
    }
}

/// Declared target before hostname resolution or traffic-policy effects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Target {
    Address(IpAddr),
    Hostname(String),
}

impl fmt::Display for Target {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(address) => address.fmt(formatter),
            Self::Hostname(hostname) => formatter.write_str(hostname),
        }
    }
}

/// Target whose declared name and selected addresses have been authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorized {
    pub declared: String,
    pub addresses: Vec<IpAddr>,
}

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
    family: AddressFamily,
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

    let mut addresses = Vec::with_capacity(resolved.addresses.len());
    let mut seen = HashSet::with_capacity(resolved.addresses.len());
    for address in resolved.addresses {
        check_deadline(deadline, &mut duration_error)?;
        if family.accepts(address) && seen.insert(address) {
            addresses.push(address);
        }
    }
    Ok(SelectedTargets {
        declared: resolved.declared,
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
    policy: &'a packetcraftr_client::policy::Policy,
    resolver: &'a R,
}

impl<'a, R> PolicyAuthorizer<'a, R> {
    pub fn new(policy: &'a packetcraftr_client::policy::Policy, resolver: &'a R) -> Self {
        Self { policy, resolver }
    }
}

impl<R: packetcraftr_client::target::Resolver> Authorizer for PolicyAuthorizer<'_, R> {
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::AddressFamily;

    #[test]
    fn any_address_family_accepts_both_ip_versions() {
        assert!(AddressFamily::Any.accepts(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(AddressFamily::Any.accepts(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn explicit_address_families_reject_the_other_ip_version() {
        assert!(AddressFamily::Ipv4.accepts(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!AddressFamily::Ipv4.accepts(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(AddressFamily::Ipv6.accepts(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!AddressFamily::Ipv6.accepts(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn address_family_labels_are_stable_and_any_is_default() {
        assert_eq!(AddressFamily::default(), AddressFamily::Any);
        assert_eq!(AddressFamily::Any.label(), "requested");
        assert_eq!(AddressFamily::Ipv4.label(), "IPv4");
        assert_eq!(AddressFamily::Ipv6.label(), "IPv6");
    }
}
