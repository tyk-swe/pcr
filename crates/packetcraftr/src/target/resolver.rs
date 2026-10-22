// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-authorized targets and the resolvers that turn hostnames and
//! zones into them.

use std::net::IpAddr;

use serde::Serialize;

use super::{Error, Family, Hostname, SelectedAddress, Target, Zone};

/// Policy-authorized target with private fields that prevent forgery.
#[derive(Clone, Debug, Serialize)]
pub struct Authorized {
    pub(crate) declared: Target,
    pub(crate) selected: Vec<SelectedAddress>,
}

impl Authorized {
    pub fn declared(&self) -> &Target {
        &self.declared
    }

    pub fn addresses(&self) -> Vec<IpAddr> {
        self.selected
            .iter()
            .map(|selected| selected.address)
            .collect()
    }

    pub fn selected(&self) -> &[SelectedAddress] {
        &self.selected
    }

    // authorization only constructs `Authorized` with a non-empty address list
    pub fn selected_address(&self) -> IpAddr {
        self.selected[0].address
    }

    pub fn address_for_family(&self, family: Family) -> Option<IpAddr> {
        self.selected
            .iter()
            .map(|selected| selected.address)
            .find(|address| family.accepts(*address))
    }
}

/// Injectable hostname resolver. Implementations must stop once `limit`
/// distinct addresses have been selected and report a typed overflow.
/// The legacy `resolve` callback is synchronous. `resolve_controlled` checks
/// control around that callback but cannot interrupt it. Override it with a
/// cooperative implementation or use [`BlockingResolver`] for owned isolation.
pub trait Resolver: Send + Sync {
    fn resolve(&self, hostname: &Hostname, limit: usize) -> Result<Vec<IpAddr>, Error>;

    fn resolve_controlled(
        &self,
        hostname: &Hostname,
        limit: usize,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<Vec<IpAddr>, Error> {
        deadline
            .enforce()
            .map_err(packetcraftr_core::error::BoundaryError::from_error)?;
        let result = self.resolve(hostname, limit);
        deadline
            .enforce()
            .map_err(packetcraftr_core::error::BoundaryError::from_error)?;
        result
    }

    fn resolve_zone(
        &self,
        zone: &Zone,
        _deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<packetcraftr_netio::interface::Id, Error> {
        Err(Error::ZoneCapability { zone: zone.clone() })
    }
}

pub(crate) trait ResolveTarget {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<Authorized, packetcraftr_core::error::BoundaryError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, hostname: &Hostname, limit: usize) -> Result<Vec<IpAddr>, Error> {
        self.resolve_controlled(
            hostname,
            limit,
            &packetcraftr_core::budget::Deadline::new(packetcraftr_netio::deadline::MAX_WAIT),
        )
    }

    fn resolve_controlled(
        &self,
        hostname: &Hostname,
        limit: usize,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<Vec<IpAddr>, Error> {
        let addresses = packetcraftr_netio::resolution::system(hostname.as_str(), limit, deadline)?;
        distinct_addresses(hostname, addresses, limit)
    }

    fn resolve_zone(
        &self,
        zone: &Zone,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<packetcraftr_netio::interface::Id, Error> {
        let interfaces = packetcraftr_netio::interface::SystemProvider
            .ipv6_interfaces(deadline)
            .map_err(|source| Error::ZoneResolution {
                zone: zone.clone(),
                source,
            })?;
        resolve_zone_from(zone, interfaces.into_iter().map(|info| info.id))
    }
}

/// An owned adapter for legacy blocking hostname resolvers. At most
/// `netio::resolution::MAX_PENDING_LOOKUPS` invocations remain unfinished, also
/// charged to the native root. Zone callbacks retain their cooperative contract.
#[derive(Debug)]
pub struct BlockingResolver<R>(std::sync::Arc<R>);

impl<R> Clone for BlockingResolver<R> {
    fn clone(&self) -> Self {
        Self(std::sync::Arc::clone(&self.0))
    }
}

impl<R> BlockingResolver<R> {
    pub fn new(resolver: R) -> Self {
        Self(std::sync::Arc::new(resolver))
    }
}

impl<R: Resolver + 'static> Resolver for BlockingResolver<R> {
    fn resolve(&self, hostname: &Hostname, limit: usize) -> Result<Vec<IpAddr>, Error> {
        self.resolve_controlled(
            hostname,
            limit,
            &packetcraftr_core::budget::Deadline::new(packetcraftr_netio::deadline::MAX_WAIT),
        )
    }

    fn resolve_controlled(
        &self,
        hostname: &Hostname,
        limit: usize,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<Vec<IpAddr>, Error> {
        let resolver = std::sync::Arc::clone(&self.0);
        let hostname = hostname.clone();
        Ok(packetcraftr_netio::resolution::blocking_lookup(
            deadline,
            move || {
                resolver
                    .resolve(&hostname, limit)
                    .map_err(packetcraftr_core::error::BoundaryError::from_error)
            },
        )?)
    }

    fn resolve_zone(
        &self,
        zone: &Zone,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<packetcraftr_netio::interface::Id, Error> {
        self.0.resolve_zone(zone, deadline)
    }
}

fn resolve_zone_from(
    zone: &Zone,
    interfaces: impl IntoIterator<Item = packetcraftr_netio::interface::Id>,
) -> Result<packetcraftr_netio::interface::Id, Error> {
    let mut matches = interfaces.into_iter().filter(|id| match zone.index() {
        Some(index) => id.index == index,
        None => id.name == zone.as_str(),
    });
    let resolved = matches
        .next()
        .ok_or_else(|| Error::UnknownZone { zone: zone.clone() })?;
    if matches.next().is_some() {
        return Err(Error::AmbiguousZone { zone: zone.clone() });
    }
    valid_zone_interface(zone, resolved)
}

pub(crate) fn valid_zone_interface(
    zone: &Zone,
    interface: packetcraftr_netio::interface::Id,
) -> Result<packetcraftr_netio::interface::Id, Error> {
    if interface.index == 0 || interface.name.is_empty() {
        return Err(Error::InvalidZoneInterface {
            zone: zone.clone(),
            interface,
        });
    }
    Ok(interface)
}

/// Keeps each address in first-seen order. Only distinct addresses count
/// toward `limit`.
pub(crate) fn distinct_addresses(
    hostname: &Hostname,
    resolved: impl IntoIterator<Item = IpAddr>,
    limit: usize,
) -> Result<Vec<IpAddr>, Error> {
    let mut addresses = Vec::new();
    for address in resolved {
        if addresses.contains(&address) {
            continue;
        }
        if addresses.len() >= limit {
            return Err(Error::AddressLimit {
                hostname: hostname.to_string(),
                limit,
            });
        }
        addresses.push(address);
    }
    if addresses.is_empty() {
        return Err(Error::NoAddresses {
            hostname: hostname.to_string(),
        });
    }
    Ok(addresses)
}
