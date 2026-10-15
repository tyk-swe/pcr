// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod error;
mod models;
#[cfg(native_route)]
pub(crate) mod normalize;

use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Classified;

use crate::interface::Id as InterfaceId;

pub use error::Error;
pub use models::{Decision, Scope, SelectionReason};

/// Passive route and interface lookups.
pub trait Provider: Send + Sync {
    type Error: Classified + Send + Sync + 'static;

    /// `preferred_source` constrains interface selection but never rewrites packet source.
    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
        deadline: &Deadline,
    ) -> Result<Decision, Self::Error>;

    /// Passively selects an interface for destination-free packets.
    fn lookup_interface(
        &self,
        _interface: &InterfaceId,
        _deadline: &Deadline,
    ) -> Result<Option<Decision>, Self::Error> {
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    type Error = Error;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
        deadline: &Deadline,
    ) -> Result<Decision, Self::Error> {
        validate_preferred_source_family(destination, preferred_source)?;
        admit(deadline, "looking up a route")?;
        crate::platform::route(destination, interface_hint, preferred_source, deadline)
    }

    fn lookup_interface(
        &self,
        interface: &InterfaceId,
        deadline: &Deadline,
    ) -> Result<Option<Decision>, Self::Error> {
        admit(deadline, "looking up an interface route")?;
        crate::platform::interface_route(interface, deadline).map(Some)
    }
}

fn admit(deadline: &Deadline, operation: &'static str) -> Result<(), Error> {
    deadline
        .live_remaining()
        .map(drop)
        .map_err(|interrupted| Error::interrupted(interrupted, operation))
}

fn validate_preferred_source_family(
    destination: IpAddr,
    preferred_source: Option<IpAddr>,
) -> Result<(), Error> {
    if let Some(source) = preferred_source
        && source.is_ipv4() != destination.is_ipv4()
    {
        return Err(Error::SourceFamilyMismatch {
            preferred_source: source,
            destination,
        });
    }
    Ok(())
}
