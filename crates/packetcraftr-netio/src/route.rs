// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod models;
#[cfg(any(native_route, test))]
#[cfg_attr(not(native_route), allow(dead_code))]
pub(crate) mod normalize;

use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Classified;

use crate::interface::Id as InterfaceId;

pub use crate::native::Error;
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

    /// Passively selects interface-only routes for a surveyed interface list.
    fn lookup_interfaces(
        &self,
        interfaces: Vec<crate::interface::Info>,
        deadline: &Deadline,
    ) -> Result<Vec<Decision>, Self::Error> {
        let mut routes = Vec::with_capacity(interfaces.len());
        for interface in interfaces {
            if let Some(decision) = self.lookup_interface(&interface.id, deadline)? {
                routes.push(decision);
            }
        }
        Ok(routes)
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
        let result =
            crate::platform::route::lookup(destination, interface_hint, preferred_source, deadline);
        admit(deadline, "looking up a route")?;
        result
    }

    fn lookup_interface(
        &self,
        interface: &InterfaceId,
        deadline: &Deadline,
    ) -> Result<Option<Decision>, Self::Error> {
        admit(deadline, "looking up an interface route")?;
        let result = crate::platform::route::lookup_interface(interface, deadline);
        admit(deadline, "looking up an interface route")?;
        result.map(Some)
    }

    #[cfg(all(native_route, target_os = "linux"))]
    fn lookup_interfaces(
        &self,
        interfaces: Vec<crate::interface::Info>,
        deadline: &Deadline,
    ) -> Result<Vec<Decision>, Self::Error> {
        admit(deadline, "looking up an interface route")?;
        let result = interfaces
            .into_iter()
            .map(normalize::interface_decision)
            .collect();
        admit(deadline, "looking up an interface route")?;
        result
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{interface, link::Capability};
    use packetcraftr_core::frame::LinkType;
    use std::time::Duration;

    fn info(index: u32) -> interface::Info {
        interface::Info {
            id: InterfaceId {
                name: format!("eth{index}"),
                index,
            },
            description: None,
            mac_address: None,
            addresses: Vec::new(),
            flags: interface::Flags::default(),
            mtu: Some(1500),
            capability: Capability::Layer3,
            link_type: LinkType::RAW,
        }
    }

    struct StubProvider;

    impl Provider for StubProvider {
        type Error = Error;

        fn lookup_with_preferences(
            &self,
            destination: IpAddr,
            _: Option<&InterfaceId>,
            _: Option<IpAddr>,
            _: &Deadline,
        ) -> Result<Decision, Self::Error> {
            Err(Error::RouteNotFound { destination })
        }

        fn lookup_interface(
            &self,
            interface: &InterfaceId,
            _: &Deadline,
        ) -> Result<Option<Decision>, Self::Error> {
            if interface.index == 2 {
                return Ok(None);
            }
            Ok(Some(Decision {
                interface: interface.clone(),
                source_mac: None,
                selected_source: None,
                preferred_source: None,
                next_hop: None,
                selection_reason: SelectionReason::InterfaceOnly,
                destination_scope: Scope::Unspecified,
                mtu: 1500,
                capability: Capability::Layer3,
                link_type: LinkType::RAW,
            }))
        }
    }

    #[test]
    fn default_lookup_interfaces_collects_present_decisions_in_order() {
        let deadline = Deadline::new(Duration::from_secs(5));
        let routes = StubProvider
            .lookup_interfaces(vec![info(1), info(2), info(3)], &deadline)
            .unwrap();
        let indexes: Vec<u32> = routes.iter().map(|route| route.interface.index).collect();
        assert_eq!(indexes, vec![1, 3]);
    }

    #[cfg(all(native_route, target_os = "linux"))]
    #[test]
    fn linux_system_provider_lookup_interfaces_uses_snapshot() {
        let deadline = Deadline::new(Duration::from_secs(5));
        let routes = SystemProvider
            .lookup_interfaces(vec![info(1), info(2)], &deadline)
            .unwrap();
        let indexes: Vec<u32> = routes.iter().map(|route| route.interface.index).collect();
        assert_eq!(indexes, vec![1, 2]);
        assert!(
            routes
                .iter()
                .all(|route| route.selection_reason == SelectionReason::InterfaceOnly)
        );
    }
}
