// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(target_os = "macos")]
pub(in crate::platform) mod af_route;
#[cfg(target_os = "windows")]
pub(in crate::platform) mod iphelper;
#[cfg(target_os = "linux")]
pub(in crate::platform) mod netlink;

#[cfg(any(target_os = "macos", target_os = "windows", test))]
use std::net::IpAddr;

use crate::{
    interface::{self, Id as InterfaceId},
    route,
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn find_interface(
    interfaces: &[interface::Info],
    requested: &InterfaceId,
) -> Result<interface::Info, route::Error> {
    if let Some(interface) = interfaces
        .iter()
        .find(|interface| interface.id == *requested)
    {
        return Ok(interface.clone());
    }
    if let Some(actual) = interfaces.iter().find(|interface| {
        interface.id.name == requested.name || interface.id.index == requested.index
    }) {
        return Err(route::Error::InterfaceMismatch {
            requested: requested.name.clone(),
            requested_index: requested.index,
            actual: actual.id.name.clone(),
            actual_index: actual.id.index,
        });
    }
    Err(route::Error::InterfaceNotFound {
        name: requested.name.clone(),
        index: requested.index,
    })
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
trait InterfaceCandidate: Clone {
    fn interface(&self) -> &interface::Info;
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
impl InterfaceCandidate for interface::Info {
    fn interface(&self) -> &interface::Info {
        self
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn constrain_by_preferred_source<T: InterfaceCandidate>(
    available: &[T],
    interface_hint: Option<&InterfaceId>,
    requested: Option<T>,
    preferred_source: Option<IpAddr>,
) -> Result<Option<T>, route::Error> {
    let Some(source) = preferred_source else {
        return Ok(requested);
    };
    let owns_source = |candidate: &T| {
        candidate
            .interface()
            .addresses
            .iter()
            .any(|assigned| assigned.address == source)
    };
    if let Some(requested) = requested {
        if owns_source(&requested) {
            return Ok(Some(requested));
        }
        return Err(route::Error::SourceUnavailable {
            preferred_source: source,
            interface: requested.interface().id.name.clone(),
        });
    }
    available
        .iter()
        .find(|candidate| owns_source(candidate))
        .cloned()
        .map(Some)
        .ok_or_else(|| route::Error::SourceUnavailable {
            preferred_source: source,
            interface: interface_hint
                .map_or_else(|| "any interface".to_owned(), |hint| hint.name.clone()),
        })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::test_support::interface_id;
    use crate::test_support::{assigned, interface_info, v4};

    fn interface() -> interface::Info {
        interface::Info {
            addresses: vec![
                assigned(v4(10, 0, 0, 2), 8),
                assigned(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
            ],
            ..interface_info("fixture0", 7)
        }
    }

    #[test]
    fn explicit_interface_owns_source_even_when_another_owner_is_enumerated_first() {
        let first = interface();
        let mut selected = first.clone();
        selected.id.name = "fixture1".to_owned();
        selected.id.index = 8;
        let source = first.addresses[0].address;
        for available in [
            vec![first.clone(), selected.clone()],
            vec![selected.clone(), first],
        ] {
            let actual = constrain_by_preferred_source(
                &available,
                Some(&selected.id),
                Some(selected.clone()),
                Some(source),
            )
            .unwrap()
            .unwrap();
            assert_eq!(actual.id, selected.id);
        }
        selected.addresses.clear();
        assert!(
            constrain_by_preferred_source(
                &[interface()],
                Some(&selected.id),
                Some(selected.clone()),
                Some(source)
            )
            .is_err()
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn interface_lookup_requires_the_complete_stable_identity() {
        let available = interface();
        assert_eq!(
            find_interface(std::slice::from_ref(&available), &available.id)
                .expect("exact identity"),
            available
        );

        for requested in [interface_id("fixture0", 8), interface_id("other0", 7)] {
            assert!(matches!(
                find_interface(std::slice::from_ref(&available), &requested),
                Err(route::Error::InterfaceMismatch { .. })
            ));
        }
        assert!(matches!(
            find_interface(
                std::slice::from_ref(&available),
                &interface_id("missing0", 99)
            ),
            Err(route::Error::InterfaceNotFound { .. })
        ));
    }
}
