// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(target_os = "macos")]
pub(in crate::platform) mod af_route;
#[cfg(target_os = "windows")]
pub(in crate::platform) mod iphelper;
#[cfg(target_os = "linux")]
pub(in crate::platform) mod netlink;

#[cfg(any(target_os = "macos", target_os = "windows"))]
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

#[cfg(any(target_os = "macos", target_os = "windows"))]
trait InterfaceCandidate: Clone {
    fn interface(&self) -> &interface::Info;
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl InterfaceCandidate for interface::Info {
    fn interface(&self) -> &interface::Info {
        self
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
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
