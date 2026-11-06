// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(native_route))]
use crate::{NativeCapability, Unsupported, route::Decision};
#[cfg(not(native_route))]
use packetcraftr_core::budget::Deadline;
#[cfg(not(native_route))]
use std::net::IpAddr;

#[cfg(all(native_route, target_os = "macos"))]
use af_route as backend;
#[cfg(all(native_route, target_os = "windows"))]
use iphelper as backend;
#[cfg(all(native_route, target_os = "linux"))]
use netlink as backend;

#[cfg(native_route)]
pub(crate) use backend::{interface_route as lookup_interface, route as lookup};

#[cfg(all(native_route, target_os = "macos"))]
pub(in crate::platform) mod af_route;
#[cfg(all(native_route, target_os = "windows"))]
pub(in crate::platform) mod iphelper;
#[cfg(all(native_route, target_os = "linux"))]
pub(in crate::platform) mod netlink;

#[cfg(all(native_route, any(target_os = "macos", target_os = "windows")))]
use std::net::IpAddr;

#[cfg(native_route)]
use crate::interface;
use crate::{interface::Id as InterfaceId, route};

#[cfg(all(native_route, any(target_os = "linux", target_os = "macos")))]
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

#[cfg(all(native_route, any(target_os = "macos", target_os = "windows")))]
trait InterfaceCandidate: Clone {
    fn interface(&self) -> &interface::Info;
}

#[cfg(all(native_route, any(target_os = "macos", target_os = "windows")))]
impl InterfaceCandidate for interface::Info {
    fn interface(&self) -> &interface::Info {
        self
    }
}

#[cfg(all(native_route, any(target_os = "macos", target_os = "windows")))]
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

#[cfg(not(native_route))]
pub(crate) fn lookup(
    _destination: IpAddr,
    _interface_hint: Option<&InterfaceId>,
    _preferred_source: Option<IpAddr>,
    _deadline: &Deadline,
) -> Result<Decision, route::Error> {
    Err(Unsupported::unbuilt(NativeCapability::Route, "route selection").into())
}

#[cfg(not(native_route))]
pub(crate) fn lookup_interface(
    _interface: &InterfaceId,
    _deadline: &Deadline,
) -> Result<Decision, route::Error> {
    Err(Unsupported::unbuilt(NativeCapability::Route, "interface selection").into())
}
