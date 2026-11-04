// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(all(native_route, target_os = "macos"))]
pub(in crate::platform) mod af_route;
#[cfg(native_send)]
mod identity;
#[cfg(all(native_route, target_os = "windows"))]
pub(in crate::platform) mod iphelper;
#[cfg(all(native_route, target_os = "linux"))]
pub(in crate::platform) mod netlink;

#[cfg(all(native_route, target_os = "macos"))]
use af_route as backend;
#[cfg(all(native_route, target_os = "windows"))]
use iphelper as backend;
#[cfg(all(native_route, target_os = "linux"))]
use netlink as backend;

#[cfg(any(not(native_route), native_send))]
use crate::interface;
#[cfg(native_send)]
use crate::interface::Id as InterfaceId;
#[cfg(not(native_route))]
use crate::{NativeCapability, Unsupported};
#[cfg(any(not(native_route), native_send))]
use packetcraftr_core::budget::Deadline;

#[cfg(native_route)]
pub(crate) use backend::interfaces as enumerate;
#[cfg(all(native_route, target_os = "windows"))]
pub(crate) use backend::ipv6_interfaces as enumerate_ipv6;
#[cfg(not(all(native_route, target_os = "windows")))]
pub(crate) use enumerate as enumerate_ipv6;
#[cfg(native_send)]
pub(crate) use identity::verify_interface_identity as verify_identity;

#[cfg(not(native_route))]
pub(crate) fn enumerate(_deadline: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
    Err(Unsupported::unbuilt(
        NativeCapability::InterfaceEnumeration,
        cfg!(feature = "native-route"),
        "native-route",
        "interface enumeration",
    )
    .into())
}

#[cfg(native_send)]
pub(crate) fn enumerate_for_identity(
    expected: &InterfaceId,
    deadline: &Deadline,
) -> Result<Vec<interface::Info>, interface::Error> {
    #[cfg(all(native_route, target_os = "windows"))]
    {
        backend::interfaces_for_identity(expected, deadline)
    }
    #[cfg(not(all(native_route, target_os = "windows")))]
    {
        let _ = expected;
        enumerate(deadline)
    }
}
