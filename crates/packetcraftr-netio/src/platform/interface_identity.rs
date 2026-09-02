// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interface identity validation for native I/O boundaries.
//!
//! Both entry points check the same property: the selected interface name
//! still resolves to the selected index at the moment native I/O begins, so a
//! renamed, removed, or re-created interface cannot silently receive traffic
//! planned for a different one. They differ only in cost. Capture needs the
//! interface's addresses to derive a BPF netmask and therefore pays for a full
//! enumeration once per session; transmission needs nothing but the answer and
//! runs once per frame, so it asks the operating system about that one name.

#![cfg_attr(any(target_os = "linux", target_os = "macos"), allow(unsafe_code))]

use crate::{Error, interface::Id as InterfaceId};

/// Confirms the selected interface is still current and returns its snapshot.
///
/// Reserved for capture, which reads the returned addresses, and for targets
/// with no cheap name lookup. Every other native boundary uses
/// [`verify_interface_identity`].
#[cfg(any(native_layer2, not(any(target_os = "linux", target_os = "macos"))))]
pub(super) fn validate_current_interface_identity(
    expected: &InterfaceId,
) -> Result<crate::interface::Info, Error> {
    let mut interfaces = super::system_interfaces()?;
    if let Some(position) = interfaces
        .iter()
        .position(|interface| interface.id == *expected)
    {
        return Ok(interfaces.swap_remove(position));
    }
    let actual = interfaces
        .iter()
        .find(|interface| interface.id.index == expected.index)
        .map(|interface| interface.id.name.clone());
    Err(identity_changed(expected, actual.as_deref()))
}

/// Confirms the selected interface is still current without enumerating every
/// interface on the host.
///
/// This sits on the per-frame transmit path, so it must not perform a native
/// snapshot: on Linux a full enumeration costs a worker thread, a Tokio
/// runtime, a route-netlink socket, and a complete link plus address dump.
pub(super) fn verify_interface_identity(expected: &InterfaceId) -> Result<(), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // A name is unique among the interfaces the kernel currently owns, so
        // `if_nametoindex` answers the identity question exactly: the pair
        // (name, index) is current if and only if the name resolves to the
        // index. `if_indextoname` then names whichever interface holds the
        // planned index, reproducing the enumeration's diagnostic.
        if current_index(&expected.name) == Some(expected.index) {
            return Ok(());
        }
        Err(identity_changed(
            expected,
            current_name(expected.index).as_deref(),
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        validate_current_interface_identity(expected).map(|_| ())
    }
}

fn identity_changed(expected: &InterfaceId, actual: Option<&str>) -> Error {
    let actual = actual.map_or_else(
        || "no current interface".to_owned(),
        |name| format!("{name} (index {})", expected.index),
    );
    Error::Device {
        interface: expected.name.clone(),
        message: format!(
            "interface identity changed before native I/O: expected {} (index {}), found {actual}",
            expected.name, expected.index
        ),
        source: None,
    }
}

/// Resolves the index an interface name currently holds, if any.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn current_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `name` owns a NUL-terminated C string that outlives this call,
    // and `if_nametoindex` only reads it. A zero return means the name is not
    // current, which is the caller's rejection case.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

/// Resolves the name an interface index currently holds, if any.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn current_name(index: u32) -> Option<String> {
    let mut buffer = [0 as std::ffi::c_char; libc::IF_NAMESIZE];
    // SAFETY: `buffer` is writable for exactly the `IF_NAMESIZE` bytes
    // `if_indextoname` is documented to require, and it returns null rather
    // than writing when the index names no interface.
    let resolved = unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) };
    if resolved.is_null() {
        return None;
    }
    // SAFETY: a non-null return means `if_indextoname` NUL-terminated the name
    // inside `buffer`, which is still owned and borrowed by this frame.
    let name = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) };
    Some(name.to_string_lossy().into_owned())
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use crate::error::testing::assert_same_failure;

    const ABSENT_NAME: &str = "pcr-absent0";
    const ABSENT_INDEX: u32 = u32::MAX - 1;

    fn identifier(name: &str, index: u32) -> InterfaceId {
        InterfaceId {
            name: name.to_owned(),
            index,
        }
    }

    /// The first interface the kernel can still name, which every host has at
    /// least one of (loopback).
    fn current_interface() -> InterfaceId {
        (1..=16_u32)
            .find_map(|index| current_name(index).map(|name| identifier(&name, index)))
            .expect("the host must own at least one nameable interface")
    }

    #[test]
    fn verification_accepts_an_interface_whose_name_still_resolves_to_its_index() {
        let current = current_interface();

        verify_interface_identity(&current)
            .expect("a name that still resolves to its index is accepted");
    }

    #[test]
    fn verification_rejects_a_name_that_no_longer_resolves_and_names_the_current_holder() {
        let current = current_interface();

        let error = verify_interface_identity(&identifier(ABSENT_NAME, current.index))
            .expect_err("a name that resolves to no index must fail closed");

        assert_same_failure(
            &error,
            &Error::Device {
                interface: ABSENT_NAME.to_owned(),
                message: format!(
                    "interface identity changed before native I/O: expected {ABSENT_NAME} (index {}), found {} (index {})",
                    current.index, current.name, current.index
                ),
                source: None,
            },
        );
    }

    #[test]
    fn verification_rejects_a_name_that_resolves_to_a_different_index() {
        let current = current_interface();

        let error = verify_interface_identity(&identifier(&current.name, ABSENT_INDEX))
            .expect_err("a moved index must fail closed");

        assert_same_failure(
            &error,
            &Error::Device {
                interface: current.name.clone(),
                message: format!(
                    "interface identity changed before native I/O: expected {} (index {ABSENT_INDEX}), found no current interface",
                    current.name
                ),
                source: None,
            },
        );
    }

    #[test]
    fn absent_identities_resolve_to_nothing_in_either_direction() {
        assert_eq!(current_index(ABSENT_NAME), None);
        assert_eq!(current_index("interior\0nul"), None);
        assert_eq!(current_name(ABSENT_INDEX), None);
    }
}
