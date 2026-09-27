// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The per-send check that the selected interface still has its name and
//! index. Linux and macOS ask the kernel by name; other targets have no cheap
//! name lookup and enumerate through the interface capability on every check.

#![cfg_attr(any(target_os = "linux", target_os = "macos"), allow(unsafe_code))]

use crate::{Error, interface::Id as InterfaceId};

/// Confirms the interface a send was routed to is still current.
pub(in crate::platform) fn verify_interface_identity(expected: &InterfaceId) -> Result<(), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // `if_nametoindex` verifies the pair; `if_indextoname` supplies the
        // current name for mismatch diagnostics.
        if current_index(&expected.name) == Some(expected.index) {
            return Ok(());
        }
        Err(crate::interface::identity_changed(
            expected,
            current_name(expected.index).as_deref(),
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // A send has no deadline to give, and this target's enumeration is a
        // synchronous snapshot that takes none.
        let unbounded = packetcraftr_core::budget::Deadline::new(std::time::Duration::MAX);
        crate::interface::current(expected, &unbounded).map(|_| ())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn current_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `name` owns a NUL-terminated C string that outlives this call,
    // and `if_nametoindex` only reads it. A zero return means the name is not
    // current, which is the caller's rejection case.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

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
    use crate::error::test_support::assert_same_failure;

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
