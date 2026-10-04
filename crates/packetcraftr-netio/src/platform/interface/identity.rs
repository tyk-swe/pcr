// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg_attr(any(target_os = "linux", target_os = "macos"), allow(unsafe_code))]

use crate::{Error, interface::Id as InterfaceId};

pub(in crate::platform) fn verify_interface_identity(expected: &InterfaceId) -> Result<(), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
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
        // A send has no deadline to give; this target's enumeration is a synchronous snapshot.
        let unbounded = packetcraftr_core::budget::Deadline::new(std::time::Duration::MAX);
        crate::interface::current(expected, &unbounded).map(|_| ())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn current_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `name` owns a NUL-terminated C string that outlives this call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn current_name(index: u32) -> Option<String> {
    let mut buffer = [0 as std::ffi::c_char; libc::IF_NAMESIZE];
    // SAFETY: `buffer` is writable for exactly the `IF_NAMESIZE` bytes `if_indextoname` requires.
    let resolved = unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) };
    if resolved.is_null() {
        return None;
    }
    // SAFETY: a non-null return means `if_indextoname` NUL-terminated the name inside `buffer`.
    let name = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) };
    Some(name.to_string_lossy().into_owned())
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use crate::error::test_support::assert_same_failure;
    use crate::test_support::interface_id;

    const ABSENT_NAME: &str = "pcr-absent0";
    const ABSENT_INDEX: u32 = u32::MAX - 1;

    fn current_interface() -> InterfaceId {
        (1..=16_u32)
            .find_map(|index| current_name(index).map(|name| interface_id(&name, index)))
            .expect("the host must own at least one nameable interface")
    }

    #[test]
    fn verification_rejects_stale_name_and_names_holder() {
        let current = current_interface();

        let error = verify_interface_identity(&interface_id(ABSENT_NAME, current.index))
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

        let error = verify_interface_identity(&interface_id(&current.name, ABSENT_INDEX))
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
}
