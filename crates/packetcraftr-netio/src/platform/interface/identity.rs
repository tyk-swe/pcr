// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{Error, interface::Id as InterfaceId};

pub(crate) fn verify_interface_identity(expected: &InterfaceId) -> Result<(), Error> {
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
    #[cfg(target_os = "windows")]
    {
        super::iphelper::verify_identity(expected)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[expect(
    unsafe_code,
    reason = "interface index lookup calls libc::if_nametoindex"
)]
fn current_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `name` owns a NUL-terminated C string that outlives this call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[expect(
    unsafe_code,
    reason = "interface name lookup calls libc::if_indextoname and reads its C string"
)]
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
