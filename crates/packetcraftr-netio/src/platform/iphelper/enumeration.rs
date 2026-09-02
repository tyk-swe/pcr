// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Windows interface enumeration backed by IP Helper `GetAdaptersAddresses`.

#![allow(unsafe_code)]

use std::mem::{align_of, size_of};

use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::Networking::WinSock::AF_UNSPEC;

use super::adapter::{BufferBounds, WindowsAdapter, parse_adapters};
use crate::{interface, route::SystemError};

pub(in crate::platform) fn interfaces() -> Result<Vec<interface::Info>, SystemError> {
    Ok(adapter_snapshots()?
        .into_iter()
        .map(|adapter| adapter.interface)
        .collect())
}

pub(super) fn adapter_snapshots() -> Result<Vec<WindowsAdapter>, SystemError> {
    const FLAGS: GET_ADAPTERS_ADDRESSES_FLAGS = GET_ADAPTERS_ADDRESSES_FLAGS(
        GAA_FLAG_INCLUDE_PREFIX.0
            | GAA_FLAG_SKIP_ANYCAST.0
            | GAA_FLAG_SKIP_MULTICAST.0
            | GAA_FLAG_SKIP_DNS_SERVER.0,
    );
    let mut required = 0_u32;
    // SAFETY: this documented sizing call has null output storage and a valid
    // size pointer. No linked-list pointer is dereferenced.
    let sizing =
        unsafe { GetAdaptersAddresses(u32::from(AF_UNSPEC.0), FLAGS, None, None, &mut required) };
    if sizing != ERROR_BUFFER_OVERFLOW.0 && sizing != NO_ERROR.0 {
        return Err(win32_error(
            "GetAdaptersAddresses(size)",
            WIN32_ERROR(sizing),
        ));
    }

    for _ in 0..4 {
        let word_count = usize::try_from(required)
            .ok()
            .map(|bytes| bytes.div_ceil(align_of::<usize>()))
            .filter(|words| *words != 0)
            .ok_or_else(|| SystemError::InvalidResponse {
                message: "Windows reported an invalid adapter buffer size".to_owned(),
            })?;
        // A usize vector supplies alignment at least as strict as every IP
        // Helper structure while keeping the backing allocation initialized.
        let mut storage = vec![0_usize; word_count];
        let head = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut supplied = required;
        // SAFETY: `storage` is writable for at least `supplied` bytes and is
        // suitably aligned for IP_ADAPTER_ADDRESSES_LH.
        let result = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                FLAGS,
                None,
                Some(head),
                &mut supplied,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW.0 {
            required = supplied;
            continue;
        }
        if result != NO_ERROR.0 {
            return Err(win32_error("GetAdaptersAddresses", WIN32_ERROR(result)));
        }
        let initialized = usize::try_from(supplied).map_err(|_| SystemError::InvalidResponse {
            message: "Windows returned an unrepresentable adapter buffer length".to_owned(),
        })?;
        let allocated = storage
            .len()
            .checked_mul(size_of::<usize>())
            .ok_or_else(|| SystemError::InvalidResponse {
                message: "Windows adapter buffer size overflowed".to_owned(),
            })?;
        if initialized == 0 || initialized > allocated {
            return Err(SystemError::InvalidResponse {
                message: format!(
                    "Windows initialized {initialized} bytes of a {allocated}-byte adapter buffer"
                ),
            });
        }
        let bounds = BufferBounds::new(storage.as_ptr().cast(), initialized)?;
        return parse_adapters(head, bounds);
    }
    Err(SystemError::OperatingSystem {
        operation: "GetAdaptersAddresses",
        message: "adapter list changed during four consecutive reads".to_owned(),
        source: None,
    })
}

pub(super) fn win32_error(operation: &'static str, error: WIN32_ERROR) -> SystemError {
    SystemError::OperatingSystem {
        operation,
        message: format!("Win32 error {}", error.0),
        source: Some(std::sync::Arc::new(std::io::Error::from_raw_os_error(
            error.0.cast_signed(),
        ))),
    }
}
