// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Secure Npcap library discovery, loading, and symbol ownership.

#![allow(unsafe_code)]

use std::{
    ffi::{OsString, c_char},
    os::windows::ffi::OsStringExt,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use libloading::os::windows::{
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, Library,
};
use windows::{
    Win32::{
        Foundation::NO_ERROR,
        NetworkManagement::{
            IpHelper::{ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid},
            Ndis::NET_LUID_LH,
        },
        System::SystemInformation::GetSystemWindowsDirectoryW,
    },
    core::GUID,
};

use super::{
    abi::{
        NPCAP_DEPENDENCY, PCAP_CHAR_ENC_UTF_8, PCAP_ERROR_BUFFER_SIZE, PcapActivate, PcapBreakLoop,
        PcapClose, PcapCompile, PcapCreate, PcapDatalink, PcapFreeCode, PcapGetError, PcapInit,
        PcapNextEx, PcapSendPacket, PcapSetFilter, PcapSetInteger, PcapStats,
    },
    error::{error_buffer_message, interface_conversion_error},
};
use crate::{Error as LiveIoError, route::InterfaceId};

pub(super) struct NpcapApi {
    // Function pointers remain valid only while their defining module is
    // loaded. This owner keeps it live for every use of the inert pointers.
    _library: Library,
    pub(super) pcap_create: PcapCreate,
    pub(super) pcap_set_snaplen: PcapSetInteger,
    pub(super) pcap_set_promisc: PcapSetInteger,
    pub(super) pcap_set_timeout: PcapSetInteger,
    pub(super) pcap_set_immediate_mode: PcapSetInteger,
    pub(super) pcap_activate: PcapActivate,
    pub(super) pcap_datalink: PcapDatalink,
    pub(super) pcap_compile: PcapCompile,
    pub(super) pcap_setfilter: PcapSetFilter,
    pub(super) pcap_freecode: PcapFreeCode,
    pub(super) pcap_next_ex: PcapNextEx,
    pub(super) pcap_sendpacket: PcapSendPacket,
    pub(super) pcap_stats: PcapStats,
    pub(super) pcap_breakloop: PcapBreakLoop,
    pub(super) pcap_geterr: PcapGetError,
    pub(super) pcap_close: PcapClose,
}

impl NpcapApi {
    fn load() -> Result<Self, LiveIoError> {
        let path = npcap_library_path()?;
        // SAFETY: the path is obtained from the operating system rather than
        // process environment, and the flags restrict dependent DLL lookup to
        // Npcap's directory plus System32.
        let library = unsafe {
            Library::load_with_flags(
                &path,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        }
        .map_err(|error| LiveIoError::MissingDependency {
            dependency: NPCAP_DEPENDENCY,
            message: format!(
                "could not load {}: {error}; install Npcap 1.88 for all users and restart PacketcraftR",
                path.display()
            ),
        })?;

        // SAFETY: every requested symbol and function signature is copied
        // directly from the pinned Npcap SDK 1.16 pcap.h ABI.
        let pcap_init = unsafe { load_symbol::<PcapInit>(&library, b"pcap_init\0")? };
        // SAFETY: see the ABI note above.
        let pcap_create = unsafe { load_symbol::<PcapCreate>(&library, b"pcap_create\0")? };
        // SAFETY: see the ABI note above.
        let pcap_set_snaplen =
            unsafe { load_symbol::<PcapSetInteger>(&library, b"pcap_set_snaplen\0")? };
        // SAFETY: see the ABI note above.
        let pcap_set_promisc =
            unsafe { load_symbol::<PcapSetInteger>(&library, b"pcap_set_promisc\0")? };
        // SAFETY: see the ABI note above.
        let pcap_set_timeout =
            unsafe { load_symbol::<PcapSetInteger>(&library, b"pcap_set_timeout\0")? };
        // SAFETY: see the ABI note above.
        let pcap_set_immediate_mode =
            unsafe { load_symbol::<PcapSetInteger>(&library, b"pcap_set_immediate_mode\0")? };
        // SAFETY: see the ABI note above.
        let pcap_activate = unsafe { load_symbol::<PcapActivate>(&library, b"pcap_activate\0")? };
        // SAFETY: see the ABI note above.
        let pcap_datalink = unsafe { load_symbol::<PcapDatalink>(&library, b"pcap_datalink\0")? };
        // SAFETY: see the ABI note above.
        let pcap_compile = unsafe { load_symbol::<PcapCompile>(&library, b"pcap_compile\0")? };
        // SAFETY: see the ABI note above.
        let pcap_setfilter =
            unsafe { load_symbol::<PcapSetFilter>(&library, b"pcap_setfilter\0")? };
        // SAFETY: see the ABI note above.
        let pcap_freecode = unsafe { load_symbol::<PcapFreeCode>(&library, b"pcap_freecode\0")? };
        // SAFETY: see the ABI note above.
        let pcap_next_ex = unsafe { load_symbol::<PcapNextEx>(&library, b"pcap_next_ex\0")? };
        // SAFETY: see the ABI note above.
        let pcap_sendpacket =
            unsafe { load_symbol::<PcapSendPacket>(&library, b"pcap_sendpacket\0")? };
        // SAFETY: see the ABI note above.
        let pcap_stats = unsafe { load_symbol::<PcapStats>(&library, b"pcap_stats\0")? };
        // SAFETY: see the ABI note above.
        let pcap_breakloop =
            unsafe { load_symbol::<PcapBreakLoop>(&library, b"pcap_breakloop\0")? };
        // SAFETY: see the ABI note above.
        let pcap_geterr = unsafe { load_symbol::<PcapGetError>(&library, b"pcap_geterr\0")? };
        // SAFETY: see the ABI note above.
        let pcap_close = unsafe { load_symbol::<PcapClose>(&library, b"pcap_close\0")? };

        let mut error_buffer = [0 as c_char; PCAP_ERROR_BUFFER_SIZE];
        // SAFETY: the function pointer came from the pinned DLL and the
        // writable error buffer has PCAP_ERRBUF_SIZE bytes.
        let initialization = unsafe { pcap_init(PCAP_CHAR_ENC_UTF_8, error_buffer.as_mut_ptr()) };
        if initialization != 0 {
            return Err(LiveIoError::MissingDependency {
                dependency: NPCAP_DEPENDENCY,
                message: format!(
                    "pcap_init rejected UTF-8 mode: {}",
                    error_buffer_message(&error_buffer)
                ),
            });
        }

        Ok(Self {
            _library: library,
            pcap_create,
            pcap_set_snaplen,
            pcap_set_promisc,
            pcap_set_timeout,
            pcap_set_immediate_mode,
            pcap_activate,
            pcap_datalink,
            pcap_compile,
            pcap_setfilter,
            pcap_freecode,
            pcap_next_ex,
            pcap_sendpacket,
            pcap_stats,
            pcap_breakloop,
            pcap_geterr,
            pcap_close,
        })
    }
}

pub(super) fn npcap_api() -> Result<Arc<NpcapApi>, LiveIoError> {
    static API: OnceLock<Result<Arc<NpcapApi>, LiveIoError>> = OnceLock::new();
    API.get_or_init(|| NpcapApi::load().map(Arc::new)).clone()
}

pub(super) fn npcap_device_name(interface: &InterfaceId) -> Result<String, LiveIoError> {
    let mut luid = NET_LUID_LH::default();
    // SAFETY: luid is writable and the interface index is a plain value.
    let index_result = unsafe { ConvertInterfaceIndexToLuid(interface.index, &mut luid) };
    if index_result != NO_ERROR {
        return Err(interface_conversion_error(
            interface,
            "ConvertInterfaceIndexToLuid",
            index_result.0,
        ));
    }
    let mut guid = GUID::zeroed();
    // SAFETY: luid was initialized by IP Helper and guid is writable.
    let guid_result = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
    if guid_result != NO_ERROR {
        return Err(interface_conversion_error(
            interface,
            "ConvertInterfaceLuidToGuid",
            guid_result.0,
        ));
    }
    Ok(format_npcap_device(guid))
}

fn format_npcap_device(guid: GUID) -> String {
    format!(r"\Device\NPF_{{{guid:?}}}")
}

fn npcap_library_path() -> Result<PathBuf, LiveIoError> {
    // Windows paths can be up to 32,767 UTF-16 code units. A fixed maximum
    // buffer avoids trusting mutable environment variables for DLL lookup.
    let mut windows_directory = vec![0_u16; 32_768];
    // SAFETY: the entire mutable UTF-16 buffer is provided to the system API,
    // which returns the number of initialized code units.
    let length = unsafe { GetSystemWindowsDirectoryW(Some(&mut windows_directory)) } as usize;
    if length == 0 || length >= windows_directory.len() {
        return Err(LiveIoError::MissingDependency {
            dependency: NPCAP_DEPENDENCY,
            message: "Windows did not return a valid system directory for secure DLL lookup"
                .to_owned(),
        });
    }
    windows_directory.truncate(length);
    let mut path = PathBuf::from(OsString::from_wide(&windows_directory));
    path.push("System32");
    path.push("Npcap");
    path.push("wpcap.dll");
    Ok(path)
}

unsafe fn load_symbol<T: Copy>(library: &Library, name: &'static [u8]) -> Result<T, LiveIoError> {
    // SAFETY: the caller supplies the exact SDK signature associated with this
    // NUL-terminated export name; the Library owner outlives T.
    unsafe { library.get::<T>(name) }
        .map(|symbol| *symbol)
        .map_err(|error| LiveIoError::MissingDependency {
            dependency: NPCAP_DEPENDENCY,
            message: format!(
                "required SDK 1.16 symbol {} is unavailable: {error}",
                String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
            ),
        })
}

#[cfg(test)]
mod tests {
    use windows::core::GUID;

    use super::format_npcap_device;

    #[test]
    fn npcap_device_uses_ip_helper_guid_syntax() {
        let guid = GUID::from_values(
            0x1234_5678,
            0x9abc,
            0xdef0,
            [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
        );
        assert_eq!(
            format_npcap_device(guid),
            r"\Device\NPF_{12345678-9ABC-DEF0-1234-56789ABCDEF0}"
        );
    }
}
