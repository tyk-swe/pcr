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
        PcapNextEx, PcapSendPacket, PcapSetFilter, PcapSetInteger, PcapSnapshot, PcapStats,
    },
    error::{error_buffer_message, interface_conversion_error},
};
use crate::{Error, interface::Id as InterfaceId};

pub(super) struct NpcapApi {
    // Keeps the DLL loaded while function pointers are used.
    pub(super) _library: Library,
    pub(super) pcap_create: PcapCreate,
    pub(super) pcap_set_snaplen: PcapSetInteger,
    pub(super) pcap_set_promisc: PcapSetInteger,
    pub(super) pcap_set_timeout: PcapSetInteger,
    pub(super) pcap_set_immediate_mode: PcapSetInteger,
    pub(super) pcap_activate: PcapActivate,
    pub(super) pcap_datalink: PcapDatalink,
    pub(super) pcap_snapshot: PcapSnapshot,
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
    fn load() -> Result<Self, Error> {
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
        .map_err(|error| Error::MissingDependency {
            dependency: NPCAP_DEPENDENCY,
            message: format!(
                "could not load {}; install Npcap 1.88 for all users and restart PacketcraftR",
                path.display()
            ),
            source: Some(Arc::new(error)),
        })?;

        load_symbols!(&library, {
            pcap_init: PcapInit,
            pcap_create: PcapCreate,
            pcap_set_snaplen: PcapSetInteger,
            pcap_set_promisc: PcapSetInteger,
            pcap_set_timeout: PcapSetInteger,
            pcap_set_immediate_mode: PcapSetInteger,
            pcap_activate: PcapActivate,
            pcap_datalink: PcapDatalink,
            pcap_snapshot: PcapSnapshot,
            pcap_compile: PcapCompile,
            pcap_setfilter: PcapSetFilter,
            pcap_freecode: PcapFreeCode,
            pcap_next_ex: PcapNextEx,
            pcap_sendpacket: PcapSendPacket,
            pcap_stats: PcapStats,
            pcap_breakloop: PcapBreakLoop,
            pcap_geterr: PcapGetError,
            pcap_close: PcapClose,
        });

        let mut error_buffer = [0 as c_char; PCAP_ERROR_BUFFER_SIZE];
        // SAFETY: the function pointer came from the pinned DLL and the
        // writable error buffer has PCAP_ERRBUF_SIZE bytes.
        let initialization = unsafe { pcap_init(PCAP_CHAR_ENC_UTF_8, error_buffer.as_mut_ptr()) };
        if initialization != 0 {
            return Err(Error::MissingDependency {
                dependency: NPCAP_DEPENDENCY,
                message: format!(
                    "pcap_init rejected UTF-8 mode: {}",
                    error_buffer_message(&error_buffer)
                ),
                source: None,
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
            pcap_snapshot,
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

pub(super) fn npcap_api() -> Result<Arc<NpcapApi>, Error> {
    static API: OnceLock<Result<Arc<NpcapApi>, Error>> = OnceLock::new();
    API.get_or_init(|| NpcapApi::load().map(Arc::new)).clone()
}

pub(super) fn npcap_device_name(interface: &InterfaceId) -> Result<String, Error> {
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

/// Renders the adapter GUID in the registry form Npcap's device namespace
/// uses, from the GUID's own fields.
fn format_npcap_device(guid: GUID) -> String {
    format!(
        r"\Device\NPF_{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    )
}

fn npcap_library_path() -> Result<PathBuf, Error> {
    // A fixed maximum path buffer avoids environment-controlled DLL lookup.
    let mut windows_directory = vec![0_u16; 32_768];
    // SAFETY: the entire mutable UTF-16 buffer is provided to the system API,
    // which returns the number of initialized code units.
    let length = unsafe { GetSystemWindowsDirectoryW(Some(&mut windows_directory)) } as usize;
    if length == 0 || length >= windows_directory.len() {
        return Err(Error::MissingDependency {
            dependency: NPCAP_DEPENDENCY,
            message: "Windows did not return a valid system directory for secure DLL lookup"
                .to_owned(),
            source: None,
        });
    }
    windows_directory.truncate(length);
    let mut path = PathBuf::from(OsString::from_wide(&windows_directory));
    path.push("System32");
    path.push("Npcap");
    path.push("wpcap.dll");
    Ok(path)
}

/// Binds each listed export to a local of the same name, typed with the
/// signature the pinned SDK declares for it.
macro_rules! load_symbols {
    ($library:expr, { $($symbol:ident : $signature:ty),* $(,)? }) => {
        $(
            // SAFETY: every requested symbol and function signature is copied
            // directly from the pinned Npcap SDK 1.16 pcap.h ABI.
            let $symbol = unsafe {
                load_symbol::<$signature>($library, concat!(stringify!($symbol), "\0").as_bytes())?
            };
        )*
    };
}
use load_symbols;

unsafe fn load_symbol<T: Copy>(library: &Library, name: &'static [u8]) -> Result<T, Error> {
    // SAFETY: the caller supplies the exact SDK signature associated with this
    // NUL-terminated export name; the Library owner outlives T.
    unsafe { library.get::<T>(name) }
        .map(|symbol| *symbol)
        .map_err(|error| Error::MissingDependency {
            dependency: NPCAP_DEPENDENCY,
            message: format!(
                "required SDK 1.16 symbol {} is unavailable",
                String::from_utf8_lossy(name.split_last().map_or(name, |(_, head)| head))
            ),
            source: Some(Arc::new(error)),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npcap_device_names_use_the_registry_guid_spelling() {
        let guid = GUID::from_values(
            0x0123_4567,
            0x89ab,
            0xcdef,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        );

        assert_eq!(
            format_npcap_device(guid),
            r"\Device\NPF_{01234567-89AB-CDEF-0123-456789ABCDEF}"
        );
        assert_eq!(
            format_npcap_device(GUID::zeroed()),
            r"\Device\NPF_{00000000-0000-0000-0000-000000000000}"
        );
    }
}
