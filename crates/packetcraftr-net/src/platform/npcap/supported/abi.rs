// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pinned Npcap SDK 1.16 ABI declarations.

#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};

pub(super) const NPCAP_DEPENDENCY: &str = "Npcap 1.88 runtime";
pub(super) const PCAP_ERROR_BUFFER_SIZE: usize = 256;
pub(super) const PCAP_CHAR_ENC_UTF_8: c_uint = 1;
pub(super) const READ_TIMEOUT_MILLIS: c_int = 50;
pub(super) const SEND_SNAPSHOT_LENGTH: c_int = 65_535;

pub(super) const PCAP_ERROR: c_int = -1;
pub(super) const PCAP_ERROR_BREAK: c_int = -2;
pub(super) const PCAP_ERROR_NO_SUCH_DEVICE: c_int = -5;
pub(super) const PCAP_ERROR_RFMON_NOTSUP: c_int = -6;
pub(super) const PCAP_ERROR_PERM_DENIED: c_int = -8;
pub(super) const PCAP_ERROR_IFACE_NOT_UP: c_int = -9;
pub(super) const PCAP_ERROR_PROMISC_PERM_DENIED: c_int = -11;
pub(super) const PCAP_ERROR_CAPTURE_NOTSUP: c_int = -13;

pub(super) type PcapInit = unsafe extern "C" fn(c_uint, *mut c_char) -> c_int;
pub(super) type PcapCreate = unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut c_void;
pub(super) type PcapSetInteger = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
pub(super) type PcapActivate = unsafe extern "C" fn(*mut c_void) -> c_int;
pub(super) type PcapDatalink = unsafe extern "C" fn(*mut c_void) -> c_int;
pub(super) type PcapNextEx =
    unsafe extern "C" fn(*mut c_void, *mut *mut PcapPacketHeader, *mut *const c_uchar) -> c_int;
pub(super) type PcapSendPacket = unsafe extern "C" fn(*mut c_void, *const c_uchar, c_int) -> c_int;
pub(super) type PcapStats = unsafe extern "C" fn(*mut c_void, *mut PcapStatistics) -> c_int;
pub(super) type PcapBreakLoop = unsafe extern "C" fn(*mut c_void);
pub(super) type PcapGetError = unsafe extern "C" fn(*mut c_void) -> *mut c_char;
pub(super) type PcapClose = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct PcapTimeval {
    pub(super) tv_sec: c_long,
    pub(super) tv_usec: c_long,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct PcapPacketHeader {
    pub(super) timestamp: PcapTimeval,
    pub(super) captured_length: c_uint,
    pub(super) original_length: c_uint,
}

// Npcap's Windows ABI extends the portable three-counter pcap_stat with
// ps_capt, ps_sent, and ps_netdrop. The complete SDK 1.16 layout is required
// so pcap_stats cannot write beyond the Rust allocation.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct PcapStatistics {
    pub(super) received: c_uint,
    pub(super) dropped: c_uint,
    pub(super) interface_dropped: c_uint,
    pub(super) captured: c_uint,
    pub(super) sent: c_uint,
    pub(super) network_dropped: c_uint,
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::{PcapPacketHeader, PcapStatistics, PcapTimeval};

    #[test]
    fn pinned_sdk_layouts_match_windows_x64_abi() {
        assert_eq!(size_of::<PcapTimeval>(), 8);
        assert_eq!(size_of::<PcapPacketHeader>(), 16);
        assert_eq!(size_of::<PcapStatistics>(), 24);
    }
}
