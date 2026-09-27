// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pinned Npcap SDK 1.16 ABI declarations.

#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ushort, c_void};

pub(in crate::platform) const NPCAP_DEPENDENCY: &str = "Npcap 1.88 runtime";
pub(in crate::platform) const PCAP_ERROR_BUFFER_SIZE: usize = 256;
pub(in crate::platform) const PCAP_CHAR_ENC_UTF_8: c_uint = 1;
pub(in crate::platform) const PCAP_NETMASK_UNKNOWN: c_uint = 0xffff_ffff;
pub(in crate::platform) const READ_TIMEOUT_MILLIS: c_int = 50;
pub(in crate::platform) const SEND_SNAPSHOT_LENGTH: c_int = 65_535;

pub(in crate::platform) const PCAP_WARNING_PROMISC_NOTSUP: c_int = 2;
pub(in crate::platform) const PCAP_ERROR: c_int = -1;
pub(in crate::platform) const PCAP_ERROR_BREAK: c_int = -2;
pub(in crate::platform) const PCAP_ERROR_NO_SUCH_DEVICE: c_int = -5;
pub(in crate::platform) const PCAP_ERROR_RFMON_NOTSUP: c_int = -6;
pub(in crate::platform) const PCAP_ERROR_PERM_DENIED: c_int = -8;
pub(in crate::platform) const PCAP_ERROR_IFACE_NOT_UP: c_int = -9;
pub(in crate::platform) const PCAP_ERROR_PROMISC_PERM_DENIED: c_int = -11;
pub(in crate::platform) const PCAP_ERROR_CAPTURE_NOTSUP: c_int = -13;

pub(in crate::platform) type PcapInit = unsafe extern "C" fn(c_uint, *mut c_char) -> c_int;
pub(in crate::platform) type PcapCreate =
    unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut c_void;
pub(in crate::platform) type PcapSetInteger = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
pub(in crate::platform) type PcapGetInteger = unsafe extern "C" fn(*mut c_void) -> c_int;
pub(in crate::platform) type PcapListTstampTypes =
    unsafe extern "C" fn(*mut c_void, *mut *mut c_int) -> c_int;
pub(in crate::platform) type PcapFreeTstampTypes = unsafe extern "C" fn(*mut c_int);
pub(in crate::platform) type PcapTstampTypeToStr = unsafe extern "C" fn(c_int) -> *const c_char;
pub(in crate::platform) type PcapActivate = unsafe extern "C" fn(*mut c_void) -> c_int;
pub(in crate::platform) type PcapDatalink = unsafe extern "C" fn(*mut c_void) -> c_int;
pub(in crate::platform) type PcapSnapshot = unsafe extern "C" fn(*mut c_void) -> c_int;
pub(in crate::platform) type PcapCompile =
    unsafe extern "C" fn(*mut c_void, *mut BpfProgram, *const c_char, c_int, c_uint) -> c_int;
pub(in crate::platform) type PcapSetFilter =
    unsafe extern "C" fn(*mut c_void, *mut BpfProgram) -> c_int;
pub(in crate::platform) type PcapFreeCode = unsafe extern "C" fn(*mut BpfProgram);
pub(in crate::platform) type PcapNextEx =
    unsafe extern "C" fn(*mut c_void, *mut *mut PcapPacketHeader, *mut *const c_uchar) -> c_int;
pub(in crate::platform) type PcapSendPacket =
    unsafe extern "C" fn(*mut c_void, *const c_uchar, c_int) -> c_int;
pub(in crate::platform) type PcapStats =
    unsafe extern "C" fn(*mut c_void, *mut PcapStatistics) -> c_int;
pub(in crate::platform) type PcapBreakLoop = unsafe extern "C" fn(*mut c_void);
pub(in crate::platform) type PcapGetError = unsafe extern "C" fn(*mut c_void) -> *mut c_char;
pub(in crate::platform) type PcapClose = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
pub(in crate::platform) struct BpfInstruction {
    pub(in crate::platform) code: c_ushort,
    pub(in crate::platform) jump_true: c_uchar,
    pub(in crate::platform) jump_false: c_uchar,
    pub(in crate::platform) value: c_uint,
}

#[repr(C)]
pub(in crate::platform) struct BpfProgram {
    pub(in crate::platform) instruction_count: c_uint,
    pub(in crate::platform) instructions: *mut BpfInstruction,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(in crate::platform) struct PcapTimeval {
    pub(in crate::platform) tv_sec: c_long,
    pub(in crate::platform) tv_usec: c_long,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(in crate::platform) struct PcapPacketHeader {
    pub(in crate::platform) timestamp: PcapTimeval,
    pub(in crate::platform) captured_length: c_uint,
    pub(in crate::platform) original_length: c_uint,
}

// Npcap's Windows ABI extends the portable three-counter pcap_stat with
// ps_capt, ps_sent, and ps_netdrop. The complete SDK 1.16 layout is required
// so pcap_stats cannot write beyond the Rust allocation.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(in crate::platform) struct PcapStatistics {
    pub(in crate::platform) received: c_uint,
    pub(in crate::platform) dropped: c_uint,
    pub(in crate::platform) interface_dropped: c_uint,
    pub(in crate::platform) captured: c_uint,
    pub(in crate::platform) sent: c_uint,
    pub(in crate::platform) network_dropped: c_uint,
}
