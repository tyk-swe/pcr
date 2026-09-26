// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Layer 2 capture and injection backends: libpcap on Linux and macOS, and
//! the runtime-loaded Npcap on Windows. Both speak the libpcap ABI that
//! `pcap_common` maps.

#[cfg(npcap_backend)]
pub(in crate::platform) mod npcap;
#[cfg(pcap_backend)]
pub(in crate::platform) mod pcap_backend;
mod pcap_common;
