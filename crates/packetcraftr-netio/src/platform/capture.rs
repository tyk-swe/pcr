// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live capture backends: libpcap on Linux and macOS, and the runtime-loaded
//! Npcap on Windows. Both speak the pcap API whose shared rules live in
//! `common::pcap_api`.

#[cfg(pcap_backend)]
pub(in crate::platform) mod libpcap;
#[cfg(npcap_backend)]
pub(in crate::platform) mod npcap;
