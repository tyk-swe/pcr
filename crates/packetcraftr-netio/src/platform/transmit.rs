// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Transmission backends: Layer 2 injection through libpcap on Linux and
//! macOS or Npcap on Windows, and Layer 3 through target-native raw IP
//! sockets.

#[cfg(pcap_backend)]
pub(in crate::platform) mod libpcap;
#[cfg(npcap_backend)]
pub(in crate::platform) mod npcap;
#[cfg(native_layer3)]
pub(in crate::platform) mod raw_ip;
