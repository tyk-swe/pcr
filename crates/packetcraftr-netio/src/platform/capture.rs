// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(pcap_backend)]
pub(in crate::platform) mod libpcap;
#[cfg(npcap_backend)]
pub(in crate::platform) mod npcap;
