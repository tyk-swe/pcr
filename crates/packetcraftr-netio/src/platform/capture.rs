// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(pcap_backend)]
mod libpcap;
#[cfg(npcap_backend)]
mod npcap;

#[cfg(pcap_backend)]
pub(crate) use libpcap::{open_capture as open, timestamp_types};
#[cfg(npcap_backend)]
pub(crate) use npcap::{open_capture as open, timestamp_types};
