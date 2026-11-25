// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use pcap::Error as PcapError;

use crate::{Error, interface::Id as InterfaceId, platform::common::pcap_api};
use packetcraftr_core::error::Source;

pub(in crate::platform) fn map_open_error(interface: &InterfaceId, error: PcapError) -> Error {
    let diagnostic = error.to_string();
    pcap_api::map_open_error(
        "libpcap",
        "grant capture privileges (for example CAP_NET_RAW on Linux or BPF access on macOS)",
        interface,
        &diagnostic,
        Some(Source::new(error)),
    )
}

pub(in crate::platform) fn map_send_error(interface: &InterfaceId, error: PcapError) -> Error {
    let diagnostic = error.to_string();
    pcap_api::map_send_error(
        "libpcap",
        "grant link-layer injection privileges",
        interface,
        &diagnostic,
        Some(Source::new(error)),
    )
}
