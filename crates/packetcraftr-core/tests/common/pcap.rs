// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Classic pcap fixtures shared by the capture contracts.

use std::time::SystemTime;

use packetcraftr_core::analysis::pcap::{PcapOptions, Writer};
use packetcraftr_core::frame::{Frame, LinkType};

pub(crate) fn frame_at(timestamp: SystemTime, link_type: LinkType, bytes: &[u8]) -> Frame {
    Frame::new(timestamp, link_type, bytes.to_vec()).expect("fixture frame must be valid")
}

pub(crate) fn pcap_bytes(options: PcapOptions, frames: &[Frame]) -> Vec<u8> {
    let mut writer = Writer::pcap_with_options(Vec::new(), LinkType::ETHERNET, options)
        .expect("fixture writer must initialize");
    for frame in frames {
        writer.write_frame(frame).expect("fixture frame must write");
    }
    writer.into_inner()
}
