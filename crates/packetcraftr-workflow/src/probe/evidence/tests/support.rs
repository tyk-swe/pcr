// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, SystemTime};

use packetcraftr_capture::{Frame, LinkType};
use packetcraftr_packet::{Packet, decode::Result as DecodedPacket, layout};

use super::super::{MatchedResponseEvidence, ResponseEvidence};

pub(super) struct NoMatchedResponses;

impl ResponseEvidence for NoMatchedResponses {
    fn response(&self) -> &DecodedPacket {
        unreachable!("fixture matches no responses, so none is ever inspected")
    }

    fn latency(&self) -> Duration {
        unreachable!("fixture matches no responses, so none is ever timed")
    }
}

impl MatchedResponseEvidence for NoMatchedResponses {
    fn request_index(&self) -> usize {
        unreachable!("fixture matches no responses, so none is ever attributed")
    }
}

pub(super) fn frame(bytes: &'static [u8]) -> Frame {
    Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).unwrap()
}

pub(super) fn decoded_at(offset: Duration, bytes: &'static [u8]) -> DecodedPacket {
    let frame = Frame::new(SystemTime::UNIX_EPOCH + offset, LinkType::RAW, bytes).unwrap();
    DecodedPacket {
        packet: Packet::new(),
        original: frame.bytes().clone(),
        frame,
        layout: layout::Packet::default(),
        diagnostics: Vec::new(),
    }
}
