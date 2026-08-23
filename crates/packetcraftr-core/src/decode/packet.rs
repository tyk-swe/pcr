// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::Packet;
use crate::diagnostic::Diagnostic;
use crate::frame::Frame;
use crate::layout::PacketLayout;

#[derive(Clone, Debug)]
pub struct DecodedPacket {
    pub packet: Packet,
    pub original: Bytes,
    pub frame: Frame,
    pub layout: PacketLayout,
    pub diagnostics: Vec<Diagnostic>,
}
