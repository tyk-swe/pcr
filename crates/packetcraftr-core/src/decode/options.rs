// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::frame::Frame;

use crate::diagnostic::Diagnostic;
use crate::layout::PacketLayout;
use crate::packet::Packet;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub limits: crate::packet::Limits,
}

#[derive(Clone, Debug)]
pub struct DecodedPacket {
    pub packet: Packet,
    /// Owns the exact input bytes; read them through `Frame::bytes`.
    pub frame: Frame,
    pub layout: PacketLayout,
    pub diagnostics: Vec<Diagnostic>,
}
