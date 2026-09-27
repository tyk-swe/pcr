// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::field::WireValue;

pub(super) const KIND_END: u8 = 0;
pub(super) const KIND_NOP: u8 = 1;
pub(super) const KIND_MSS: u8 = 2;
pub(super) const KIND_WINDOW_SCALE: u8 = 3;
pub(super) const KIND_SACK_PERMITTED: u8 = 4;
pub(super) const KIND_SACK: u8 = 5;
pub(super) const KIND_TIMESTAMPS: u8 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tcp {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub reserved_bits: u8,
    pub flags: u16,
    pub window: u16,
    pub checksum: WireValue<u16>,
    pub urgent_pointer: u16,
    pub options: Vec<TcpOption>,
}

impl Tcp {
    pub const FIN: u16 = 0x001;
    pub const SYN: u16 = 0x002;
    pub const RST: u16 = 0x004;
    pub const ACK: u16 = 0x010;
}

impl Default for Tcp {
    fn default() -> Self {
        Self {
            source_port: 50_000,
            destination_port: 80,
            sequence: 0,
            acknowledgment: 0,
            reserved_bits: 0,
            flags: Self::SYN,
            window: 65_535,
            checksum: WireValue::Auto,
            urgent_pointer: 0,
            options: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SackBlock {
    pub left_edge: u32,
    pub right_edge: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpOption {
    End,
    Nop,
    Mss(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(Vec<SackBlock>),
    Timestamps {
        value: u32,
        echo_reply: u32,
    },
    /// Any other kind, or a standard kind with a nonstandard length;
    /// `data` is the option body after the kind and length bytes.
    Raw {
        kind: u8,
        data: Bytes,
    },
    /// Padding after EOL, or bytes that cannot decode as a TLV; always last.
    Trailing(Bytes),
}

impl TcpOption {
    pub fn kind(&self) -> Option<u8> {
        Some(match self {
            Self::End => KIND_END,
            Self::Nop => KIND_NOP,
            Self::Mss(_) => KIND_MSS,
            Self::WindowScale(_) => KIND_WINDOW_SCALE,
            Self::SackPermitted => KIND_SACK_PERMITTED,
            Self::Sack(_) => KIND_SACK,
            Self::Timestamps { .. } => KIND_TIMESTAMPS,
            Self::Raw { kind, .. } => *kind,
            Self::Trailing(_) => return None,
        })
    }
}
