// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TCP diagnostic scan modes: the flag combination each raw probe carries and
//! the acknowledgment identity that binds a bare reset to its probe.

use super::Error;

const MAX_CUSTOM_FLAGS: u16 = 0x1ff;
const ACKNOWLEDGMENT_IDENTITY: u32 = 0x5043_5201;

/// Which TCP segment a raw scan sends to each scan endpoint.
///
/// `Custom` is observation-only: it never infers a port state, even when its
/// flags equal those of another mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TcpScan {
    #[default]
    Syn,
    Ack,
    Window,
    Fin,
    Null,
    Xmas,
    Maimon,
    Custom {
        flags: u16,
    },
}

impl TcpScan {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syn => "syn",
            Self::Ack => "ack",
            Self::Window => "window",
            Self::Fin => "fin",
            Self::Null => "null",
            Self::Xmas => "xmas",
            Self::Maimon => "maimon",
            Self::Custom { .. } => "custom",
        }
    }

    /// The TCP flag bits the probe carries.
    pub const fn flags(self) -> u16 {
        match self {
            Self::Syn => 0x002,
            Self::Ack | Self::Window => 0x010,
            Self::Fin => 0x001,
            Self::Null => 0x000,
            Self::Xmas => 0x029,
            Self::Maimon => 0x011,
            Self::Custom { flags } => flags,
        }
    }

    pub const fn is_syn(self) -> bool {
        matches!(self, Self::Syn)
    }

    pub fn validate(self) -> Result<(), Error> {
        match self {
            Self::Custom { flags } if flags > MAX_CUSTOM_FLAGS => Err(Error::InvalidLimit {
                field: "tcp_flags",
                value: u64::from(flags),
                reason: format!("must be within 0..={MAX_CUSTOM_FLAGS:#x}"),
            }),
            _ => Ok(()),
        }
    }

    /// The acknowledgment number a probe with `flags` carries: nonzero and
    /// distinct per sequence when ACK is set, so a bare reset binds to one
    /// probe, and zero otherwise.
    pub(super) fn acknowledgment(self, sequence: u64) -> u32 {
        if self.flags() & 0x010 != 0 {
            (sequence as u32).wrapping_add(ACKNOWLEDGMENT_IDENTITY)
        } else {
            0
        }
    }
}
