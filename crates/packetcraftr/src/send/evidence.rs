// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Confirmed transmissions and their consistency with the terminal report.

use super::{Error, Report};
use crate::evidence::SentPacket;

/// One confirmed transmission inside a send.
#[derive(Clone, Debug)]
pub struct SentFrame {
    /// One-based pass over the packet set.
    pub pass: u32,
    /// Zero-based index of the packet within one expansion pass.
    pub index: u64,
    pub packet: SentPacket,
}

/// What a send publishes while it runs. Each event is answered before the
/// next frame is transmitted.
#[derive(Clone, Debug)]
pub enum Event {
    /// The provider confirmed this frame.
    Sent(SentFrame),
}

pub(super) fn validate(sent: &[SentFrame], report: &Report) -> Result<(), Error> {
    if u64::try_from(sent.len()).unwrap_or(u64::MAX) != report.stats.packets_completed {
        return Err(Error::IncoherentEvents {
            message: "sent events disagree with completion statistics".to_owned(),
        });
    }
    Ok(())
}
