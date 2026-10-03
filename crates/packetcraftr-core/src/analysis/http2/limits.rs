// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::{Constraint, Error as AnalysisError};
use super::Error;

pub const MAX_FRAMES: u64 = 1_000_000;
pub const MAX_STREAMS: usize = 100_000;
pub const MAX_ACTIVE_STREAMS: usize = 4_096;
pub const MAX_FRAME_BYTES: usize = 16_777_215;
pub const MAX_HEADER_BLOCK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_HEADER_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_HEADERS: usize = 16_384;
pub const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CONTINUATIONS: usize = 16_384;
pub const MAX_PENDING_SETTINGS: usize = 4_096;
pub const MAX_BODY_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_frames: u64,
    pub max_streams: usize,
    pub max_active_streams: usize,
    pub max_frame_bytes: usize,
    pub max_header_block_bytes: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub max_table_bytes: usize,
    pub max_continuations: usize,
    pub max_pending_settings: usize,
    pub max_body_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: 100_000,
            max_streams: 4_096,
            max_active_streams: 128,
            max_frame_bytes: 1024 * 1024,
            max_header_block_bytes: 64 * 1024,
            max_header_bytes: 64 * 1024,
            max_headers: 256,
            max_table_bytes: 64 * 1024,
            max_continuations: 256,
            max_pending_settings: 64,
            max_body_bytes: 16 * 1024 * 1024,
        }
    }
}
impl Limits {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        for (field, value, maximum) in [
            ("max_frames", self.max_frames, MAX_FRAMES),
            ("max_streams", self.max_streams as u64, MAX_STREAMS as u64),
            (
                "max_active_streams",
                self.max_active_streams as u64,
                MAX_ACTIVE_STREAMS as u64,
            ),
            (
                "max_frame_bytes",
                self.max_frame_bytes as u64,
                MAX_FRAME_BYTES as u64,
            ),
            (
                "max_header_block_bytes",
                self.max_header_block_bytes as u64,
                MAX_HEADER_BLOCK_BYTES as u64,
            ),
            (
                "max_header_bytes",
                self.max_header_bytes as u64,
                MAX_HEADER_BYTES as u64,
            ),
            ("max_headers", self.max_headers as u64, MAX_HEADERS as u64),
            (
                "max_table_bytes",
                self.max_table_bytes as u64,
                MAX_TABLE_BYTES as u64,
            ),
            (
                "max_continuations",
                self.max_continuations as u64,
                MAX_CONTINUATIONS as u64,
            ),
            (
                "max_pending_settings",
                self.max_pending_settings as u64,
                MAX_PENDING_SETTINGS as u64,
            ),
            ("max_body_bytes", self.max_body_bytes, MAX_BODY_BYTES),
        ] {
            check(field, value, maximum)?;
        }
        Ok(())
    }
    pub(crate) fn hpack(&self) -> crate::protocol::application::http2::hpack::Limits {
        crate::protocol::application::http2::hpack::Limits {
            max_block_bytes: self.max_header_block_bytes,
            max_header_bytes: self.max_header_bytes,
            max_headers: self.max_headers,
            max_table_bytes: self.max_table_bytes,
        }
    }
}
fn check(field: &'static str, value: u64, maximum: u64) -> Result<(), Error> {
    let reason = if value == 0 {
        Constraint::NonZero
    } else if value > maximum {
        Constraint::AtMost { maximum }
    } else {
        return Ok(());
    };
    Err(AnalysisError::InvalidLimit {
        field,
        value,
        reason,
    }
    .into())
}
