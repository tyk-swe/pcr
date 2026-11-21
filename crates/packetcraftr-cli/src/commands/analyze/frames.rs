// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;

use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::frame::Frame;

use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;

pub(crate) fn read_frames(
    invocation: &crate::invocation::Invocation,
    path: &Path,
    arguments: OfflineCaptureLimitsArgs,
) -> Result<Vec<Frame>, CliError> {
    let max_frames = arguments.max_frames;
    let max_bytes = arguments.max_bytes;
    let limits = arguments.limits()?;
    let mut reader = crate::input::open_capture_file(&invocation.control, path, limits)?;
    let mut frames = Vec::new();
    let mut bytes: u64 = 0;
    while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
        bytes = bytes
            .checked_add(u64::try_from(frame.bytes().len()).unwrap_or(u64::MAX))
            .ok_or_else(|| CliError::new(Kind::Internal, "capture byte count overflowed"))?;
        frames.push(frame);
        if frames.len() as u64 > max_frames || bytes > max_bytes {
            return Err(CliError::from_classification(
                Classification::new(
                    packetcraftr_core::error::Code::CliCaptureLimit,
                    Kind::Usage,
                    Some("narrow the capture or raise the finite capture limits"),
                ),
                format!(
                    "capture exceeds its limits at {} frames and {bytes} bytes",
                    frames.len()
                ),
                Vec::new(),
            ));
        }
    }
    Ok(frames)
}
