// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::command_options::CaptureReaderBoundsArgs;

fn limits() -> OfflineCaptureLimitsArgs {
    OfflineCaptureLimitsArgs {
        max_frames: 10,
        max_bytes: 1000,
        reader: CaptureReaderBoundsArgs {
            max_decoded_bytes: 256 * 1024 * 1024,
            max_encoded_bytes: 256 * 1024 * 1024,
            max_frame_bytes: 1000,
            max_interfaces: 1,
        },
    }
}

fn description(resolution: capture::TimestampResolution, snap_len: u32) -> capture::Interface {
    capture::Interface {
        link_type: core::frame::LinkType::IPV4,
        snap_len,
        timestamp_resolution: resolution,
        timestamp_offset: 0,
    }
}

#[test]
fn ns_detail_never_rounds_microsecond_target() {
    let mut writer = open_classic_writer(
        Vec::new(),
        &description(capture::TimestampResolution::Decimal(6), 100),
        limits(),
    )
    .unwrap();
    let frame = core::frame::Frame::new(
        std::time::UNIX_EPOCH + std::time::Duration::new(1, 1_500),
        core::frame::LinkType::IPV4,
        vec![1],
    )
    .unwrap();
    let error = CliError::classified(writer.write_frame(&frame).unwrap_err());
    assert_eq!(error.exit_code(), 3);
    assert!(error.message.contains("microsecond timestamp precision"));
}
