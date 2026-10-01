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
fn classic_output_supports_only_microsecond_and_nanosecond_sources() {
    for resolution in [
        capture::TimestampResolution::Decimal(3),
        capture::TimestampResolution::Binary(10),
    ] {
        let error = open_classic_writer(Vec::new(), &description(resolution, 100), limits())
            .err()
            .expect("an unsupported resolution is refused");
        assert_eq!(
            error.classification.code,
            "packet.capture_transform_metadata"
        );
        assert!(error.message.contains("pcap cannot represent"), "{error:?}");
    }
    for resolution in [
        capture::TimestampResolution::Decimal(6),
        capture::TimestampResolution::Decimal(9),
    ] {
        open_classic_writer(Vec::new(), &description(resolution, 0), limits())
            .expect("supported resolutions open");
    }
}

#[test]
fn a_nanosecond_detail_never_rounds_into_a_microsecond_target() {
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
