// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::SystemTime;

use packetcraftr::{capture, core, error};

#[test]
fn core_and_compatibility_paths_name_the_same_public_types() {
    let frame: Result<core::frame::Frame, core::frame::FrameError> =
        capture::Frame::new(SystemTime::UNIX_EPOCH, capture::LinkType::RAW, vec![1]);
    let frame = frame.unwrap();
    let direction: capture::Direction = core::frame::Direction::Unknown;
    let classification: error::Classification =
        core::error::Classification::new("test.topology", core::error::Kind::Internal, None);

    assert_eq!(frame.link_type, core::frame::LinkType::RAW);
    assert_eq!(direction, core::frame::Direction::Unknown);
    assert_eq!(classification.kind, error::Kind::Internal);
}
