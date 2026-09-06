// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use super::*;
use crate::command_options::CaptureReaderBoundsArgs;

struct FailingOutput {
    remaining: usize,
}

impl Write for FailingOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("fixture output write failed"));
        }
        let accepted = bytes.len().min(self.remaining);
        self.remaining -= accepted;
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("fixture output flush failed"))
    }
}

#[test]
fn normalized_output_propagates_header_interface_packet_and_flush_failures() {
    let frame =
        core::frame::Frame::new(std::time::UNIX_EPOCH, core::frame::LinkType::IPV4, vec![1])
            .unwrap();
    let mut source = capture::Writer::pcap(Vec::new(), frame.link_type).unwrap();
    source.write_frame(&frame).unwrap();
    let source = source.into_inner();
    for remaining in [0, 28, 60, usize::MAX] {
        let mut reader = Reader::new(std::io::Cursor::new(&source)).unwrap();
        let error = normalize_capture(
            &mut reader,
            OfflineCaptureLimitsArgs {
                max_frames: 1,
                max_bytes: 1000,
                reader: CaptureReaderBoundsArgs {
                    max_frame_bytes: 1000,
                    max_interfaces: 1,
                },
            },
            None,
            FailingOutput { remaining },
        )
        .unwrap_err();
        assert_eq!(error.exit_code(), 5);
        assert!(error.message.contains("fixture output"));
    }
}
