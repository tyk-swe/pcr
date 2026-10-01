// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::selection::Selection;
use crate::command_options::CaptureReaderBoundsArgs;
use crate::command_options::FrameSelection;
use crate::command_options::OfflineCaptureLimitsArgs;
use packetcraftr_core as core;
use packetcraftr_core::capture_file as capture;
use packetcraftr_core::capture_file::Reader;
use std::io::{self, Write};

use super::normalize;

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
    let selection = FrameSelection::default();
    for (format, remaining) in [
        (capture::Format::PcapNg, 0),
        (capture::Format::PcapNg, 28),
        (capture::Format::PcapNg, 60),
        (capture::Format::PcapNg, usize::MAX),
        // The classic header, then the record header, then the flush.
        (capture::Format::Pcap, 0),
        (capture::Format::Pcap, 24),
        (capture::Format::Pcap, usize::MAX),
    ] {
        let mut reader = Reader::new(std::io::Cursor::new(&source)).unwrap();
        let error = normalize::run(
            &mut reader,
            OfflineCaptureLimitsArgs {
                max_frames: 1,
                max_bytes: 1000,
                reader: CaptureReaderBoundsArgs {
                    max_decoded_bytes: 256 * 1024 * 1024,
                    max_encoded_bytes: 256 * 1024 * 1024,
                    max_frame_bytes: 1000,
                    max_interfaces: 1,
                },
            },
            Selection {
                bounds: None,
                frames: &selection,
                decoding: None,
            },
            format,
            FailingOutput { remaining },
        )
        .unwrap_err();
        assert_eq!(error.exit_code(), 5);
        assert!(
            error
                .causes
                .iter()
                .any(|cause| cause.contains("fixture output")),
            "{format:?} {remaining}: {:?}",
            error.causes
        );
    }
}
