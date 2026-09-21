// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture writer state shared by command renderers.

use std::io::Write;

use packetcraftr_core::analysis::pcap::{Error, Format, Interface, Writer, compression};
use packetcraftr_core::frame::{Frame, LinkType};

use crate::errors::CliError;

/// A streaming writer plus the interface mapping its callers register.
///
/// `K` is the identity each output interface is mapped by, so a writer only
/// exposes the registration its format was opened for.
pub(crate) struct CaptureWriter<W, K> {
    writer: Writer<W>,
    interface_map: Vec<(K, u32)>,
}

/// Maps PCAPNG interfaces by link type as generated frames arrive.
pub(crate) type LinkCaptureWriter<W> = CaptureWriter<W, LinkType>;

/// Maps declared interface descriptions into a newly generated capture.
pub(crate) type SourceCaptureWriter<W> = CaptureWriter<W, Option<u32>>;

/// Finishes an initialized compressor after capture processing, retaining the
/// processing failure as primary when finalization also fails.
pub(crate) fn finish_compressed_output<W: Write, T>(
    result: Result<T, CliError>,
    output: compression::Output<W>,
) -> Result<T, CliError> {
    let finished = output.finish().map_err(CliError::classified);
    match (result, finished) {
        (Err(primary), Err(secondary)) => {
            Err(primary.with_secondary("output finalization", secondary))
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(value), Ok(_)) => Ok(value),
    }
}

impl<W: Write, K: Copy + PartialEq> CaptureWriter<W, K> {
    pub(crate) fn new(writer: Writer<W>) -> Self {
        Self {
            writer,
            interface_map: Vec::new(),
        }
    }

    /// Resolves the output interface ID for `key`, registering it once.
    ///
    /// Classic PCAP carries no interface IDs, so it maps to `None`.
    fn map_interface(
        &mut self,
        key: K,
        register: impl FnOnce(&mut Writer<W>) -> Result<u32, Error>,
    ) -> Result<Option<u32>, Error> {
        if self.writer.format() == Format::Pcap {
            return Ok(None);
        }
        if let Some((_, output_id)) = self.interface_map.iter().find(|(mapped, _)| *mapped == key) {
            return Ok(Some(*output_id));
        }
        let output_id = register(&mut self.writer)?;
        self.interface_map.push((key, output_id));
        Ok(Some(output_id))
    }

    pub(crate) fn flush(&mut self) -> Result<(), Error> {
        self.writer.flush()
    }

    pub(crate) fn into_inner(self) -> W {
        self.writer.into_inner()
    }
}

impl<W: Write> LinkCaptureWriter<W> {
    /// Declares a link type before the first frame when callers need eager
    /// validation, and returns its PCAPNG interface ID.
    pub(crate) fn add_link_type(&mut self, link_type: LinkType) -> Result<Option<u32>, Error> {
        self.map_interface(link_type, |writer| writer.add_interface(link_type))
    }

    /// Writes a generated frame, mapping each PCAPNG link type once.
    pub(crate) fn write_link_mapped(&mut self, mut frame: Frame) -> Result<(), Error> {
        frame.interface = self.add_link_type(frame.link_type)?;
        self.writer.write_frame(&frame)
    }
}

impl<W: Write> SourceCaptureWriter<W> {
    pub(crate) fn add_source_interface(
        &mut self,
        source_id: Option<u32>,
        description: Interface,
    ) -> Result<Option<u32>, Error> {
        self.map_interface(source_id, |writer| {
            writer.add_interface_description(description)
        })
    }

    pub(crate) fn write_source_frame(
        &mut self,
        source_id: Option<u32>,
        description: Interface,
        mut frame: Frame,
    ) -> Result<(), Error> {
        frame.interface = self.add_source_interface(source_id, description)?;
        self.writer.write_frame(&frame)
    }
}

#[cfg(test)]
mod tests {

    use std::io::{self, Cursor};
    use std::time::UNIX_EPOCH;

    use packetcraftr_core::analysis::pcap::{Limits, PcapOptions, Reader, TimestampResolution};
    use packetcraftr_core::error::{Classification, Kind};

    use super::*;

    fn frame(link_type: LinkType, byte: u8) -> Frame {
        Frame::new(UNIX_EPOCH, link_type, vec![byte]).expect("bounded frame")
    }

    fn interface(link_type: LinkType, snap_len: u32) -> Interface {
        Interface {
            link_type,
            snap_len,
            timestamp_resolution: TimestampResolution::Decimal(9),
            timestamp_offset: 0,
        }
    }

    fn read(bytes: Vec<u8>) -> (Vec<Frame>, Vec<Interface>) {
        let mut reader = Reader::new(Cursor::new(bytes)).expect("capture opens");
        let mut frames = Vec::new();
        while let Some(frame) = reader.next_frame().expect("capture record") {
            frames.push(frame);
        }
        (frames, reader.interfaces().to_vec())
    }

    #[test]
    fn output_finalization_failure_remains_secondary_to_processing_failure() {
        struct FailingFlush;

        impl Write for FailingFlush {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("fixture flush failed"))
            }
        }

        let primary = CliError::from_classification(
            Classification::new("policy.fixture", Kind::Policy, None),
            "processing failed",
            vec!["processing cause".to_owned()],
        );
        let output = compression::Output::new(FailingFlush, compression::Format::None)
            .expect("plain output opens");

        let error = finish_compressed_output::<_, ()>(Err(primary), output)
            .expect_err("both processing and finalization fail");

        assert_eq!(error.classification.code, "policy.fixture");
        assert_eq!(error.classification.kind, Kind::Policy);
        assert_eq!(
            error.message,
            "processing failed; output finalization also failed: None capture compression I/O failed: fixture flush failed"
        );
        assert_eq!(
            error.causes,
            [
                "processing cause",
                "None capture compression I/O failed: fixture flush failed",
                "fixture flush failed"
            ]
        );
    }

    #[test]
    fn pcapng_link_mapping_is_stable() {
        let writer = Writer::pcapng(Vec::new()).expect("PCAPNG writer");
        let mut output = LinkCaptureWriter::new(writer);

        assert_eq!(output.add_link_type(LinkType::ETHERNET).unwrap(), Some(0));
        assert_eq!(output.add_link_type(LinkType::ETHERNET).unwrap(), Some(0));
        output
            .write_link_mapped(frame(LinkType::ETHERNET, 1))
            .expect("Ethernet frame");
        output
            .write_link_mapped(frame(LinkType::IPV4, 2))
            .expect("IPv4 frame");
        output.flush().expect("memory writer flushes");

        let (frames, interfaces) = read(output.into_inner());
        assert_eq!(
            (frames[0].interface, frames[1].interface),
            (Some(0), Some(1))
        );
        assert_eq!(
            interfaces
                .iter()
                .map(|description| description.link_type)
                .collect::<Vec<_>>(),
            [LinkType::ETHERNET, LinkType::IPV4]
        );
    }

    #[test]
    fn pcapng_source_mapping_uses_source_identity_not_repeated_descriptions() {
        let writer = Writer::pcapng(Vec::new()).expect("PCAPNG writer");
        let mut output = SourceCaptureWriter::new(writer);
        output
            .write_source_frame(
                Some(7),
                interface(LinkType::ETHERNET, 64),
                frame(LinkType::ETHERNET, 1),
            )
            .expect("first source frame");
        output
            .write_source_frame(
                Some(7),
                interface(LinkType::ETHERNET, 128),
                frame(LinkType::ETHERNET, 2),
            )
            .expect("repeated source frame");
        output
            .write_source_frame(
                None,
                interface(LinkType::IPV4, 256),
                frame(LinkType::IPV4, 3),
            )
            .expect("source without an ID");

        let (frames, interfaces) = read(output.into_inner());
        assert_eq!(
            frames
                .iter()
                .map(|frame| frame.interface)
                .collect::<Vec<_>>(),
            [Some(0), Some(0), Some(1)]
        );
        assert_eq!(interfaces[0].snap_len, 64);
        assert_eq!(interfaces[1].link_type, LinkType::IPV4);
    }

    #[test]
    fn classic_pcap_has_no_interface_ids_and_enforces_stream_limits() {
        let writer = Writer::pcap_with_options(
            Vec::new(),
            LinkType::ETHERNET,
            PcapOptions {
                stream_limits: Limits {
                    max_frames: 1,
                    max_bytes: 1,
                },
                ..PcapOptions::default()
            },
        )
        .expect("classic PCAP writer");
        let mut output = LinkCaptureWriter::new(writer);

        assert_eq!(output.add_link_type(LinkType::ETHERNET).unwrap(), None);
        output
            .write_link_mapped(frame(LinkType::ETHERNET, 1))
            .expect("first frame fits");
        assert!(matches!(
            output.write_link_mapped(frame(LinkType::ETHERNET, 2)),
            Err(Error::FrameLimitExceeded {
                actual: 2,
                limit: 1
            })
        ));

        let (frames, _) = read(output.into_inner());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].interface, None);
    }
}
