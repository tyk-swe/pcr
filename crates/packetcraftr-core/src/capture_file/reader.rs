// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Seek};

use crate::budget::Cancellation;
use crate::frame::Frame;

use super::classic::{PcapState, pcap_layout, read_next_pcap_record, read_pcap_header};
use super::error::Error;
use super::format::{Endianness, Format};
use super::header::{CaptureHeader, Interface, PcapNgOption, Section};
use super::limits::ReaderLimits;
use super::pcapng::{PcapNgState, read_next_pcapng_record, read_section_header_after_type};
use super::record::{CaptureRecord, MetadataBlockKind, RecordKind};
use super::wire::{PCAPNG_SECTION_HEADER, read_exact_or_eof};

pub(super) const DECLARED_FCS: &str = "declared frame check sequence";

pub(super) enum ReaderState {
    Pcap(PcapState),
    PcapNg(PcapNgState),
}

/// Streaming capture reader; construction consumes only the container header.
pub struct Reader<R> {
    inner: R,
    state: ReaderState,
    header: CaptureHeader,
    interfaces: Vec<Interface>,
    declares_fcs: bool,
    limits: ReaderLimits,
    scratch: Vec<u8>,
    finished: bool,
    cancellation: Option<Cancellation>,
    deadline: Option<std::sync::Arc<crate::budget::Deadline>>,
}

impl<R: Read> Reader<R> {
    pub fn new(inner: R) -> Result<Self, Error> {
        Self::with_limits(inner, ReaderLimits::default())
    }

    pub fn with_limits(mut inner: R, limits: ReaderLimits) -> Result<Self, Error> {
        let max_size = limits.max_size;
        let max_total_interfaces = limits.max_total_interfaces;
        let mut scratch = Vec::new();
        let mut magic = [0_u8; 4];
        if !read_exact_or_eof(&mut inner, &mut magic, "capture magic")? {
            return Err(Error::EmptyInput);
        }

        let (state, header) = match magic {
            PCAPNG_SECTION_HEADER => {
                let header = read_section_header_after_type(&mut inner, max_size, &mut scratch)?;
                let section = Section {
                    index: 0,
                    endianness: header.endianness,
                    major: header.major,
                    minor: header.minor,
                    length: header.length,
                    options: header.options.clone(),
                    raw: header.raw.clone(),
                };
                (
                    ReaderState::PcapNg(PcapNgState::new(header)),
                    CaptureHeader::PcapNg(section),
                )
            }
            magic => {
                let Some((endianness, precision)) = pcap_layout(magic) else {
                    return Err(Error::UnrecognizedFormat { magic });
                };
                let (state, header) = read_pcap_header(&mut inner, magic, endianness, precision)?;
                (ReaderState::Pcap(state), CaptureHeader::Pcap(header))
            }
        };

        let interfaces = match &state {
            ReaderState::Pcap(state) => vec![state.interface()],
            ReaderState::PcapNg(_) => Vec::new(),
        };
        if interfaces.len() > max_total_interfaces {
            return Err(Error::TotalInterfaceLimit {
                limit: max_total_interfaces,
            });
        }

        let declares_fcs = matches!(&header, CaptureHeader::Pcap(header) if header.declares_fcs());
        Ok(Self {
            inner,
            state,
            header,
            interfaces,
            declares_fcs,
            limits,
            scratch,
            finished: false,
            cancellation: None,
            deadline: None,
        })
    }

    #[must_use]
    pub fn with_cancellation(mut self, cancellation: Cancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    /// Construction reads a header, so callers also gate before and after constructing a reader.
    #[must_use]
    pub fn with_deadline(mut self, deadline: std::sync::Arc<crate::budget::Deadline>) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub(crate) fn deadline(&self) -> Option<std::sync::Arc<crate::budget::Deadline>> {
        self.deadline.clone()
    }

    pub(crate) fn replace_deadline(
        &mut self,
        deadline: Option<std::sync::Arc<crate::budget::Deadline>>,
    ) {
        self.deadline = deadline;
    }

    fn check_interrupted(&self) -> Result<(), Error> {
        if let Some(signal) = &self.cancellation {
            signal.check()?;
        }
        if let Some(deadline) = &self.deadline {
            deadline.enforce()?;
        }
        Ok(())
    }

    pub fn format(&self) -> Format {
        self.header.format()
    }

    pub fn endianness(&self) -> Endianness {
        match &self.state {
            ReaderState::Pcap(state) => state.endianness(),
            ReaderState::PcapNg(state) => state.endianness(),
        }
    }

    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    pub fn header(&self) -> &CaptureHeader {
        &self.header
    }

    /// Fails with [`Error::TransformMetadata`] when the header or an interface read so far
    /// declares a frame check sequence that frames still carry, which a PCAPNG re-encoding
    /// without that declaration would expose as payload.
    pub fn refuse_declared_fcs(&self) -> Result<(), Error> {
        if self.declares_fcs {
            return Err(Error::TransformMetadata(DECLARED_FCS));
        }
        Ok(())
    }

    pub(super) fn declares_fcs(&self) -> bool {
        self.declares_fcs
    }

    pub fn next_record(&mut self) -> Result<Option<CaptureRecord>, Error> {
        if self.finished {
            return Ok(None);
        }
        let result = self.read_record();
        match result {
            Ok(record) => {
                if record.is_none() {
                    self.finished = true;
                }
                Ok(record)
            }
            Err(error) => {
                self.finished = true;
                Err(error)
            }
        }
    }

    fn read_record(&mut self) -> Result<Option<CaptureRecord>, Error> {
        self.check_interrupted()?;
        let record = match &mut self.state {
            ReaderState::Pcap(state) => {
                read_next_pcap_record(&mut self.inner, state, self.limits.max_size)
            }
            ReaderState::PcapNg(state) => read_next_pcapng_record(
                &mut self.inner,
                state,
                &mut self.interfaces,
                &self.limits,
                &mut self.scratch,
            ),
        }?;
        self.check_interrupted()?;
        if let Some(CaptureRecord {
            kind: RecordKind::Metadata(MetadataBlockKind::InterfaceDescription { options, .. }),
            ..
        }) = &record
            && options.iter().any(PcapNgOption::declares_fcs)
        {
            self.declares_fcs = true;
        }
        Ok(record)
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, Error> {
        while let Some(record) = self.next_record()? {
            if let Some(frame) = record.frame {
                return Ok(Some(frame));
            }
        }
        Ok(None)
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Iterator for Reader<R> {
    type Item = Result<Frame, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_frame() {
            Ok(Some(frame)) => Some(Ok(frame)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
}

impl<R: Read + Seek> Reader<R> {
    pub fn rewind(&mut self) -> Result<(), Error> {
        self.check_interrupted()?;
        self.finished = true;
        self.inner.rewind()?;
        let fresh = Reader::with_limits(&mut self.inner, self.limits)?;
        self.state = fresh.state;
        self.header = fresh.header;
        self.interfaces = fresh.interfaces;
        self.declares_fcs = fresh.declares_fcs;
        self.scratch = fresh.scratch;
        self.finished = false;
        self.check_interrupted()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture_file::{Limits, TimestampResolution, Writer, rewrite, select};
    use crate::error::Classified;
    use crate::frame::LinkType;
    use std::io::{self, Cursor};
    use std::time::UNIX_EPOCH;

    struct CancelOnRead {
        input: Cursor<Vec<u8>>,
        signal: Cancellation,
        armed: bool,
    }

    impl Read for CancelOnRead {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let result = self.input.read(bytes);
            if self.armed {
                self.signal.cancel();
            }
            result
        }
    }

    #[test]
    fn cancellation_during_packet_metadata_or_eof_cannot_be_copied_or_complete() {
        for format in [Format::Pcap, Format::PcapNg] {
            for has_frame in [false, true] {
                let mut bytes = Vec::new();
                let mut writer = Writer::new(&mut bytes, format, LinkType::IPV4).unwrap();
                if has_frame {
                    writer
                        .write_frame(&Frame::new(UNIX_EPOCH, LinkType::IPV4, vec![0; 20]).unwrap())
                        .unwrap();
                }
                writer.flush().unwrap();
                drop(writer);
                for selecting in [false, true] {
                    let signal = Cancellation::default();
                    let input = CancelOnRead {
                        input: Cursor::new(bytes.clone()),
                        signal: signal.clone(),
                        armed: false,
                    };
                    let mut reader = Reader::new(input).unwrap().with_cancellation(signal);
                    reader.get_mut().armed = true;
                    let header_length = reader.header().raw().len();
                    let mut output = Vec::new();
                    let classification = if selecting {
                        select(&mut reader, &mut output, Limits::default(), |_, _| {
                            panic!("cancelled records cannot reach the selection predicate")
                        })
                        .unwrap_err()
                        .classification()
                    } else {
                        rewrite(&mut reader, &mut output, Limits::default())
                            .unwrap_err()
                            .classification()
                    };
                    assert_eq!(classification.code, "io.cancelled");
                    assert_eq!(output.len(), header_length);
                    assert!(reader.next_record().unwrap().is_none());
                }
            }
        }
    }

    #[test]
    fn declared_fcs_comes_from_the_classic_header_or_a_read_pcapng_interface() {
        let mut classic = Vec::new();
        Writer::pcap(&mut classic, LinkType::IPV4)
            .unwrap()
            .flush()
            .unwrap();
        assert!(
            Reader::new(Cursor::new(&classic))
                .unwrap()
                .refuse_declared_fcs()
                .is_ok()
        );
        classic[20..24].copy_from_slice(&(0x2400_0000 | LinkType::IPV4.0).to_le_bytes());
        assert!(matches!(
            Reader::new(Cursor::new(&classic))
                .unwrap()
                .refuse_declared_fcs(),
            Err(Error::TransformMetadata(DECLARED_FCS))
        ));

        let mut writer = Writer::pcapng(Vec::new()).unwrap();
        writer.add_interface(LinkType::IPV4).unwrap();
        writer
            .add_interface_description_with_options(
                Interface {
                    link_type: LinkType::IPV4,
                    snap_len: 65535,
                    timestamp_resolution: TimestampResolution::Decimal(9),
                    timestamp_offset: 0,
                },
                &[PcapNgOption {
                    code: 13,
                    value: bytes::Bytes::from_static(&[4]),
                }],
            )
            .unwrap();
        let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
        assert!(reader.refuse_declared_fcs().is_ok());
        reader.next_record().unwrap().unwrap();
        assert!(reader.refuse_declared_fcs().is_ok());
        reader.next_record().unwrap().unwrap();
        assert!(reader.refuse_declared_fcs().is_err());
        reader.rewind().unwrap();
        assert!(reader.refuse_declared_fcs().is_ok());
    }

    #[test]
    fn a_declared_fcs_needs_a_nonzero_length_in_either_format() {
        let mut classic = Vec::new();
        Writer::pcap(&mut classic, LinkType::IPV4)
            .unwrap()
            .flush()
            .unwrap();
        for (high_bits, declared) in [
            (0x0000_0000_u32, false),
            (0x0400_0000, false),
            (0x5000_0000, false),
            (0x0100_0000, false),
            (0x0008_0000, false),
            (0x0800_0000, false),
            (0x1400_0000, true),
            (0x2400_0000, true),
            (0xf400_0000, true),
            (0x5500_0000, true),
        ] {
            classic[20..24].copy_from_slice(&(high_bits | LinkType::IPV4.0).to_le_bytes());
            let reader = Reader::new(Cursor::new(&classic)).unwrap();
            assert_eq!(
                reader.refuse_declared_fcs().is_err(),
                declared,
                "network {high_bits:#010x}"
            );
        }

        for (value, declared) in [
            (&[0_u8][..], false),
            (&[4], true),
            (&[255], true),
            (&[], true),
            (&[0, 0], true),
        ] {
            let mut writer = Writer::pcapng(Vec::new()).unwrap();
            writer
                .add_interface_description_with_options(
                    Interface {
                        link_type: LinkType::IPV4,
                        snap_len: 65535,
                        timestamp_resolution: TimestampResolution::Decimal(9),
                        timestamp_offset: 0,
                    },
                    &[PcapNgOption {
                        code: 13,
                        value: bytes::Bytes::copy_from_slice(value),
                    }],
                )
                .unwrap();
            let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
            while reader.next_record().unwrap().is_some() {}
            assert_eq!(
                reader.refuse_declared_fcs().is_err(),
                declared,
                "if_fcslen {value:?}"
            );
        }
    }

    #[test]
    fn cancelled_reader_does_not_consume_another_record() {
        let mut bytes = Vec::new();
        Writer::pcap(&mut bytes, LinkType::IPV4)
            .unwrap()
            .flush()
            .unwrap();
        let signal = Cancellation::default();
        let mut reader = Reader::new(Cursor::new(bytes))
            .unwrap()
            .with_cancellation(signal.clone());
        let position = reader.get_ref().position();
        signal.cancel();
        assert!(matches!(reader.next_record(), Err(Error::Cancelled(_))));
        assert_eq!(reader.get_ref().position(), position);
    }
}
