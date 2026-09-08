// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Read;

use crate::budget::Cancellation;
use crate::frame::{Frame, LinkType};

use super::classic::{read_next_pcap_record, read_pcap_header};
use super::error::Error;
use super::model::{
    CaptureHeader, CaptureRecord, Endianness, Format, Interface, ReaderOptions, Section,
    TimestampPrecision, TimestampResolution,
};
use super::pcapng::{PcapNgState, read_next_pcapng_record, read_section_header_after_type};
use super::wire::{PCAPNG_SECTION_HEADER, read_exact_or_eof};

pub(super) enum ReaderState {
    Pcap {
        endianness: Endianness,
        precision: TimestampPrecision,
        snap_len: u32,
        link_type: LinkType,
    },
    PcapNg(PcapNgState),
}

/// A streaming capture reader over any [`Read`] implementation.
///
/// Construction consumes only the container header. Use
/// [`next_record`](Self::next_record) when source structure matters;
/// [`next_frame`](Self::next_frame) is a packet-only adapter that consumes and
/// omits intervening metadata records from its return value.
pub struct Reader<R> {
    inner: R,
    state: ReaderState,
    header: CaptureHeader,
    interfaces: Vec<Interface>,
    options: ReaderOptions,
    scratch: Vec<u8>,
    finished: bool,
    cancellation: Option<Cancellation>,
}

fn wrap_pcap_header(
    value: (ReaderState, super::model::PcapHeader),
) -> (ReaderState, CaptureHeader) {
    (value.0, CaptureHeader::Pcap(value.1))
}

impl<R: Read> Reader<R> {
    /// Opens a capture with the default resource limits.
    pub fn new(inner: R) -> Result<Self, Error> {
        Self::with_options(inner, ReaderOptions::default())
    }

    /// Opens a capture with explicit resource limits.
    pub fn with_options(mut inner: R, options: ReaderOptions) -> Result<Self, Error> {
        let max_size = options.max_size;
        let max_total_interfaces = options.max_total_interfaces;
        let mut scratch = Vec::new();
        let mut magic = [0_u8; 4];
        if !read_exact_or_eof(&mut inner, &mut magic, "capture magic")? {
            return Err(Error::EmptyInput);
        }

        let (state, header) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => wrap_pcap_header(read_pcap_header(
                &mut inner,
                magic,
                Endianness::Little,
                TimestampPrecision::Microseconds,
            )?),
            [0xa1, 0xb2, 0xc3, 0xd4] => wrap_pcap_header(read_pcap_header(
                &mut inner,
                magic,
                Endianness::Big,
                TimestampPrecision::Microseconds,
            )?),
            [0x4d, 0x3c, 0xb2, 0xa1] => wrap_pcap_header(read_pcap_header(
                &mut inner,
                magic,
                Endianness::Little,
                TimestampPrecision::Nanoseconds,
            )?),
            [0xa1, 0xb2, 0x3c, 0x4d] => wrap_pcap_header(read_pcap_header(
                &mut inner,
                magic,
                Endianness::Big,
                TimestampPrecision::Nanoseconds,
            )?),
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
            unknown_magic => {
                return Err(Error::UnrecognizedFormat {
                    magic: unknown_magic,
                });
            }
        };

        let interfaces = match &state {
            ReaderState::Pcap {
                precision,
                snap_len,
                link_type,
                ..
            } => vec![Interface {
                link_type: *link_type,
                snap_len: *snap_len,
                timestamp_resolution: match precision {
                    TimestampPrecision::Microseconds => TimestampResolution::Decimal(6),
                    TimestampPrecision::Nanoseconds => TimestampResolution::Decimal(9),
                },
                timestamp_offset: 0,
            }],
            ReaderState::PcapNg(_) => Vec::new(),
        };
        if interfaces.len() > max_total_interfaces {
            return Err(Error::TotalInterfaceLimit {
                limit: max_total_interfaces,
            });
        }

        Ok(Self {
            inner,
            state,
            header,
            interfaces,
            options,
            scratch,
            finished: false,
            cancellation: None,
        })
    }

    /// Checks a cooperative stop signal before and after each source record,
    /// including metadata and EOF. An in-progress `Read` must return first.
    #[must_use]
    pub fn with_cancellation(mut self, cancellation: Cancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    /// Returns the detected capture format.
    pub fn format(&self) -> Format {
        self.header.format()
    }

    /// Returns the current byte order.
    ///
    /// For PCAPNG this starts with the first section and changes after a later
    /// section header is consumed.
    pub fn endianness(&self) -> Endianness {
        match self.state {
            ReaderState::Pcap { endianness, .. } => endianness,
            ReaderState::PcapNg(ref state) => state.endianness(),
        }
    }

    /// Interface metadata parsed so far.
    ///
    /// Classic PCAP exposes its single global interface immediately. PCAPNG
    /// descriptions are appended while [`next_frame`](Self::next_frame)
    /// advances the stream, before any frame that references them is returned.
    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    /// Returns the validated source header.
    pub fn header(&self) -> &CaptureHeader {
        &self.header
    }

    /// Reads the next source record, including metadata and validated bytes.
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
        if let Some(signal) = &self.cancellation {
            signal.check()?;
        }
        let record = match &mut self.state {
            ReaderState::Pcap {
                endianness,
                precision,
                snap_len,
                link_type,
            } => read_next_pcap_record(
                &mut self.inner,
                *endianness,
                *precision,
                *snap_len,
                *link_type,
                self.options.max_size,
            ),
            ReaderState::PcapNg(state) => read_next_pcapng_record(
                &mut self.inner,
                state,
                &mut self.interfaces,
                &self.options,
                &mut self.scratch,
            ),
        }?;
        if let Some(signal) = &self.cancellation {
            signal.check()?;
        }
        Ok(record)
    }

    /// Reads the next frame, consuming but not returning metadata records.
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

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use crate::analysis::pcap::{Limits, Writer, rewrite, select};
    use crate::error::Classified;
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
