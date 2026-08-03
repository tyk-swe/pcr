// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Read;

use crate::{Frame, LinkType};

use super::classic::{read_next_pcap_frame, read_pcap_header};
use super::error::Error;
use super::model::{
    Endianness, Format, Interface, ReaderOptions, TimestampPrecision, TimestampResolution,
};
use super::pcapng::{PcapNgState, read_next_pcapng_frame, read_section_header_after_type};
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
/// Construction consumes only the container header.  Each call to
/// [`next_frame`](Self::next_frame) then reads at most one packet plus any
/// intervening metadata blocks.
pub struct Reader<R> {
    inner: R,
    state: ReaderState,
    interfaces: Vec<Interface>,
    options: ReaderOptions,
    pub(super) max_total_interfaces: usize,
    scratch: Vec<u8>,
    finished: bool,
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

        let state = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => read_pcap_header(
                &mut inner,
                Endianness::Little,
                TimestampPrecision::Microseconds,
            )?,
            [0xa1, 0xb2, 0xc3, 0xd4] => read_pcap_header(
                &mut inner,
                Endianness::Big,
                TimestampPrecision::Microseconds,
            )?,
            [0x4d, 0x3c, 0xb2, 0xa1] => read_pcap_header(
                &mut inner,
                Endianness::Little,
                TimestampPrecision::Nanoseconds,
            )?,
            [0xa1, 0xb2, 0x3c, 0x4d] => {
                read_pcap_header(&mut inner, Endianness::Big, TimestampPrecision::Nanoseconds)?
            }
            PCAPNG_SECTION_HEADER => {
                let header = read_section_header_after_type(&mut inner, max_size, &mut scratch)?;
                ReaderState::PcapNg(PcapNgState::new(header))
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
            interfaces,
            options,
            max_total_interfaces,
            scratch,
            finished: false,
        })
    }

    /// Returns the detected capture format.
    pub fn format(&self) -> Format {
        match self.state {
            ReaderState::Pcap { .. } => Format::Pcap,
            ReaderState::PcapNg(_) => Format::PcapNg,
        }
    }

    /// Returns the capture byte order.
    pub fn endianness(&self) -> Endianness {
        match self.state {
            ReaderState::Pcap { endianness, .. } => endianness,
            ReaderState::PcapNg(ref state) => state.endianness(),
        }
    }

    /// Returns the configured packet/block limit.
    pub fn size_limit(&self) -> usize {
        self.options.max_size
    }

    /// Interface metadata parsed so far.
    ///
    /// Classic PCAP exposes its single global interface immediately. PCAPNG
    /// descriptions are appended while [`next_frame`](Self::next_frame)
    /// advances the stream, before any frame that references them is returned.
    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    /// Reads the next frame, or `None` after a clean end of file.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, Error> {
        if self.finished {
            return Ok(None);
        }

        let result = match &mut self.state {
            ReaderState::Pcap {
                endianness,
                precision,
                snap_len,
                link_type,
            } => read_next_pcap_frame(
                &mut self.inner,
                *endianness,
                *precision,
                *snap_len,
                *link_type,
                self.options.max_size,
            ),
            ReaderState::PcapNg(state) => read_next_pcapng_frame(
                &mut self.inner,
                state,
                &mut self.interfaces,
                &self.options,
                &mut self.scratch,
            ),
        };

        match result {
            Ok(frame) => {
                if frame.is_none() {
                    self.finished = true;
                }
                Ok(frame)
            }
            Err(error) => {
                self.finished = true;
                Err(error)
            }
        }
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
