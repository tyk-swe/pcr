// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Seek};
use std::sync::Arc;

use crate::budget::{Cancellation, Deadline};
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
    deadline: Option<Arc<Deadline>>,
}

impl<R: Read> Reader<R> {
    pub fn with_limits(inner: R, limits: ReaderLimits) -> Result<Self, Error> {
        Self::with_control(inner, limits, None)
    }

    pub fn with_control(
        inner: R,
        limits: ReaderLimits,
        control: Option<Arc<Deadline>>,
    ) -> Result<Self, Error> {
        if let Some(control) = &control {
            control.enforce()?;
        }
        let result = Self::read_header(inner, limits, control.clone());
        if let Some(control) = &control {
            control.enforce()?;
        }
        result
    }

    fn read_header(
        mut inner: R,
        limits: ReaderLimits,
        deadline: Option<Arc<Deadline>>,
    ) -> Result<Self, Error> {
        let max_size = limits.max_size;
        let max_total_interfaces = limits.max_total_interfaces;
        let mut scratch = Vec::new();
        let mut magic = [0_u8; 4];
        if !read_exact_or_eof(&mut inner, &mut magic, "capture magic")? {
            return Err(Error::EmptyInput);
        }

        let (state, header) = match magic {
            PCAPNG_SECTION_HEADER => {
                let header = read_section_header_after_type(
                    &mut inner,
                    max_size,
                    limits.max_options_per_block,
                    &mut scratch,
                )?;
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
            deadline,
        })
    }

    #[must_use]
    pub fn with_cancellation(mut self, cancellation: Cancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub(crate) fn deadline(&self) -> Option<Arc<Deadline>> {
        self.deadline.clone()
    }

    pub(crate) fn cancellation(&self) -> Option<Cancellation> {
        self.cancellation.clone()
    }

    pub(crate) fn replace_deadline(&mut self, deadline: Option<Arc<Deadline>>) {
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
        }
        .map_err(|error| self.check_interrupted().err().unwrap_or(error))?;
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
        self.finished = true;
        self.check_interrupted()?;
        self.inner.rewind().map_err(|error| {
            self.check_interrupted()
                .err()
                .unwrap_or_else(|| error.into())
        })?;
        self.check_interrupted()?;
        let control = Arc::new(
            Deadline::new(std::time::Duration::MAX)
                .with_parent(self.deadline.clone())
                .with_cancellation(self.cancellation.clone()),
        );
        let fresh = Reader::with_control(&mut self.inner, self.limits, Some(control))?;
        self.state = fresh.state;
        self.header = fresh.header;
        self.interfaces = fresh.interfaces;
        self.declares_fcs = fresh.declares_fcs;
        self.scratch = fresh.scratch;
        self.check_interrupted()?;
        self.finished = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
