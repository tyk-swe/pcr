// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::io::Write;

use packetcraftr_core::capture_file::{Error, Format, Interface, Writer, compression};
use packetcraftr_core::frame::{Frame, LinkType};

use crate::errors::CliError;

pub(crate) struct CaptureWriter<W, K> {
    writer: Writer<W>,
    interface_map: BTreeMap<K, u32>,
}

pub(crate) type LinkCaptureWriter<W> = CaptureWriter<W, LinkType>;

pub(crate) type SourceCaptureWriter<W> = CaptureWriter<W, Option<u32>>;

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

impl<W: Write, K: Copy + Ord> CaptureWriter<W, K> {
    pub(crate) fn new(writer: Writer<W>) -> Self {
        Self {
            writer,
            interface_map: BTreeMap::new(),
        }
    }

    /// Classic PCAP carries no interface IDs, so it maps to `None`.
    fn map_interface(
        &mut self,
        key: K,
        register: impl FnOnce(&mut Writer<W>) -> Result<u32, Error>,
    ) -> Result<Option<u32>, Error> {
        if self.writer.format() == Format::Pcap {
            return Ok(None);
        }
        if let Some(output_id) = self.interface_map.get(&key) {
            return Ok(Some(*output_id));
        }
        let output_id = register(&mut self.writer)?;
        self.interface_map.insert(key, output_id);
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
    pub(crate) fn add_link_type(&mut self, link_type: LinkType) -> Result<Option<u32>, Error> {
        self.map_interface(link_type, |writer| writer.add_interface(link_type))
    }

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
