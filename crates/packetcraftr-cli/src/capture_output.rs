// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private capture-output state shared by CLI commands and renderers.

use std::io::Write;

use packetcraftr::capture::{Error, Format, Frame, Interface, Limits, LinkType, Writer};

#[derive(Clone, Copy, Debug)]
struct LinkTypeMapping {
    link_type: LinkType,
    output_id: u32,
}

#[derive(Clone, Copy, Debug)]
struct SourceInterfaceMapping {
    source_id: Option<u32>,
    output_id: u32,
}

#[derive(Debug)]
enum InterfaceLifecycle {
    LinkTypes(Vec<LinkTypeMapping>),
    SourceInterfaces(Vec<SourceInterfaceMapping>),
}

/// A streaming writer plus its interface-mapping lifecycle.
pub(crate) struct CaptureOutput<W> {
    writer: Writer<W>,
    interfaces: InterfaceLifecycle,
}

impl<W: Write> CaptureOutput<W> {
    /// Maps PCAPNG interfaces by link type as generated frames arrive.
    pub(crate) fn link_mapped(writer: Writer<W>) -> Self {
        Self {
            writer,
            interfaces: InterfaceLifecycle::LinkTypes(Vec::new()),
        }
    }

    /// Copies exact source PCAPNG interface descriptions and remaps IDs.
    pub(crate) fn source_preserving(writer: Writer<W>) -> Self {
        Self {
            writer,
            interfaces: InterfaceLifecycle::SourceInterfaces(Vec::new()),
        }
    }

    pub(crate) fn format(&self) -> Format {
        self.writer.format()
    }

    pub(crate) fn set_stream_limits(&mut self, limits: Limits) -> Result<(), Error> {
        self.writer.set_stream_limits(limits)
    }

    /// Declares a link type before the first frame when callers need eager
    /// validation, and returns its PCAPNG interface ID.
    pub(crate) fn add_link_type(&mut self, link_type: LinkType) -> Result<Option<u32>, Error> {
        if self.format() == Format::Pcap {
            return Ok(None);
        }
        let mappings = match &mut self.interfaces {
            InterfaceLifecycle::LinkTypes(mappings) => mappings,
            InterfaceLifecycle::SourceInterfaces(_) => {
                unreachable!("link types are registered only on link-mapped output")
            }
        };
        if let Some(mapping) = mappings
            .iter()
            .find(|mapping| mapping.link_type == link_type)
        {
            return Ok(Some(mapping.output_id));
        }
        let output_id = self.writer.add_interface(link_type)?;
        mappings.push(LinkTypeMapping {
            link_type,
            output_id,
        });
        Ok(Some(output_id))
    }

    /// Writes a generated frame, mapping each PCAPNG link type once.
    pub(crate) fn write_link_mapped(&mut self, mut frame: Frame) -> Result<(), Error> {
        frame.interface = self.add_link_type(frame.link_type)?;
        self.writer.write_frame(&frame)
    }

    /// Writes a frame on an eagerly chosen link-type interface.
    pub(crate) fn write_on_link_type(
        &mut self,
        link_type: LinkType,
        mut frame: Frame,
    ) -> Result<(), Error> {
        frame.interface = self.add_link_type(link_type)?;
        self.writer.write_frame(&frame)
    }

    /// Registers one exact source interface and returns its output ID.
    fn add_source_interface(
        &mut self,
        source_id: Option<u32>,
        description: Interface,
    ) -> Result<Option<u32>, Error> {
        if self.format() == Format::Pcap {
            return Ok(None);
        }
        let mappings = match &mut self.interfaces {
            InterfaceLifecycle::SourceInterfaces(mappings) => mappings,
            InterfaceLifecycle::LinkTypes(_) => {
                unreachable!("source interfaces are registered only on preserving output")
            }
        };
        if let Some(mapping) = mappings
            .iter()
            .find(|mapping| mapping.source_id == source_id)
        {
            return Ok(Some(mapping.output_id));
        }
        let output_id = self.writer.add_interface_description(description)?;
        mappings.push(SourceInterfaceMapping {
            source_id,
            output_id,
        });
        Ok(Some(output_id))
    }

    /// Copies every source interface discovered so far, exactly once.
    pub(crate) fn synchronize_source_interfaces(
        &mut self,
        interfaces: &[Interface],
    ) -> Result<(), Error> {
        if self.format() == Format::Pcap {
            return Ok(());
        }
        for (source_id, description) in (0_u32..).zip(interfaces.iter().copied()) {
            self.add_source_interface(Some(source_id), description)?;
        }
        Ok(())
    }

    /// Writes evidence carrying its exact source interface description.
    pub(crate) fn write_source_frame(
        &mut self,
        source_id: Option<u32>,
        description: Interface,
        mut frame: Frame,
    ) -> Result<(), Error> {
        frame.interface = self.add_source_interface(source_id, description)?;
        self.writer.write_frame(&frame)
    }

    /// Writes a frame after its reader's known interfaces were synchronized.
    pub(crate) fn write_synchronized_frame(&mut self, mut frame: Frame) -> Result<(), Error> {
        frame.interface = match (self.format(), frame.interface) {
            (Format::Pcap, _) | (Format::PcapNg, None) => None,
            (Format::PcapNg, Some(source_id)) => {
                let InterfaceLifecycle::SourceInterfaces(mappings) = &self.interfaces else {
                    unreachable!("synchronized frames require source-preserving output");
                };
                Some(
                    mappings
                        .iter()
                        .find(|mapping| mapping.source_id == Some(source_id))
                        .expect("source interfaces are synchronized before their frames")
                        .output_id,
                )
            }
        };
        self.writer.write_frame(&frame)
    }

    pub(crate) fn flush(&mut self) -> Result<(), Error> {
        self.writer.flush()
    }

    pub(crate) fn into_inner(self) -> W {
        self.writer.into_inner()
    }
}
