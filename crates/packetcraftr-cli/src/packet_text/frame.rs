// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use packetcraftr_core::document;

use super::dns::render_dns_records;
use super::field_tree::FieldTree;
use crate::errors::CliError;
use crate::invocation::{Invocation, Presentation};
use crate::output::frame::{Captured, SourceFrame, Stack};
use crate::output::hex::SpacedHex;
use crate::terminal::{render_diagnostics_text, write_details, write_stdout_line};

pub(crate) enum Layers<'a> {
    /// Every field as a tree, with the frame bytes on the summary line.
    Tree(&'a mut FieldTree),
    /// DNS records, and with verbose presentation the frame bytes and decoded fields.
    Fields(Presentation),
}

impl<'a> Layers<'a> {
    pub(crate) fn new(tree: Option<&'a mut FieldTree>, presentation: Presentation) -> Self {
        tree.map_or(Self::Fields(presentation), Self::Tree)
    }

    const fn shows_bytes(&self) -> bool {
        match self {
            Self::Tree(_) => true,
            Self::Fields(presentation) => presentation.verbose,
        }
    }
}

pub(crate) fn render_frame(
    invocation: &Invocation,
    source_frame: SourceFrame,
    frame: &Captured,
    decoded: Option<&Stack>,
    layers: Layers<'_>,
) -> Result<(), CliError> {
    let Some(decoded) = decoded else {
        return if layers.shows_bytes() {
            write_stdout_line(
                invocation,
                format_args!("{source_frame}: {}", CapturedFrameText(frame)),
            )
        } else {
            write_stdout_line(
                invocation,
                format_args!("{source_frame}: {}", FrameHeader(frame)),
            )
        };
    };
    let protocols = decoded
        .packet
        .layers
        .iter()
        .map(|layer| layer.protocol.as_str())
        .collect::<Vec<_>>()
        .join("/");
    let bytes = if layers.shows_bytes() {
        SpacedHex(frame.bytes()).to_string()
    } else {
        String::new()
    };
    write_stdout_line(
        invocation,
        format_args!(
            "{source_frame}: {} layers={protocols} {bytes}",
            FrameHeader(frame)
        ),
    )?;
    match layers {
        Layers::Tree(tree) => {
            tree.render_layers(invocation, &decoded.packet, |index, protocol| {
                format!("{source_frame}: {index}: {protocol}")
            })?;
        }
        Layers::Fields(presentation) => render_fields(invocation, &decoded.packet, presentation)?,
    }
    if decoded.diagnostics.is_empty() {
        return Ok(());
    }
    write_stdout_line(invocation, format_args!("{source_frame}: diagnostics:"))?;
    render_diagnostics_text(invocation, &decoded.diagnostics)
}

pub(crate) fn render_fields(
    invocation: &Invocation,
    packet: &document::Packet,
    presentation: Presentation,
) -> Result<(), CliError> {
    render_dns_records(invocation, packet)?;
    write_details(invocation, presentation, "Decoded fields", packet)
}

pub(crate) fn render_undecoded<'a>(
    invocation: &Invocation,
    rows: impl IntoIterator<Item = (Option<String>, &'a Captured)>,
) -> Result<(), CliError> {
    for (label, frame) in rows {
        match label {
            Some(label) => write_stdout_line(
                invocation,
                format_args!("undecoded {label} {}", CapturedFrameText(frame)),
            )?,
            None => write_stdout_line(
                invocation,
                format_args!("undecoded {}", CapturedFrameText(frame)),
            )?,
        }
    }
    Ok(())
}

pub(crate) struct CapturedFrameText<'a>(pub(crate) &'a Captured);

impl fmt::Display for CapturedFrameText<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {}",
            FrameHeader(self.0),
            SpacedHex(self.0.bytes())
        )
    }
}

struct FrameHeader<'a>(&'a Captured);

impl fmt::Display for FrameHeader<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let frame = self.0;
        write!(
            formatter,
            "dlt={} caplen={} wirelen={}",
            frame.link_type, frame.captured_length, frame.original_length
        )
    }
}
