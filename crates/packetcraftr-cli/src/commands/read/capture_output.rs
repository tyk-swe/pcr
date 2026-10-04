// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};

use packetcraftr_core::capture_file as capture;
use packetcraftr_core::capture_file::Reader;
use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Kind;

use super::selection::Selection;
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::output::contract::Format;

#[derive(Clone, Copy)]
pub(super) enum CaptureOutput {
    Verbatim(capture::Format),
    Normalized(capture::Format),
}

impl CaptureOutput {
    pub(super) fn resolve(normalize: bool, format: Format) -> Result<Option<Self>, CliError> {
        let format = match format {
            Format::Pcap => capture::Format::Pcap,
            Format::PcapNg => capture::Format::PcapNg,
            _ if normalize => {
                return Err(CliError::from_classification(
                    Classification::new(
                        "cli.capture_normalize_format",
                        Kind::Usage,
                        Some("use --normalize with --output pcapng or --output pcap"),
                    ),
                    "--normalize requires PCAP or PCAPNG output",
                    Vec::new(),
                ));
            }
            _ => return Ok(None),
        };
        Ok(Some(if normalize {
            Self::Normalized(format)
        } else {
            Self::Verbatim(format)
        }))
    }

    pub(super) fn validate_input(self, input: capture::Format) -> Result<(), CliError> {
        match self {
            Self::Verbatim(output) => validate_rewrite_format(input, output),
            Self::Normalized(_) => Ok(()),
        }
    }

    pub(super) fn write(
        self,
        reader: &mut Reader<impl Read>,
        limits: OfflineCaptureLimitsArgs,
        selection: Selection<'_>,
        destination: &mut impl Write,
    ) -> Result<(), CliError> {
        match self {
            Self::Verbatim(_) => {
                rewrite_capture(reader, limits.stream_limits(), selection, destination)
            }
            Self::Normalized(format) => {
                super::normalize::run(reader, limits, selection, format, destination)
            }
        }
    }
}

/// Checked before stdout is wrapped, so a rejected conversion writes no compressed container.
fn validate_rewrite_format(
    input: capture::Format,
    output: capture::Format,
) -> Result<(), CliError> {
    if output != input {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_rewrite_format",
                Kind::Usage,
                Some("select the capture output format matching the input capture"),
            ),
            format!(
                "capture rewriting cannot convert {input} input to {output} without normalization"
            ),
            Vec::new(),
        ));
    }
    Ok(())
}

fn rewrite_capture(
    reader: &mut Reader<impl Read>,
    limits: capture::Limits,
    selection: Selection<'_>,
    destination: &mut impl Write,
) -> Result<(), CliError> {
    if selection.is_unrestricted() {
        return capture::rewrite(reader, destination, limits)
            .map(|_| ())
            .map_err(CliError::classified);
    }
    capture::select(reader, destination, limits, |number, frame| {
        selection
            .matches(number, frame)
            .map_err(CliError::into_boundary_error)
    })
    .map(|_| ())
    .map_err(CliError::classified)
}
