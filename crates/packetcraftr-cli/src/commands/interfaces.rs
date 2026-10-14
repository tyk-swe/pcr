// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod rendering;

use crate::command_options::InterfaceSelector;
use crate::errors::CliError;
use crate::output::{self, contract::Format};

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr network interfaces
  packetcraftr network interfaces --interface lo
  packetcraftr --output json network interfaces";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Only list the interface with this name or numeric index.
    #[arg(long, value_name = "NAME_OR_INDEX", value_parser = crate::command_options::interface_selector)]
    pub(crate) interface: Option<crate::command_options::Selector<InterfaceSelector>>,
    /// List the packet timestamp types the capture backend advertises for each
    /// interface; types without a source are not selectable for capture.
    #[arg(long)]
    pub(crate) timestamp_types: bool,
}

impl super::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
    ];
    const CANCELLATION: bool = false;

    fn run(
        self,
        format: Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream.presentation()).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    arguments: Args,
    format: Format,
    presentation: crate::rendering::Presentation,
) -> Result<(), CliError> {
    let selector = arguments
        .interface
        .as_ref()
        .map(crate::command_options::Selector::get)
        .transpose()?;
    let mut interfaces = crate::system::interfaces(selector.as_ref())?;
    // Enumerate timestamp types in published order, so the first failure is
    // the one for the first interface a reader would see.
    interfaces.sort_by(|left, right| {
        (left.id.index, left.id.name.as_str()).cmp(&(right.id.index, right.id.name.as_str()))
    });
    let interfaces = interfaces
        .into_iter()
        .map(|info| {
            let timestamp_types = arguments
                .timestamp_types
                .then(|| crate::system::timestamp_types(&info.id))
                .transpose()?;
            Ok((info, timestamp_types))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let result = output::interfaces::Report::from(interfaces);
    if format == Format::Text && !presentation.verbose && !arguments.timestamp_types {
        crate::rendering::table_row(&[
            ("INTERFACE", 16),
            ("INDEX", 5),
            ("CAPABILITY", 12),
            ("ADDRESSES", 0),
        ])?;
    }
    crate::rendering::render_aggregate_rows(
        output::contract::Command::Interfaces,
        format,
        &result,
        &result.interfaces,
        |interface| {
            if presentation.verbose || arguments.timestamp_types {
                rendering::interface_line(interface)
            } else {
                format!(
                    "{:<16}  {:<5}  {:<12}  {}",
                    interface.name,
                    interface.index,
                    interface.capability,
                    interface.addresses.join(", ")
                )
            }
        },
    )
}
