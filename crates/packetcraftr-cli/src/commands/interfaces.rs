// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use self::arguments::Args;
use crate::output::contract::AggregateFormat;

use crate::output;

use crate::errors::CliError;

impl super::Spec for Args {
    type Format = crate::output::contract::AggregateFormat;
    const CANCELLATION: bool = false;

    fn run(
        self,
        format: Self::Format,
        _stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: AggregateFormat) -> Result<(), CliError> {
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
    super::render_aggregate_rows(
        output::contract::Command::Interfaces,
        format,
        &result,
        &result.interfaces,
        rendering::interface_line,
    )
}
