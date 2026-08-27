// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod arguments;

use packetcraftr::core;
use packetcraftr::core::error::{Classification, Kind};
use packetcraftr::output;

use self::arguments::{Args, SchemaCommand};
use super::super::errors::CliError;
use super::super::rendering::write_raw;
use super::registry;

pub(crate) fn run(arguments: Args, _format: output::contract::Format) -> Result<(), CliError> {
    match arguments.command {
        SchemaCommand::Emit(emit_args) => match emit_args.contract.as_str() {
            "packet/v2" => {
                let registry = registry()?;
                let schema_json = core::document::v2_schema::emit_pretty(&registry);
                write_raw(schema_json.as_bytes())
            }
            "packet/v1" => {
                const V1_SCHEMA: &str =
                    include_str!("../../../../../schemas/packetcraftr.packet.v1.schema.json");
                write_raw(V1_SCHEMA.as_bytes())
            }
            other => Err(CliError::from_classification(
                Classification::new(
                    "request.unknown_contract",
                    Kind::Request,
                    Some("supported contracts are packet/v1 and packet/v2"),
                ),
                format!(
                    "unknown schema contract `{other}`; supported contracts are packet/v1 and packet/v2"
                ),
                Vec::new(),
            )),
        },
    }
}
