// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::{Args as ClapArgs, Subcommand};

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr schema emit --contract packet/v2
  packetcraftr schema emit --contract packet/v1"#;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) command: SchemaCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SchemaCommand {
    /// Emit a JSON schema for packet contracts.
    Emit(EmitArgs),
}

#[derive(Debug, ClapArgs)]
pub(crate) struct EmitArgs {
    /// Contract identifier to emit (e.g. packet/v1, packet/v2).
    #[arg(long = "contract", value_name = "CONTRACT")]
    pub(crate) contract: String,
}
