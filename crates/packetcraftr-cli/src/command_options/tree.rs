// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Display;

use clap::Args;
use packetcraftr_core::error::{Classification, Kind};

use crate::errors::CliError;

/// Text field-tree view of dissected layers.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct TreeArgs {
    /// Print every layer's fields as an indented tree (text output only).
    #[arg(long)]
    pub(crate) tree: bool,
    /// Maximum text bytes across all --tree layer and field lines.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub(crate) max_tree_bytes: usize,
}

impl TreeArgs {
    pub(crate) fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [max_tree_bytes: Bytes @ Output]);
    }

    /// The tree is human text, so machine and byte formats refuse it.
    pub(crate) fn validate_format(&self, text: bool, format: impl Display) -> Result<(), CliError> {
        if self.tree && !text {
            return Err(CliError::from_classification(
                Classification::new(
                    "cli.tree_unsupported_format",
                    Kind::Usage,
                    Some("use --output text to show the field tree"),
                ),
                format!("--tree has no effect on {format} output"),
                Vec::new(),
            ));
        }
        Ok(())
    }
}
