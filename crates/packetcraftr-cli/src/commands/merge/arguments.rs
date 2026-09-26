// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{Compression, OfflineCaptureLimitsArgs};

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Captures in stable tie-breaking order; at most one may read stdin with -.
    #[arg(required = true, num_args = 2..)]
    pub(crate) paths: Vec<PathBuf>,
    /// New PCAPNG destination. Existing files are never overwritten.
    #[arg(long)]
    pub(crate) write: PathBuf,
    /// Compression of the saved PCAPNG file.
    #[arg(long, value_enum, default_value_t = Compression::None)]
    pub(crate) compression: Compression,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
}
