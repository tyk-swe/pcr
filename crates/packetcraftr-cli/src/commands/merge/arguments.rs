// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{CompressionArgs, OfflineCaptureLimitsArgs, SavedPcapNg};

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Captures in stable tie-breaking order; at most one may read stdin with -.
    #[arg(required = true, num_args = 2..)]
    pub(crate) paths: Vec<PathBuf>,
    /// New PCAPNG destination. Existing files are never overwritten.
    #[arg(long)]
    pub(crate) write: PathBuf,
    #[command(flatten)]
    pub(crate) compression: CompressionArgs<SavedPcapNg>,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
}
