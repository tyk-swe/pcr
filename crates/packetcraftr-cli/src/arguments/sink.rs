// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Shared exact-byte output destination.

use std::path::PathBuf;

use clap::Args;

#[derive(Clone, Debug, Args)]
pub(crate) struct CaptureSinkArgs {
    /// Write exact pcap, pcapng, or raw bytes to PATH instead of stdout.
    #[arg(long, value_name = "PATH")]
    pub(crate) write: Option<PathBuf>,
}
