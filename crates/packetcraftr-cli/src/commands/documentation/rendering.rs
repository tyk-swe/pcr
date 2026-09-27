// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Renders the command tree as shell completions and man pages.

use std::io;
use std::path::Path;

use clap::{CommandFactory, ValueEnum};
use clap_complete::Shell;

use crate::cli::Cli;

/// One completion script per supported shell.
pub(super) fn write_completions(directory: &Path) -> io::Result<()> {
    for shell in Shell::value_variants() {
        clap_complete::generate_to(*shell, &mut Cli::command(), "packetcraftr", directory)?;
    }
    Ok(())
}

/// One man page per command.
pub(super) fn write_man_pages(directory: &Path) -> io::Result<()> {
    clap_mangen::generate_to(Cli::command(), directory)
}
