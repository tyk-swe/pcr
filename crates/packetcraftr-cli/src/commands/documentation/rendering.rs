// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::path::Path;

use clap::{CommandFactory, ValueEnum};
use clap_complete::{Generator, Shell};

use crate::cli::Cli;

pub(super) fn write_completions(directory: &Path) -> io::Result<()> {
    for shell in Shell::value_variants() {
        let mut command = Cli::command();
        command.set_bin_name("packetcraftr");
        command.build();
        // Some shell generators panic on write errors even through try_generate.
        // Render the fixed command tree in memory, then propagate filesystem errors.
        let mut completion = Vec::new();
        shell.try_generate(&command, &mut completion)?;
        std::fs::write(directory.join(shell.file_name("packetcraftr")), completion)?;
    }
    Ok(())
}

pub(super) fn write_man_pages(directory: &Path) -> io::Result<()> {
    clap_mangen::generate_to(Cli::command(), directory)
}
