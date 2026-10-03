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
        let mut file = std::fs::File::create(directory.join(shell.file_name("packetcraftr")))?;
        // generate_to propagates open errors but panics on completion write errors.
        shell.try_generate(&command, &mut file)?;
    }
    Ok(())
}

pub(super) fn write_man_pages(directory: &Path) -> io::Result<()> {
    clap_mangen::generate_to(Cli::command(), directory)
}
