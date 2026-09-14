// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

use clap::{CommandFactory, ValueEnum};
use clap_complete::Shell;
use packetcraftr_core::error::{Classification, Kind};

use crate::cli::Cli;
use crate::errors::CliError;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Write `completions/` and `man/` trees under this directory.
    #[arg(long, value_name = "DIR")]
    pub(crate) directory: PathBuf,
}

/// Generates shell completions and man pages from the finalized command tree,
/// so the shipped documentation always describes the binary that produced it.
/// One file lands per supported shell and per command under the directory.
pub(crate) fn run(arguments: &Args) -> Result<(), CliError> {
    let completions = arguments.directory.join("completions");
    let man = arguments.directory.join("man");
    for directory in [&completions, &man] {
        std::fs::create_dir_all(directory).map_err(|error| io_error(directory, error))?;
    }
    for shell in Shell::value_variants() {
        clap_complete::generate_to(*shell, &mut Cli::command(), "packetcraftr", &completions)
            .map_err(|error| io_error(&completions, error))?;
    }
    clap_mangen::generate_to(Cli::command(), &man).map_err(|error| io_error(&man, error))?;
    Ok(())
}

fn io_error(directory: &Path, error: std::io::Error) -> CliError {
    CliError::from_classification(
        Classification::new(
            "io.documentation",
            Kind::Io,
            Some("choose a writable documentation directory"),
        ),
        format!(
            "cannot write generated documentation under {}: {error}",
            directory.display()
        ),
        Vec::new(),
    )
}
