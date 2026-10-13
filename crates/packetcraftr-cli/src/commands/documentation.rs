// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::path::{Path, PathBuf};

use clap::{CommandFactory, ValueEnum};
use clap_complete::{Generator, Shell};
use packetcraftr_core::error::{Classification, Kind};

use crate::cli::Cli;
use crate::errors::{CliError, source_causes};
use crate::output::contract::Format;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Write `completions/` and `man/` trees under this directory.
    #[arg(long, value_name = "DIR")]
    pub(crate) directory: PathBuf,
}

impl super::Generate for Args {
    fn generate(self, _format: Format) -> Result<(), CliError> {
        run(&self)
    }
}

fn run(arguments: &Args) -> Result<(), CliError> {
    let completions = arguments.directory.join("completions");
    let man = arguments.directory.join("man");
    for directory in [&completions, &man] {
        std::fs::create_dir_all(directory).map_err(|error| io_error(directory, error))?;
    }
    write_completions(&completions).map_err(|error| io_error(&completions, error))?;
    clap_mangen::generate_to(Cli::command(), &man).map_err(|error| io_error(&man, error))?;
    Ok(())
}

fn write_completions(directory: &Path) -> io::Result<()> {
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

fn io_error(directory: &Path, error: std::io::Error) -> CliError {
    CliError::from_classification(
        Classification::new(
            "io.documentation",
            Kind::Io,
            Some("choose a writable documentation directory"),
        ),
        format!(
            "cannot write generated documentation under {}",
            directory.display()
        ),
        source_causes(&error),
    )
}
