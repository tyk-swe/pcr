// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod rendering;

use std::path::{Path, PathBuf};

use packetcraftr_core::error::{Classification, Kind};

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
    rendering::write_completions(&completions).map_err(|error| io_error(&completions, error))?;
    rendering::write_man_pages(&man).map_err(|error| io_error(&man, error))?;
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
